package collector

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
)

// IfNameSource resolves interface names learned from the exporters
// themselves (NetFlow v9 / IPFIX option data, sFlow counter samples).
type IfNameSource interface {
	Lookup(exporter netip.Addr, ifIndex uint32) (name, descr string, speed uint64, ok bool)
}

// ExporterInfo describes an exporter seen by the collector.
type ExporterInfo struct {
	Address        netip.Addr
	LastSeen       time.Time
	FlowTypes      []string // "netflow5", "netflow9", "ipfix", "sflow"
	Packets        uint64
	Flows          uint64
	DecodeErrors   uint64
	FlowsPerSecond float64  // as reported (not multiplied by sampling rate)
	SamplingRates  []uint64 // distinct effective rates seen, ascending
	Templates      int      // NetFlow v9 / IPFIX templates currently known
	Interfaces     []InterfaceInfo
}

// InterfaceInfo is what the exporter told us about one of its interfaces.
type InterfaceInfo struct {
	Index       uint32
	Name        string
	Description string
	Speed       uint64 // bits per second, 0 if unknown
}

// maxRatesSeen bounds the per-exporter set of distinct sampling rates.
const maxRatesSeen = 16

// samplerKey identifies a sampler within an exporter. id is anySampler for
// the rate that applies when a record does not name its sampler.
type samplerKey struct {
	version uint16
	domain  uint32
	id      uint64
}

const anySampler = ^uint64(0)

// exporter is the per-exporter state. Datagrams from one source address are
// decoded by a single worker, but the registry is also read by the API, so
// mutable fields are guarded by mu.
type exporter struct {
	addr     netip.Addr
	label    string
	override atomic.Uint64 // forced sampling rate, 0 if none (changed by SetSamplingOverrides)

	templates netflow.NetFlowTemplateSystem // per exporter; keyed inside by version + domain

	mu        sync.Mutex
	counters  map[string]*exporterCounters // by flow type
	samplers  map[samplerKey]uint64
	ratesSeen map[uint64]struct{}
	lastSeen  time.Time
	packets   uint64
	flows     uint64
	errors    uint64
	fps       float64
	rateFlows uint64
	rateAt    time.Time
}

type registry struct {
	mu        sync.RWMutex
	exporters map[netip.Addr]*exporter
	cfg       *Config
}

func newRegistry(cfg *Config) *registry {
	return &registry{exporters: make(map[netip.Addr]*exporter), cfg: cfg}
}

func (r *registry) get(addr netip.Addr) *exporter {
	r.mu.RLock()
	e := r.exporters[addr]
	r.mu.RUnlock()
	if e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.exporters[addr]; e == nil {
		e = &exporter{
			addr:      addr,
			label:     addr.String(),
			templates: netflow.CreateTemplateSystem(),
			counters:  make(map[string]*exporterCounters),
			samplers:  make(map[samplerKey]uint64),
			ratesSeen: make(map[uint64]struct{}),
		}
		e.override.Store(r.cfg.overrideFor(addr))
		r.exporters[addr] = e
	}
	return e
}

// setOverrides replaces the sampling overrides (sorted longest prefix first)
// and re-applies them to the known exporters.
func (r *registry) setOverrides(ov []SamplingOverride) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg.SamplingOverrides = ov
	for a, e := range r.exporters {
		e.override.Store(r.cfg.overrideFor(a))
	}
}

func (r *registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.exporters)
}

func (r *registry) all() []*exporter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*exporter, 0, len(r.exporters))
	for _, e := range r.exporters {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b *exporter) int { return a.addr.Compare(b.addr) })
	return out
}

// countersLocked returns the metric counters for a flow type. Caller holds e.mu.
func (e *exporter) countersLocked(m *metrics, typ string) *exporterCounters {
	c := e.counters[typ]
	if c == nil {
		c = m.forExporter(e.label, typ)
		e.counters[typ] = c
	}
	return c
}

// account records one decoded datagram.
func (e *exporter) account(m *metrics, typ string, now time.Time, flows int, failed bool) {
	e.mu.Lock()
	c := e.countersLocked(m, typ)
	e.lastSeen = now
	e.packets++
	e.flows += uint64(flows)
	if failed {
		e.errors++
	}
	e.mu.Unlock()
	c.packets.Inc()
	if flows > 0 {
		c.flows.Add(float64(flows))
	}
	if failed {
		c.errors.Inc()
	}
}

// effectiveRate applies override > reported > default, and remembers it.
func (e *exporter) effectiveRate(reported, def uint64) uint64 {
	rate := reported
	if o := e.override.Load(); o != 0 {
		rate = o
	}
	if rate == 0 {
		rate = def
	}
	return rate
}

func (e *exporter) noteRates(rates []uint64) {
	if len(rates) == 0 {
		return
	}
	e.mu.Lock()
	for _, r := range rates {
		if _, ok := e.ratesSeen[r]; !ok && len(e.ratesSeen) < maxRatesSeen {
			e.ratesSeen[r] = struct{}{}
		}
	}
	e.mu.Unlock()
}

func (e *exporter) setSampler(k samplerKey, rate uint64) {
	if rate == 0 {
		return
	}
	e.mu.Lock()
	e.samplers[k] = rate
	if k.id != anySampler {
		// also the fallback for records that do not name a sampler
		e.samplers[samplerKey{k.version, k.domain, anySampler}] = rate
	}
	e.mu.Unlock()
}

// sampler returns the rate learned from option data, 0 if unknown.
func (e *exporter) sampler(version uint16, domain uint32, id uint64) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id != anySampler {
		if r, ok := e.samplers[samplerKey{version, domain, id}]; ok {
			return r
		}
	}
	return e.samplers[samplerKey{version, domain, anySampler}]
}

// updateRate refreshes the flows/s estimate (exponentially smoothed).
func (e *exporter) updateRate(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.rateAt.IsZero() {
		dt := now.Sub(e.rateAt).Seconds()
		if dt <= 0 {
			return
		}
		inst := float64(e.flows-e.rateFlows) / dt
		if e.fps == 0 {
			e.fps = inst
		} else {
			e.fps = 0.5*e.fps + 0.5*inst
		}
	}
	e.rateFlows = e.flows
	e.rateAt = now
}

func (e *exporter) info(ifc *ifCache) ExporterInfo {
	e.mu.Lock()
	info := ExporterInfo{
		Address:        e.addr,
		LastSeen:       e.lastSeen,
		Packets:        e.packets,
		Flows:          e.flows,
		DecodeErrors:   e.errors,
		FlowsPerSecond: e.fps,
	}
	for t := range e.counters {
		info.FlowTypes = append(info.FlowTypes, t)
	}
	for r := range e.ratesSeen {
		info.SamplingRates = append(info.SamplingRates, r)
	}
	e.mu.Unlock()
	slices.Sort(info.FlowTypes)
	slices.Sort(info.SamplingRates)
	info.Templates = len(e.templates.GetTemplates())
	info.Interfaces = ifc.forExporter(e.addr)
	return info
}

// ifKey identifies an interface of an exporter.
type ifKey struct {
	exporter netip.Addr
	index    uint32
}

type ifEntry struct {
	name, descr string
	speed       uint64
	updated     time.Time
}

// ifCache holds interface names and speeds learned from the exporters.
type ifCache struct {
	mu sync.RWMutex
	m  map[ifKey]ifEntry
}

func newIfCache() *ifCache { return &ifCache{m: make(map[ifKey]ifEntry)} }

// Lookup implements IfNameSource.
func (c *ifCache) Lookup(exporter netip.Addr, ifIndex uint32) (name, descr string, speed uint64, ok bool) {
	c.mu.RLock()
	e, ok := c.m[ifKey{exporter.Unmap(), ifIndex}]
	c.mu.RUnlock()
	return e.name, e.descr, e.speed, ok
}

// setNames records name/description; empty values keep what is known.
func (c *ifCache) setNames(exporter netip.Addr, idx uint32, name, descr string, now time.Time) {
	c.mu.Lock()
	k := ifKey{exporter, idx}
	e := c.m[k]
	if name != "" {
		e.name = name
	}
	if descr != "" {
		e.descr = descr
	}
	e.updated = now
	c.m[k] = e
	c.mu.Unlock()
}

func (c *ifCache) setSpeed(exporter netip.Addr, idx uint32, speed uint64, now time.Time) {
	c.mu.Lock()
	k := ifKey{exporter, idx}
	e := c.m[k]
	e.speed = speed
	e.updated = now
	c.m[k] = e
	c.mu.Unlock()
}

func (c *ifCache) prune(before time.Time) {
	c.mu.Lock()
	for k, e := range c.m {
		if e.updated.Before(before) {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

func (c *ifCache) forExporter(a netip.Addr) []InterfaceInfo {
	c.mu.RLock()
	var out []InterfaceInfo
	for k, e := range c.m {
		if k.exporter == a {
			out = append(out, InterfaceInfo{Index: k.index, Name: e.name, Description: e.descr, Speed: e.speed})
		}
	}
	c.mu.RUnlock()
	slices.SortFunc(out, func(a, b InterfaceInfo) int { return cmp.Compare(a.Index, b.Index) })
	return out
}
