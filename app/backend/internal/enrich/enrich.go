// Package enrich fills the "enriched" fields of flows (exporter, interfaces,
// networks, hosts, GeoIP, AS, application) from the Inventory DB snapshot,
// interface names learned by the collector, CEL classifiers, GeoIP and the
// application table, then passes the batch to the next sink.
package enrich

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/apps"
	"github.com/sbrw-evc/network/app/backend/internal/classifier"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/geoip"
	"github.com/sbrw-evc/network/app/backend/internal/inventory"
)

// IfNameSource gives interface attributes learned by the collector (option
// templates, sFlow counters, SNMP). The collector implements it.
type IfNameSource interface {
	Lookup(exporter netip.Addr, ifIndex uint32) (name, descr string, speed uint64, ok bool)
}

// InventorySource returns the current Inventory DB snapshot (never nil);
// *inventory.Syncer implements it.
type InventorySource interface {
	Current() *inventory.Snapshot
}

// GeoSource looks up addresses; *geoip.DB implements it.
type GeoSource interface {
	Lookup(addr netip.Addr) geoip.Info
}

// AppSource names applications; *apps.Table implements it.
type AppSource interface {
	Lookup(proto uint8, srcPort, dstPort uint16) string
}

// AS providers, tried in order until one gives a non-zero AS.
const (
	// ASFlow is the AS reported by the exporter.
	ASFlow = "flow"
	// ASFlowExceptPrivate is the reported AS unless it is private (RFC 6996).
	ASFlowExceptPrivate = "flow-except-private"
	// ASGeoIP is the AS from the GeoIP (ASN / IPinfo) database.
	ASGeoIP = "geoip"
)

// Config of the enricher. Every source is optional.
type Config struct {
	Inventory   InventorySource
	IfNames     IfNameSource
	Classifiers *classifier.Set
	GeoIP       GeoSource
	Apps        AppSource // default apps.Default()
	// ASProviders in order (default flow, geoip).
	ASProviders []string
	// CacheTTL of per-exporter / per-interface results (default 1 min).
	// Entries are also dropped when the inventory snapshot changes.
	CacheTTL time.Duration
	// MaxExporters bounds the exporter cache and the unknown-exporter list
	// (default 10000).
	MaxExporters int
	// UnknownAddresses is the size of the top unknown addresses table
	// (default 1000; negative disables).
	UnknownAddresses int
	// TrackUnknown decides which addresses without an IPAM prefix are
	// counted as unknown (default: private, CGNAT and ULA addresses —
	// public Internet addresses are expected to be outside IPAM).
	TrackUnknown func(netip.Addr) bool
	// Metrics registers Prometheus metrics when set.
	Metrics Registerer
	// PTR resolves reverse DNS names of addresses without an Inventory DB
	// host name (rdns.go); nil disables.
	PTR PTRSource
	// Threats names the threat list of an address (threat.go); nil disables.
	Threats ThreatSource
	// ExporterNames names exporters that are not Inventory DB devices but
	// synthetic addresses of cloud flow logs (internal/flowlogs); such
	// exporters are not reported as unknown.
	ExporterNames func(netip.Addr) (string, bool)
	// Routing gives the BGP route of an address (BMP, routing.go): the
	// "routing" AS provider and DstASPath / DstCommunities /
	// DstLargeCommunities; nil disables.
	Routing RoutingSource
}

// Enricher implements flow.Sink.
type Enricher struct {
	next    flow.Sink
	cfg     Config
	inv     InventorySource
	ifn     IfNameSource
	geo     GeoSource
	apps    AppSource
	asOrder []string
	asDyn   atomic.Pointer[[]string] // SetASProviders (routing.go)
	cls     atomic.Pointer[classifier.Set]
	empty   *inventory.Snapshot
	mu      sync.RWMutex
	cache   map[netip.Addr]*expEntry
	unknown *unknownTracker
	m       *metrics
	now     func() time.Time
}

// New returns an enricher passing enriched batches to next.
func New(next flow.Sink, cfg Config) (*Enricher, error) {
	if next == nil {
		return nil, errors.New("enrich: next sink is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Minute
	}
	if cfg.MaxExporters <= 0 {
		cfg.MaxExporters = 10_000
	}
	if cfg.UnknownAddresses == 0 {
		cfg.UnknownAddresses = 1000
	}
	if cfg.TrackUnknown == nil {
		cfg.TrackUnknown = isInternalAddr
	}
	if len(cfg.ASProviders) == 0 {
		cfg.ASProviders = []string{ASFlow, ASGeoIP}
	}
	for _, p := range cfg.ASProviders {
		switch p {
		case ASFlow, ASFlowExceptPrivate, ASGeoIP, ASRouting:
		default:
			return nil, errors.New("enrich: unknown AS provider " + strconv.Quote(p))
		}
	}
	e := &Enricher{
		next: next, cfg: cfg, inv: cfg.Inventory, ifn: cfg.IfNames, geo: cfg.GeoIP, apps: cfg.Apps,
		asOrder: cfg.ASProviders, empty: inventory.Empty(), cache: map[netip.Addr]*expEntry{},
		unknown: newUnknownTracker(cfg.MaxExporters, cfg.UnknownAddresses), now: time.Now,
	}
	if e.apps == nil {
		e.apps = apps.Default()
	}
	if cfg.Classifiers != nil {
		e.cls.Store(cfg.Classifiers)
	}
	m, err := newMetrics(cfg.Metrics, e)
	if err != nil {
		return nil, err
	}
	e.m = m
	return e, nil
}

// SetClassifiers replaces the classifier set (nil removes it) and clears the
// caches.
func (e *Enricher) SetClassifiers(s *classifier.Set) {
	e.cls.Store(s)
	e.Reset()
}

// Reset clears the per-exporter caches.
func (e *Enricher) Reset() {
	e.mu.Lock()
	e.cache = map[netip.Addr]*expEntry{}
	e.mu.Unlock()
}

func (e *Enricher) snapshot() *inventory.Snapshot {
	if e.inv == nil {
		return e.empty
	}
	if s := e.inv.Current(); s != nil {
		return s
	}
	return e.empty
}

// expEntry is the cached enrichment of one exporter and its interfaces.
type expEntry struct {
	snap    *inventory.Snapshot
	cls     *classifier.Set
	expires time.Time
	known   bool
	dev     *inventory.Device
	cexp    classifier.Exporter

	name, ref, site, region, role, group, tenant string

	mu     sync.RWMutex
	ifaces map[uint32]*ifEntry
}

type ifEntry struct {
	expires                                   time.Time
	source                                    int // ifSource*
	name, descr                               string
	speed                                     uint64
	boundary, connectivity, provider, circuit string
	rd                                        string // route distinguisher of the interface VRF
}

const (
	ifSourceNone = iota
	ifSourceInventory
	ifSourceCollector
)

func (e *Enricher) exporter(addr netip.Addr, snap *inventory.Snapshot, cls *classifier.Set, now time.Time, st *batchStats) *expEntry {
	e.mu.RLock()
	x := e.cache[addr]
	e.mu.RUnlock()
	if x != nil && x.snap == snap && x.cls == cls && now.Before(x.expires) {
		st.cacheHits++
		return x
	}
	st.cacheMisses++
	x = &expEntry{snap: snap, cls: cls, expires: now.Add(e.cfg.CacheTTL), ifaces: map[uint32]*ifEntry{}}
	in := classifier.Exporter{Address: addr.String()}
	if d, ok := snap.Exporter(addr); ok {
		x.known, x.dev = true, d
		x.ref = d.Ref
		in.Name, in.Site, in.Region, in.Role, in.Tenant, in.Tags = d.Name, d.Site, d.Region, d.Role, d.Tenant, d.Tags
	} else {
		in.Name = addr.String()
		if e.cfg.ExporterNames != nil {
			if n, ok := e.cfg.ExporterNames(addr); ok {
				in.Name, x.known = n, true
			}
		}
	}
	out := in
	if cls.HasExporterRules() {
		out = cls.Exporter(addr, in)
	}
	x.cexp = out
	x.name, x.site, x.region, x.role, x.group, x.tenant = out.Name, out.Site, out.Region, out.Role, out.Group, out.Tenant
	e.mu.Lock()
	if len(e.cache) >= e.cfg.MaxExporters {
		clear(e.cache)
	}
	e.cache[addr] = x
	e.mu.Unlock()
	return x
}

func (e *Enricher) iface(x *expEntry, addr netip.Addr, idx uint32, cls *classifier.Set, now time.Time, st *batchStats) *ifEntry {
	x.mu.RLock()
	i := x.ifaces[idx]
	x.mu.RUnlock()
	if i != nil && now.Before(i.expires) {
		return i
	}
	i = &ifEntry{expires: now.Add(e.cfg.CacheTTL)}
	var cname, cdescr string
	var cspeed uint64
	var cok bool
	if e.ifn != nil {
		cname, cdescr, cspeed, cok = e.ifn.Lookup(addr, idx)
	}
	var it *inventory.Interface
	if x.dev != nil && x.dev.Kind == inventory.KindDevice {
		if v, ok := x.snap.Interface(x.dev.ID, idx); ok {
			it = v
		} else if cok && cname != "" {
			it, _ = x.snap.InterfaceByName(x.dev.ID, cname)
		}
	}
	switch {
	case it != nil:
		i.source = ifSourceInventory
		i.name, i.descr, i.speed = it.Name, it.Description, it.Speed
		i.boundary, i.connectivity, i.provider, i.circuit = it.Boundary, it.Connectivity, it.Provider, it.Circuit
		i.rd = it.RD
		if i.descr == "" {
			i.descr = cdescr
		}
		if i.speed == 0 {
			i.speed = cspeed
		}
	case cok:
		i.source = ifSourceCollector
		i.name, i.descr, i.speed = cname, cdescr, cspeed
	}
	if cls.HasInterfaceRules() {
		in := classifier.Interface{Index: idx, Name: i.name, Description: i.descr, Speed: i.speed, Boundary: i.boundary,
			Connectivity: i.connectivity, Provider: i.provider, Circuit: i.circuit}
		if it != nil {
			in.VLAN = uint32(it.VLAN)
		}
		out := cls.Interface(addr, x.cexp, in)
		i.name, i.descr, i.speed = out.Name, out.Description, out.Speed
		i.boundary, i.connectivity, i.provider = out.Boundary, out.Connectivity, out.Provider
	}
	x.mu.Lock()
	if len(x.ifaces) >= 65536 {
		clear(x.ifaces)
	}
	x.ifaces[idx] = i
	x.mu.Unlock()
	return i
}

// batchStats are counted locally and published once per batch.
type batchStats struct {
	flows, unknownExporter           int
	ifInventory, ifCollector, ifNone int
	netPrefix, netMask, netNone      int
	cacheHits, cacheMisses           int
}

// Put enriches flows in place and hands them to the next sink.
func (e *Enricher) Put(ctx context.Context, flows []*flow.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	snap := e.snapshot()
	cls := e.cls.Load()
	now := e.now()
	var st batchStats
	var lastAddr netip.Addr
	var x *expEntry
	unk := e.unknown.batch()
	for _, f := range flows {
		if f == nil {
			continue
		}
		st.flows++
		ea := f.ExporterAddress.Unmap()
		if x == nil || ea != lastAddr {
			x, lastAddr = e.exporter(ea, snap, cls, now, &st), ea
		}
		e.enrichOne(f, x, ea, snap, cls, now, &st, unk)
	}
	e.unknown.merge(unk, now)
	e.m.publish(&st)
	return e.next.Put(ctx, flows)
}

func (e *Enricher) enrichOne(f *flow.Flow, x *expEntry, ea netip.Addr, snap *inventory.Snapshot, cls *classifier.Set, now time.Time, st *batchStats, unk *unknownBatch) {
	f.ExporterName, f.ExporterRef, f.ExporterSite, f.ExporterRegion = x.name, x.ref, x.site, x.region
	f.ExporterRole, f.ExporterGroup, f.ExporterTenant = x.role, x.group, x.tenant
	if !x.known {
		st.unknownExporter++
		unk.exporter(ea)
	}
	// Routes are looked up in the VRF of the input interface (else the
	// output one), the table the router forwarded the flow with.
	rd, rdSet := "", false
	if f.InIf != 0 {
		i := e.iface(x, ea, f.InIf, cls, now, st)
		rd, rdSet = i.rd, true
		st.countIf(i)
		f.InIfName, f.InIfDescription, f.InIfSpeed = i.name, i.descr, i.speed
		f.InIfBoundary, f.InIfConnectivity, f.InIfProvider, f.InIfCircuit = i.boundary, i.connectivity, i.provider, i.circuit
	}
	if f.OutIf != 0 {
		i := e.iface(x, ea, f.OutIf, cls, now, st)
		if !rdSet {
			rd = i.rd
		}
		st.countIf(i)
		f.OutIfName, f.OutIfDescription, f.OutIfSpeed = i.name, i.descr, i.speed
		f.OutIfBoundary, f.OutIfConnectivity, f.OutIfProvider, f.OutIfCircuit = i.boundary, i.connectivity, i.provider, i.circuit
	}

	// Source network.
	src, dst := f.SrcAddr.Unmap(), f.DstAddr.Unmap()
	if src.IsValid() {
		var n netInfo
		e.network(src, f.SrcNetMask, snap, &n, st, unk, f.Bytes*max(f.SamplingRate, 1))
		f.SrcNetPrefix, f.SrcNetName, f.SrcNetRole, f.SrcNetSite, f.SrcNetTenant, f.SrcNetVRF = n.prefix, n.name, n.role, n.site, n.tenant, n.vrf
		f.SrcHost, f.SrcCI, f.SrcCountry, f.SrcCity = n.host, n.ci, n.geo.Country, n.geo.City
		e.route(rd, src, &n)
		f.SrcAS = e.as(f.SrcAS, &n)
	}
	if dst.IsValid() {
		var n netInfo
		e.network(dst, f.DstNetMask, snap, &n, st, unk, f.Bytes*max(f.SamplingRate, 1))
		f.DstNetPrefix, f.DstNetName, f.DstNetRole, f.DstNetSite, f.DstNetTenant, f.DstNetVRF = n.prefix, n.name, n.role, n.site, n.tenant, n.vrf
		f.DstHost, f.DstCI, f.DstCountry, f.DstCity = n.host, n.ci, n.geo.Country, n.geo.City
		e.route(rd, dst, &n)
		f.DstAS = e.as(f.DstAS, &n)
		e.applyDstRoute(f, &n)
	}
	e.enrichPTR(f, src, dst)
	e.enrichThreat(f, src, dst)
	if f.App == "" {
		f.App = e.apps.Lookup(f.Proto, f.SrcPort, f.DstPort)
	}
}

func (st *batchStats) countIf(i *ifEntry) {
	switch i.source {
	case ifSourceInventory:
		st.ifInventory++
	case ifSourceCollector:
		st.ifCollector++
	default:
		st.ifNone++
	}
}

type netInfo struct {
	prefix                                  netip.Prefix
	name, role, site, tenant, vrf, host, ci string
	geo                                     geoip.Info
	geoDone                                 bool
	rt                                      RouteInfo // routing.go
	rtOK                                    bool
}

func (e *Enricher) network(a netip.Addr, mask uint8, snap *inventory.Snapshot, n *netInfo, st *batchStats, unk *unknownBatch, bytes uint64) {
	if p, ok := snap.Prefix(a); ok {
		st.netPrefix++
		n.prefix, n.name, n.role, n.site, n.tenant, n.vrf = p.Prefix, p.Name, p.Role, p.Site, p.Tenant, p.VRF
	} else {
		if mask > 0 && int(mask) <= a.BitLen() {
			st.netMask++
			n.prefix, _ = a.Prefix(int(mask))
		} else {
			st.netNone++
		}
		if e.unknown.addrsEnabled() && e.cfg.TrackUnknown(a) {
			unk.address(a, bytes)
		}
	}
	if ad, ok := snap.Address(a); ok {
		n.host, n.ci = ad.Host, ad.Ref
	}
	if e.geo != nil {
		n.geo, n.geoDone = e.geo.Lookup(a), true
	}
}

func (e *Enricher) as(reported uint32, n *netInfo) uint32 {
	order := e.asOrder
	if d := e.asDyn.Load(); d != nil {
		order = *d
	}
	for _, p := range order {
		switch p {
		case ASRouting:
			if n.rtOK && n.rt.OriginAS != 0 {
				return n.rt.OriginAS
			}
		case ASFlow:
			if reported != 0 {
				return reported
			}
		case ASFlowExceptPrivate:
			if reported != 0 && !isPrivateAS(reported) {
				return reported
			}
		case ASGeoIP:
			if n.geoDone && n.geo.ASN != 0 {
				return n.geo.ASN
			}
		}
	}
	return 0
}

// isPrivateAS reports RFC 6996 / RFC 7300 private and reserved ASNs.
func isPrivateAS(as uint32) bool {
	return (as >= 64512 && as <= 65535) || (as >= 4200000000) || as == 23456
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isInternalAddr: RFC 1918, ULA, CGNAT.
func isInternalAddr(a netip.Addr) bool { return a.IsPrivate() || cgnat.Contains(a) }

// Unknown is the answer of GET /api/inventory-db/unknown.
type Unknown struct {
	Exporters []UnknownExporter `json:"exporters"`
	Addresses []UnknownAddress  `json:"addresses"`
}

// UnknownExporter is an exporter without an Inventory DB device.
type UnknownExporter struct {
	Address  netip.Addr `json:"address"`
	LastSeen time.Time  `json:"last_seen"`
	Flows    uint64     `json:"flows"`
}

// UnknownAddress is an address outside every IPAM prefix.
type UnknownAddress struct {
	Address netip.Addr `json:"address"`
	Bytes   uint64     `json:"bytes"`
}

// Unknown returns unknown exporters (most recent first) and the top
// unknown addresses by bytes (sampling rate applied).
func (e *Enricher) Unknown() Unknown {
	s := e.snapshot()
	e.unknown.forget(
		func(a netip.Addr) bool { _, ok := s.Exporter(a); return ok },
		func(a netip.Addr) bool { _, ok := s.Prefix(a); return ok },
	)
	return e.unknown.snapshot()
}

// ResetUnknown clears the unknown lists (e.g. after objects were created
// in Inventory DB).
func (e *Enricher) ResetUnknown() { e.unknown.reset() }
