package snmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
)

// Interface MIB columns (IF-MIB).
const (
	oidIfDescr     = ".1.3.6.1.2.1.2.2.1.2"
	oidIfSpeed     = ".1.3.6.1.2.1.2.2.1.5"
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfHighSpeed = ".1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias     = ".1.3.6.1.2.1.31.1.1.1.18"
)

// Interface is what SNMP tells about one ifIndex.
type Interface struct {
	Name  string `json:"name"`  // ifName, or ifDescr when ifName is empty
	Descr string `json:"descr"` // ifAlias (the configured description)
	Speed uint64 `json:"speed"` // bits per second (ifHighSpeed, else ifSpeed)
}

// Resolver resolves openbao:// references (secrets.Value over the client).
type Resolver func(ref string) (string, error)

// Walker reads the interface table of one device; the default uses gosnmp.
type Walker func(ctx context.Context, target netip.Addr, p Profile, cred Credentials, s Settings) (map[uint32]Interface, error)

// Credentials are the resolved secrets of a profile.
type Credentials struct{ Community, Auth, Priv string }

type device struct {
	addr       netip.Addr
	ifaces     map[uint32]Interface
	polled     time.Time // last success
	attempt    time.Time
	next       time.Time
	err        string
	profile    string
	inflight   bool
	lastWant   time.Time // last Lookup (exporters discovered by the enricher)
	configured bool
}

// Poller polls devices and answers interface lookups. It implements the
// enricher's IfNameSource.
type Poller struct {
	log     *slog.Logger
	walk    Walker
	resolve atomic.Pointer[Resolver]
	set     atomic.Pointer[Settings]
	nets    atomic.Pointer[[][]netip.Prefix] // parsed prefixes per profile
	// Exporters lists the exporters seen by the collector (optional).
	Exporters func() []netip.Addr

	mu   sync.RWMutex
	devs map[netip.Addr]*device
	now  func() time.Time
	kick chan struct{}

	polls   *prometheus.CounterVec
	devices prometheus.GaugeFunc
}

// MaxDevices bounds the device table.
const MaxDevices = 20000

// New returns a disabled poller; Apply enables it. reg may be nil.
func New(reg prometheus.Registerer, log *slog.Logger) (*Poller, error) {
	if log == nil {
		log = slog.Default()
	}
	p := &Poller{log: log.With("component", "snmp"), walk: walkGoSNMP, devs: map[netip.Addr]*device{}, now: time.Now,
		kick: make(chan struct{}, 1)}
	p.set.Store(&Settings{})
	p.polls = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "snmp", Name: "polls_total",
		Help: "SNMP polls of devices by result."}, []string{"result"})
	p.devices = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "flow", Subsystem: "snmp", Name: "devices",
		Help: "Devices with SNMP interface data."}, func() float64 {
		p.mu.RLock()
		defer p.mu.RUnlock()
		n := 0
		for _, d := range p.devs {
			if d.ifaces != nil {
				n++
			}
		}
		return float64(n)
	})
	if reg != nil {
		for _, c := range []prometheus.Collector{p.polls, p.devices} {
			if err := reg.Register(c); err != nil {
				var are prometheus.AlreadyRegisteredError
				if !errors.As(err, &are) {
					return nil, err
				}
			}
		}
	}
	return p, nil
}

// SetWalker replaces the SNMP implementation (tests).
func (p *Poller) SetWalker(w Walker) { p.walk = w }

// Apply sets the settings (normalized) and the secret resolver.
func (p *Poller) Apply(s Settings, resolve Resolver) error {
	s, err := s.Normalize()
	if err != nil {
		return err
	}
	nets := make([][]netip.Prefix, len(s.Profiles))
	for i, pr := range s.Profiles {
		nets[i], _ = parsePrefixes(pr.Prefixes)
	}
	p.nets.Store(&nets)
	p.resolve.Store(&resolve)
	old := p.set.Swap(&s)
	p.mu.Lock()
	for _, d := range p.devs {
		d.configured = false
		// A changed profile or interval polls again now.
		if old == nil || !slices.EqualFunc(old.Profiles, s.Profiles, profileEqual) {
			d.next = time.Time{}
		}
	}
	for _, ds := range s.Devices {
		a := netip.MustParseAddr(ds)
		d := p.devs[a]
		if d == nil {
			d = &device{addr: a}
			p.devs[a] = d
		}
		d.configured = true
	}
	p.mu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
	return nil
}

func profileEqual(a, b Profile) bool {
	return a.ID == b.ID && a.Version == b.Version && a.Port == b.Port && a.CommunityRef == b.CommunityRef &&
		a.Username == b.Username && a.SecurityLevel == b.SecurityLevel && a.AuthProtocol == b.AuthProtocol &&
		a.AuthRef == b.AuthRef && a.PrivProtocol == b.PrivProtocol && a.PrivRef == b.PrivRef &&
		a.ContextName == b.ContextName && slices.Equal(a.Prefixes, b.Prefixes)
}

// Settings returns the applied settings.
func (p *Poller) Settings() Settings { return *p.set.Load() }

// profileFor returns the first profile covering a.
func (p *Poller) profileFor(a netip.Addr) (Profile, bool) {
	s := p.set.Load()
	nets := p.nets.Load()
	if nets == nil {
		return Profile{}, false
	}
	for i, pr := range s.Profiles {
		if len((*nets)[i]) == 0 {
			return pr, true
		}
		for _, n := range (*nets)[i] {
			if n.Contains(a) {
				return pr, true
			}
		}
	}
	return Profile{}, false
}

// Lookup implements enrich.IfNameSource. A miss for an exporter covered by
// a profile schedules a poll of it.
func (p *Poller) Lookup(exporter netip.Addr, ifIndex uint32) (name, descr string, speed uint64, ok bool) {
	s := p.set.Load()
	if !s.Enabled {
		return "", "", 0, false
	}
	exporter = exporter.Unmap()
	now := p.now()
	p.mu.RLock()
	d := p.devs[exporter]
	var it Interface
	found, fresh := false, false
	if d != nil {
		fresh = !d.lastWant.IsZero() && now.Sub(d.lastWant) < time.Minute
		if d.ifaces != nil && now.Sub(d.polled) < s.ttl() {
			it, found = d.ifaces[ifIndex]
		}
	}
	p.mu.RUnlock()
	if (d == nil || !fresh) && s.PollExporters {
		p.want(exporter, now)
	}
	if !found {
		return "", "", 0, false
	}
	return it.Name, it.Descr, it.Speed, true
}

func (p *Poller) want(a netip.Addr, now time.Time) {
	if _, ok := p.profileFor(a); !ok {
		return
	}
	p.mu.Lock()
	d := p.devs[a]
	if d == nil {
		if len(p.devs) >= MaxDevices {
			p.mu.Unlock()
			return
		}
		d = &device{addr: a}
		p.devs[a] = d
	}
	d.lastWant = now
	p.mu.Unlock()
}

// Run polls due devices until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		p.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.kick:
		}
	}
}

// tick starts the polls that are due and prunes forgotten devices.
func (p *Poller) tick(ctx context.Context) {
	s := p.set.Load()
	if !s.Enabled {
		return
	}
	now := p.now()
	if s.PollExporters && p.Exporters != nil {
		for _, a := range p.Exporters() {
			p.want(a.Unmap(), now)
		}
	}
	var due []*device
	p.mu.Lock()
	running := 0
	for a, d := range p.devs {
		if d.inflight {
			running++
			continue
		}
		active := d.configured || (s.PollExporters && now.Sub(d.lastWant) < s.ttl())
		if !active {
			if d.polled.IsZero() || now.Sub(d.polled) > s.ttl() {
				delete(p.devs, a)
			}
			continue
		}
		if now.Before(d.next) {
			continue
		}
		due = append(due, d)
	}
	sort.Slice(due, func(i, j int) bool { return due[i].next.Before(due[j].next) })
	if free := s.Concurrency - running; len(due) > free {
		due = due[:max(free, 0)]
	}
	for _, d := range due {
		d.inflight = true
	}
	p.mu.Unlock()
	for _, d := range due {
		go p.pollDevice(ctx, d, *s)
	}
}

func (p *Poller) pollDevice(ctx context.Context, d *device, s Settings) {
	ifaces, prof, err := p.Poll(ctx, d.addr)
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	d.inflight = false
	d.attempt = now
	d.profile = prof
	if err != nil {
		p.polls.WithLabelValues("error").Inc()
		d.err = err.Error()
		retry := max(s.interval()/4, time.Minute)
		d.next = now.Add(retry)
		p.log.Debug("SNMP poll failed", "device", d.addr, "err", err)
		return
	}
	p.polls.WithLabelValues("ok").Inc()
	d.err = ""
	d.ifaces, d.polled = ifaces, now
	d.next = now.Add(s.interval())
}

// Poll reads the interface table of a device now with its profile.
func (p *Poller) Poll(ctx context.Context, a netip.Addr) (map[uint32]Interface, string, error) {
	a = a.Unmap()
	prof, ok := p.profileFor(a)
	if !ok {
		return nil, "", fmt.Errorf("no SNMP profile covers %s", a)
	}
	ifs, err := p.PollWith(ctx, a, prof)
	return ifs, prof.Name, err
}

// PollWith reads the interface table of a device with the given profile.
func (p *Poller) PollWith(ctx context.Context, a netip.Addr, prof Profile) (map[uint32]Interface, error) {
	s := *p.set.Load()
	if s.TimeoutSeconds == 0 {
		s, _ = s.Normalize()
	}
	var resolve Resolver
	if r := p.resolve.Load(); r != nil {
		resolve = *r
	}
	cred, err := credentials(prof, resolve)
	if err != nil {
		return nil, err
	}
	return p.walk(ctx, a.Unmap(), prof, cred, s)
}

func credentials(p Profile, resolve Resolver) (Credentials, error) {
	var c Credentials
	get := func(what, ref string) (string, error) {
		if ref == "" {
			return "", nil
		}
		if resolve == nil {
			return "", errors.New("no secret resolver")
		}
		v, err := resolve(ref)
		if err != nil {
			return "", fmt.Errorf("%s of profile %q: %w", what, p.Name, err)
		}
		return v, nil
	}
	var err error
	if c.Community, err = get("community", p.CommunityRef); err != nil {
		return c, err
	}
	if c.Auth, err = get("auth password", p.AuthRef); err != nil {
		return c, err
	}
	if c.Priv, err = get("privacy password", p.PrivRef); err != nil {
		return c, err
	}
	if p.Version == Version2c && c.Community == "" {
		return c, fmt.Errorf("profile %q has no community", p.Name)
	}
	return c, nil
}

// client builds the gosnmp client of a profile.
func client(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{Target: a.String(), Port: p.Port, Transport: "udp", Timeout: s.timeout(), Retries: s.Retries,
		MaxRepetitions: 25, Context: ctx, MaxOids: gosnmp.MaxOids}
	if g.Port == 0 {
		g.Port = 161
	}
	switch p.Version {
	case Version2c:
		g.Version, g.Community = gosnmp.Version2c, c.Community
	case Version3:
		g.Version, g.SecurityModel, g.ContextName = gosnmp.Version3, gosnmp.UserSecurityModel, p.ContextName
		usm := &gosnmp.UsmSecurityParameters{UserName: p.Username}
		switch p.SecurityLevel {
		case NoAuthNoPriv:
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case AuthNoPriv:
			g.MsgFlags = gosnmp.AuthNoPriv
		default:
			g.MsgFlags = gosnmp.AuthPriv
		}
		if g.MsgFlags != gosnmp.NoAuthNoPriv {
			usm.AuthenticationProtocol = authProtocol(p.AuthProtocol)
			usm.AuthenticationPassphrase = c.Auth
		}
		if g.MsgFlags == gosnmp.AuthPriv {
			usm.PrivacyProtocol = privProtocol(p.PrivProtocol)
			usm.PrivacyPassphrase = c.Priv
		}
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("SNMP version %q", p.Version)
	}
	return g, nil
}

func authProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	return map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
		"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}[s]
}

func privProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	return map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192,
		"AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C}[s]
}

// Walk reads the interface table of a device once (the settings test).
func Walk(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings) (map[uint32]Interface, error) {
	if s.TimeoutSeconds == 0 {
		s, _ = s.Normalize()
	}
	if p.Port == 0 {
		p.Port = 161
	}
	return walkGoSNMP(ctx, a.Unmap(), p, c, s)
}

func walkGoSNMP(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings) (map[uint32]Interface, error) {
	g, err := client(ctx, a, p, c, s)
	if err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	var all []gosnmp.SnmpPDU
	for i, oid := range []string{oidIfName, oidIfDescr, oidIfAlias, oidIfHighSpeed, oidIfSpeed} {
		pdus, err := g.BulkWalkAll(oid)
		if err != nil {
			if i == 0 {
				return nil, err // the device does not answer
			}
			continue // an optional column
		}
		all = append(all, pdus...)
	}
	ifs := DecodeIfTable(all)
	if len(ifs) == 0 {
		return nil, errors.New("the device returned no interfaces")
	}
	return ifs, nil
}

// DecodeIfTable turns IF-MIB variables into interfaces by ifIndex.
func DecodeIfTable(pdus []gosnmp.SnmpPDU) map[uint32]Interface {
	type raw struct {
		name, descr, alias string
		high, speed        uint64
		hasHigh            bool
	}
	rows := map[uint32]*raw{}
	for _, v := range pdus {
		col, idx, ok := splitOID(v.Name)
		if !ok {
			continue
		}
		r := rows[idx]
		if r == nil {
			r = &raw{}
			rows[idx] = r
		}
		switch col {
		case oidIfName:
			r.name = text(v)
		case oidIfDescr:
			r.descr = text(v)
		case oidIfAlias:
			r.alias = text(v)
		case oidIfHighSpeed:
			if n := gosnmp.ToBigInt(v.Value); n != nil {
				r.high, r.hasHigh = n.Uint64(), true
			}
		case oidIfSpeed:
			if n := gosnmp.ToBigInt(v.Value); n != nil {
				r.speed = n.Uint64()
			}
		}
	}
	out := make(map[uint32]Interface, len(rows))
	for idx, r := range rows {
		it := Interface{Name: r.name, Descr: r.alias}
		if it.Name == "" {
			it.Name = r.descr
		}
		switch {
		// ifSpeed saturates at 4294967295 for links above 4 Gb/s.
		case r.hasHigh && r.high > 0:
			it.Speed = r.high * 1_000_000
		default:
			it.Speed = r.speed
		}
		out[idx] = it
	}
	return out
}

func text(v gosnmp.SnmpPDU) string {
	switch x := v.Value.(type) {
	case []byte:
		return strings.TrimRight(strings.ToValidUTF8(string(x), ""), "\x00")
	case string:
		return x
	}
	return ""
}

// splitOID returns the known column and the ifIndex of an instance OID.
func splitOID(oid string) (string, uint32, bool) {
	if !strings.HasPrefix(oid, ".") {
		oid = "." + oid
	}
	for _, col := range []string{oidIfName, oidIfDescr, oidIfAlias, oidIfHighSpeed, oidIfSpeed} {
		if strings.HasPrefix(oid, col+".") {
			n, err := strconv.ParseUint(oid[len(col)+1:], 10, 32)
			if err != nil {
				return "", 0, false
			}
			return col, uint32(n), true
		}
	}
	return "", 0, false
}

// DeviceStatus describes a polled device for the status API.
type DeviceStatus struct {
	Address    netip.Addr `json:"address"`
	Profile    string     `json:"profile,omitempty"`
	Interfaces int        `json:"interfaces"`
	Polled     *time.Time `json:"polled,omitempty"`
	Error      string     `json:"error,omitempty"`
	Configured bool       `json:"configured"`
}

// Status lists the devices by address.
func (p *Poller) Status() []DeviceStatus {
	p.mu.RLock()
	out := make([]DeviceStatus, 0, len(p.devs))
	for _, d := range p.devs {
		ds := DeviceStatus{Address: d.addr, Profile: d.profile, Interfaces: len(d.ifaces), Error: d.err, Configured: d.configured}
		if !d.polled.IsZero() {
			t := d.polled
			ds.Polled = &t
		}
		out = append(out, ds)
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Less(out[j].Address) })
	return out
}
