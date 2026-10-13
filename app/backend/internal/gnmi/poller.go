package gnmi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Interface is what gNMI tells about one ifindex.
type Interface struct {
	Name  string `json:"name"`  // interface name, "<name>.<index>" for a subinterface
	Descr string `json:"descr"` // state/description
	Speed uint64 `json:"speed"` // bits per second (Ethernet port speed or LAG speed)
}

// Resolver resolves openbao:// references (secrets.Value over the client).
type Resolver func(ref string) (string, error)

// Getter reads the interfaces of one device; the default uses gNMI Get over gRPC.
type Getter func(ctx context.Context, target netip.Addr, p Profile, cred Credentials, s Settings) (map[uint32]Interface, error)

// Credentials are the resolved secrets of a profile.
type Credentials struct{ Password, CA string }

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
	get     Getter
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
	p := &Poller{log: log.With("component", "gnmi"), get: getGNMI, devs: map[netip.Addr]*device{}, now: time.Now,
		kick: make(chan struct{}, 1)}
	p.set.Store(&Settings{})
	p.polls = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "gnmi", Name: "polls_total",
		Help: "gNMI polls of devices by result."}, []string{"result"})
	p.devices = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "flow", Subsystem: "gnmi", Name: "devices",
		Help: "Devices with gNMI interface data."}, func() float64 {
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

// SetGetter replaces the gNMI implementation (tests).
func (p *Poller) SetGetter(g Getter) { p.get = g }

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
		// A changed profile polls again now.
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
	return a.ID == b.ID && a.Port == b.Port && a.Username == b.Username && a.PasswordRef == b.PasswordRef &&
		a.TLS == b.TLS && a.SkipVerify == b.SkipVerify && a.CARef == b.CARef && a.ServerName == b.ServerName &&
		a.Encoding == b.Encoding && slices.Equal(a.Prefixes, b.Prefixes)
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
		p.log.Debug("gNMI poll failed", "device", d.addr, "err", err)
		return
	}
	p.polls.WithLabelValues("ok").Inc()
	d.err = ""
	d.ifaces, d.polled = ifaces, now
	d.next = now.Add(s.interval())
}

// Poll reads the interfaces of a device now with its profile.
func (p *Poller) Poll(ctx context.Context, a netip.Addr) (map[uint32]Interface, string, error) {
	a = a.Unmap()
	prof, ok := p.profileFor(a)
	if !ok {
		return nil, "", fmt.Errorf("no gNMI profile covers %s", a)
	}
	ifs, err := p.PollWith(ctx, a, prof)
	return ifs, prof.Name, err
}

// PollWith reads the interfaces of a device with the given profile.
func (p *Poller) PollWith(ctx context.Context, a netip.Addr, prof Profile) (map[uint32]Interface, error) {
	s := *p.set.Load()
	if s.TimeoutSeconds == 0 {
		s, _ = s.Normalize()
	}
	var resolve Resolver
	if r := p.resolve.Load(); r != nil {
		resolve = *r
	}
	cred, err := resolveCredentials(prof, resolve)
	if err != nil {
		return nil, err
	}
	return p.get(ctx, a.Unmap(), prof, cred, s)
}

func resolveCredentials(p Profile, resolve Resolver) (Credentials, error) {
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
	if c.Password, err = get("password", p.PasswordRef); err != nil {
		return c, err
	}
	if p.TLS {
		if c.CA, err = get("CA certificate", p.CARef); err != nil {
			return c, err
		}
	}
	if p.Username != "" && c.Password == "" {
		return c, fmt.Errorf("profile %q has no password", p.Name)
	}
	return c, nil
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
