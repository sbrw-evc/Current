package rdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type fakeDNS struct {
	mu      sync.Mutex
	names   map[string]string
	calls   map[string]int
	servers map[string]int
	block   chan struct{}
	fail    atomic.Bool
}

func newFake() *fakeDNS {
	return &fakeDNS{names: map[string]string{}, calls: map[string]int{}, servers: map[string]int{}}
}

func (f *fakeDNS) lookup(ctx context.Context, server, addr string) ([]string, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[addr]++
	f.servers[server]++
	if f.fail.Load() {
		return nil, &net.DNSError{Err: "server misbehaving", Name: addr, IsTemporary: true}
	}
	if n, ok := f.names[addr]; ok {
		return []string{n}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeDNS) count(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[addr]
}

// waitName polls Lookup until it returns want.
func waitName(t *testing.T, r *Resolver, a netip.Addr, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.Lookup(a); got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Lookup(%s) never became %q (stats %+v)", a, want, r.Stats())
}

func TestResolverAsyncAndCache(t *testing.T) {
	f := newFake()
	f.names["192.0.2.10"] = "web.example.com."
	var clock atomic.Pointer[time.Time]
	now := time.Unix(1_700_000_000, 0)
	clock.Store(&now)
	tick := func(d time.Duration) { n := clock.Load().Add(d); clock.Store(&n) }
	reg := prometheus.NewRegistry()
	r, err := New(Settings{Enabled: true, Servers: []string{"192.0.2.53", "[2001:db8::53]:5353"}, PositiveTTL: 60, NegativeTTL: 10, RateLimit: 10000},
		Config{Lookup: f.lookup, Metrics: reg, Now: func() time.Time { return *clock.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	a := netip.MustParseAddr("192.0.2.10")
	if got := r.Lookup(a); got != "" {
		t.Fatalf("first lookup must not block and return empty, got %q", got)
	}
	waitName(t, r, a, "web.example.com")
	if n := f.count("192.0.2.10"); n != 1 {
		t.Fatalf("queries = %d, want 1 (cached)", n)
	}
	// IPv4-mapped addresses share the entry.
	if got := r.Lookup(netip.AddrFrom16(a.As16())); got != "web.example.com" {
		t.Fatalf("mapped lookup = %q", got)
	}

	// Negative answer cached for NegativeTTL.
	b := netip.MustParseAddr("192.0.2.11")
	r.Lookup(b)
	deadline := time.Now().Add(2 * time.Second)
	for f.count("192.0.2.11") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	r.Lookup(b)
	r.Lookup(b)
	if n := f.count("192.0.2.11"); n != 1 {
		t.Fatalf("negative queries = %d, want 1", n)
	}
	// After the negative TTL the address is asked again; now it has a name.
	f.mu.Lock()
	f.names["192.0.2.11"] = "db.example.com"
	f.mu.Unlock()
	tick(11 * time.Second)
	waitName(t, r, b, "db.example.com")

	// Positive TTL expiry: stale name served while refreshing.
	tick(61 * time.Second)
	f.mu.Lock()
	f.names["192.0.2.10"] = "web2.example.com"
	f.mu.Unlock()
	if got := r.Lookup(a); got != "web.example.com" {
		t.Fatalf("stale lookup = %q, want the old name", got)
	}
	waitName(t, r, a, "web2.example.com")

	// Servers used in turn, normalized with the default port.
	f.mu.Lock()
	if f.servers["192.0.2.53:53"] == 0 || f.servers["[2001:db8::53]:5353"] == 0 {
		t.Fatalf("servers = %v", f.servers)
	}
	f.mu.Unlock()

	st := r.Stats()
	if st.Found < 3 || st.NotFound < 1 || st.Misses < 2 {
		t.Fatalf("stats = %+v", st)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for _, n := range []string{"flow_rdns_lookups_total", "flow_rdns_cache_hits_total", "flow_rdns_cache_entries", "flow_rdns_query_duration_seconds"} {
		if !names[n] {
			t.Errorf("metric %s missing", n)
		}
	}
}

func TestResolverScopeDisabledAndQueue(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	r, err := New(Settings{Enabled: true, Scope: ScopePublic, Workers: 1, QueueSize: 2, RateLimit: 1000}, Config{Lookup: f.lookup})
	if err != nil {
		t.Fatal(err)
	}
	// Private address out of scope: never queued.
	r.Lookup(netip.MustParseAddr("10.0.0.1"))
	r.Lookup(netip.MustParseAddr("127.0.0.1"))
	if st := r.Stats(); st.Cached != 0 || st.Misses != 0 {
		t.Fatalf("out-of-scope addresses must be ignored: %+v", st)
	}
	// Without workers running the queue (2) fills up; the rest is dropped
	// and never blocks.
	done := make(chan struct{})
	go func() {
		for i := range 10 {
			r.Lookup(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Lookup blocked")
	}
	if st := r.Stats(); st.Queued != 2 || st.Dropped != 8 || st.Cached != 2 {
		t.Fatalf("stats = %+v", st)
	}
	// Disabled: nothing.
	if err := r.Configure(Settings{Enabled: false, QueueSize: 2}); err != nil {
		t.Fatal(err)
	}
	if got := r.Lookup(netip.MustParseAddr("198.51.100.1")); got != "" {
		t.Fatal(got)
	}
	close(f.block)
}

func TestResolverErrorsRetrySooner(t *testing.T) {
	f := newFake()
	f.fail.Store(true)
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	r, err := New(Settings{Enabled: true, NegativeTTL: 3600, RateLimit: 1000}, Config{Lookup: f.lookup, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	a := netip.MustParseAddr("203.0.113.5")
	r.Lookup(a)
	deadline := time.Now().Add(2 * time.Second)
	for r.Stats().Errors == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	f.fail.Store(false)
	f.mu.Lock()
	f.names["203.0.113.5"] = "ok.example.net"
	f.mu.Unlock()
	mu.Lock()
	now = now.Add(61 * time.Second) // error TTL is at most a minute
	mu.Unlock()
	waitName(t, r, a, "ok.example.net")
}

func TestSettings(t *testing.T) {
	for _, s := range []string{"192.0.2.1", "dns.example.com", "192.0.2.1:5353", "[2001:db8::1]:53", "2001:db8::1"} {
		if _, err := ServerAddr(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if got, _ := ServerAddr("2001:db8::1"); got != "[2001:db8::1]:53" {
		t.Errorf("got %s", got)
	}
	if err := (Settings{Scope: "some"}).WithDefaults().Validate(); err == nil {
		t.Error("bad scope accepted")
	}
	if err := (Settings{Servers: []string{"a:b:c"}}).WithDefaults().Validate(); err == nil {
		t.Error("bad server accepted")
	}
	var dnsErr *net.DNSError
	if errors.As(errors.New("x"), &dnsErr) {
		t.Fatal()
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	var mu sync.Mutex
	l := newLimiter(2, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	ctx := context.Background()
	for range 2 {
		if err := l.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// The bucket is empty: the third call waits until the clock advances.
	done := make(chan struct{})
	go func() { _ = l.wait(ctx); close(done) }()
	select {
	case <-done:
		t.Fatal("limiter did not wait")
	case <-time.After(30 * time.Millisecond):
	}
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("limiter never released")
	}
}
