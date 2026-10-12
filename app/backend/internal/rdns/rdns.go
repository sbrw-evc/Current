// Package rdns resolves PTR names of flow addresses in the background, as
// ElastiFlow does: Lookup never blocks — it answers from a positive /
// negative cache and queues a miss for a bounded pool of workers that query
// the configured DNS servers under a rate limit. The first flows of an
// address get an empty name, later ones the cached name.
package rdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scopes: which addresses are resolved.
const (
	ScopeAll     = "all"
	ScopePrivate = "private" // RFC 1918, CGNAT, ULA
	ScopePublic  = "public"
)

// Settings are the user settings (PostgreSQL key SettingKey).
type Settings struct {
	Enabled bool `json:"enabled"`
	// Servers: DNS servers "host[:port]" queried in turn; empty = the
	// system resolver.
	Servers []string `json:"servers"`
	// Scope: all | private | public (default all).
	Scope string `json:"scope"`
	// Workers resolving in parallel (default 8, max 256).
	Workers int `json:"workers"`
	// RateLimit: queries per second over all workers (default 200; 0 = default).
	RateLimit float64 `json:"rate_limit"`
	// PositiveTTL / NegativeTTL in seconds (default 3600 / 600).
	PositiveTTL int `json:"positive_ttl"`
	NegativeTTL int `json:"negative_ttl"`
	// Timeout of one query in milliseconds (default 2000).
	Timeout int `json:"timeout_ms"`
	// CacheSize: maximum cached addresses (default 100000).
	CacheSize int `json:"cache_size"`
	// QueueSize: pending lookups; misses beyond it are dropped and retried
	// on a later flow (default 10000).
	QueueSize int `json:"queue_size"`
}

// SettingKey is the PostgreSQL settings key.
const SettingKey = "rdns"

// WithDefaults fills zero values.
func (s Settings) WithDefaults() Settings {
	if s.Scope == "" {
		s.Scope = ScopeAll
	}
	if s.Workers <= 0 {
		s.Workers = 8
	}
	if s.RateLimit <= 0 {
		s.RateLimit = 200
	}
	if s.PositiveTTL <= 0 {
		s.PositiveTTL = 3600
	}
	if s.NegativeTTL <= 0 {
		s.NegativeTTL = 600
	}
	if s.Timeout <= 0 {
		s.Timeout = 2000
	}
	if s.CacheSize <= 0 {
		s.CacheSize = 100_000
	}
	if s.QueueSize <= 0 {
		s.QueueSize = 10_000
	}
	if s.Servers == nil {
		s.Servers = []string{}
	}
	return s
}

// Validate checks the settings (after WithDefaults).
func (s Settings) Validate() error {
	var errs []error
	switch s.Scope {
	case ScopeAll, ScopePrivate, ScopePublic:
	default:
		errs = append(errs, fmt.Errorf("scope is all, private or public"))
	}
	if s.Workers > 256 {
		errs = append(errs, errors.New("workers: at most 256"))
	}
	if s.RateLimit > 100_000 {
		errs = append(errs, errors.New("rate_limit: at most 100000 per second"))
	}
	if s.Timeout > 30_000 {
		errs = append(errs, errors.New("timeout_ms: at most 30000"))
	}
	if s.CacheSize > 10_000_000 || s.QueueSize > 1_000_000 {
		errs = append(errs, errors.New("cache_size at most 10000000, queue_size at most 1000000"))
	}
	for _, sv := range s.Servers {
		if _, err := ServerAddr(sv); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ServerAddr normalizes "host[:port]" to "host:port" (port 53 by default).
func ServerAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("server: empty address")
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(s, ":") {
			return "", fmt.Errorf("server %q: %v", s, err)
		}
		host, port = s, "53"
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("server %q: host and port are required", s)
	}
	return net.JoinHostPort(host, port), nil
}

// LookupFunc resolves addr ("192.0.2.1") to its PTR names.
type LookupFunc func(ctx context.Context, server, addr string) ([]string, error)

// Config of a Resolver beyond the user settings.
type Config struct {
	// Lookup replaces DNS queries (tests); server is "" for the system
	// resolver.
	Lookup LookupFunc
	// Metrics registers Prometheus metrics when set.
	Metrics Registerer
	Now     func() time.Time
}

type entry struct {
	name    string
	expires time.Time
	pending bool
}

// Resolver is the asynchronous PTR resolver. The zero value is not usable;
// call New, then Run.
type Resolver struct {
	cfg Config
	set atomic.Pointer[Settings]

	mu    sync.RWMutex
	cache map[netip.Addr]*entry

	queue   atomic.Pointer[chan netip.Addr]
	limiter *limiter
	next    atomic.Uint64 // round-robin server index
	changed chan struct{}

	stats counters
	m     *metrics
}

type counters struct {
	hits, misses, dropped, found, notFound, errors atomic.Uint64
}

// New returns a resolver with settings s (disabled settings make Lookup
// return "" at once).
func New(s Settings, cfg Config) (*Resolver, error) {
	s = s.WithDefaults()
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Lookup == nil {
		cfg.Lookup = dnsLookup
	}
	r := &Resolver{cfg: cfg, cache: map[netip.Addr]*entry{}, changed: make(chan struct{}, 1)}
	r.limiter = newLimiter(s.RateLimit, cfg.Now)
	r.set.Store(&s)
	q := make(chan netip.Addr, s.QueueSize)
	r.queue.Store(&q)
	m, err := newMetrics(cfg.Metrics, r)
	if err != nil {
		return nil, err
	}
	r.m = m
	return r, nil
}

// Settings returns the settings in effect.
func (r *Resolver) Settings() Settings { return *r.set.Load() }

// Configure applies new settings; the worker pool is resized and the cache
// kept (entries are re-timed on their next refresh).
func (r *Resolver) Configure(s Settings) error {
	s = s.WithDefaults()
	if err := s.Validate(); err != nil {
		return err
	}
	old := r.set.Swap(&s)
	r.limiter.setRate(s.RateLimit)
	if old.QueueSize != s.QueueSize {
		q := make(chan netip.Addr, s.QueueSize)
		r.queue.Store(&q)
		// Entries waiting in the old queue are forgotten as pending; a later
		// flow queues them again.
		r.mu.Lock()
		for a, e := range r.cache {
			if e.pending && e.name == "" && e.expires.IsZero() {
				delete(r.cache, a)
			} else {
				e.pending = false
			}
		}
		r.mu.Unlock()
	}
	if !old.Enabled && s.Enabled || old.Workers != s.Workers || old.QueueSize != s.QueueSize {
		select {
		case r.changed <- struct{}{}:
		default:
		}
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func inScope(scope string, a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	private := a.IsPrivate() || cgnat.Contains(a)
	switch scope {
	case ScopePrivate:
		return private
	case ScopePublic:
		return !private
	}
	return true
}

// Lookup returns the cached PTR name of a ("" when unknown yet, negative or
// out of scope) and queues a resolution on a miss or an expired entry. It
// never blocks.
func (r *Resolver) Lookup(a netip.Addr) string {
	s := r.set.Load()
	if !s.Enabled {
		return ""
	}
	a = a.Unmap()
	if !inScope(s.Scope, a) {
		return ""
	}
	now := r.cfg.Now()
	r.mu.RLock()
	e := r.cache[a]
	var name string
	fresh, pending := false, false
	if e != nil {
		name, fresh, pending = e.name, now.Before(e.expires), e.pending
	}
	r.mu.RUnlock()
	if e != nil && (fresh || pending) {
		r.stats.hits.Add(1)
		return name
	}
	if e != nil {
		r.stats.hits.Add(1) // stale: answer the old name while refreshing
	} else {
		r.stats.misses.Add(1)
	}
	r.enqueue(a, s, now)
	return name
}

func (r *Resolver) enqueue(a netip.Addr, s *Settings, now time.Time) {
	r.mu.Lock()
	e := r.cache[a]
	if e != nil && (e.pending || now.Before(e.expires)) {
		r.mu.Unlock()
		return
	}
	if e == nil {
		if len(r.cache) >= s.CacheSize {
			r.evictLocked(now, s.CacheSize)
		}
		e = &entry{}
		r.cache[a] = e
	}
	e.pending = true
	r.mu.Unlock()
	q := *r.queue.Load()
	select {
	case q <- a:
	default:
		r.stats.dropped.Add(1)
		r.mu.Lock()
		if e.name == "" && e.expires.IsZero() {
			delete(r.cache, a)
		} else {
			e.pending = false
		}
		r.mu.Unlock()
	}
}

// evictLocked drops expired entries, then a random tenth of the cache when
// it is still full (map iteration order is random).
func (r *Resolver) evictLocked(now time.Time, size int) {
	for a, e := range r.cache {
		if !e.pending && !now.Before(e.expires) {
			delete(r.cache, a)
		}
	}
	if len(r.cache) < size {
		return
	}
	n := max(size/10, 1)
	for a, e := range r.cache {
		if n == 0 {
			break
		}
		if !e.pending {
			delete(r.cache, a)
			n--
		}
	}
}

// Run starts the workers and keeps the pool sized to the settings until ctx
// is done.
func (r *Resolver) Run(ctx context.Context) {
	for {
		s := r.set.Load()
		q := *r.queue.Load()
		wctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		if s.Enabled {
			for range s.Workers {
				wg.Go(func() { r.worker(wctx, q) })
			}
		}
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return
		case <-r.changed:
			cancel()
			wg.Wait()
		}
	}
}

func (r *Resolver) worker(ctx context.Context, q chan netip.Addr) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-q:
			if err := r.limiter.wait(ctx); err != nil {
				r.release(a)
				return
			}
			r.resolve(ctx, a)
		}
	}
}

// release clears the pending mark of an address not resolved.
func (r *Resolver) release(a netip.Addr) {
	r.mu.Lock()
	if e := r.cache[a]; e != nil {
		e.pending = false
	}
	r.mu.Unlock()
}

func (r *Resolver) server(s *Settings) string {
	if len(s.Servers) == 0 {
		return ""
	}
	i := r.next.Add(1) - 1
	addr, _ := ServerAddr(s.Servers[i%uint64(len(s.Servers))])
	return addr
}

func (r *Resolver) resolve(ctx context.Context, a netip.Addr) {
	s := r.set.Load()
	qctx, cancel := context.WithTimeout(ctx, time.Duration(s.Timeout)*time.Millisecond)
	start := r.cfg.Now()
	names, err := r.cfg.Lookup(qctx, r.server(s), a.String())
	cancel()
	r.m.observe(r.cfg.Now().Sub(start))
	if ctx.Err() != nil {
		r.release(a)
		return
	}
	now := r.cfg.Now()
	name := ""
	ttl := time.Duration(s.NegativeTTL) * time.Second
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(names) > 0:
		name = strings.TrimSuffix(names[0], ".")
		ttl = time.Duration(s.PositiveTTL) * time.Second
		r.stats.found.Add(1)
	case err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound):
		r.stats.notFound.Add(1)
	default:
		// Timeouts and server failures: retry sooner than a real negative
		// answer, keeping a name we had.
		r.stats.errors.Add(1)
		ttl = min(ttl, time.Minute)
	}
	r.mu.Lock()
	e := r.cache[a]
	if e == nil {
		e = &entry{}
		r.cache[a] = e
	}
	if name != "" || err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		e.name = name
	}
	e.expires, e.pending = now.Add(ttl), false
	r.mu.Unlock()
}

// Stats are the counters since start.
type Stats struct {
	Enabled  bool   `json:"enabled"`
	Cached   int    `json:"cached"`
	Queued   int    `json:"queued"`
	Hits     uint64 `json:"hits"`
	Misses   uint64 `json:"misses"`
	Dropped  uint64 `json:"dropped"`
	Found    uint64 `json:"found"`
	NotFound uint64 `json:"not_found"`
	Errors   uint64 `json:"errors"`
}

// Stats returns the counters.
func (r *Resolver) Stats() Stats {
	r.mu.RLock()
	n := len(r.cache)
	r.mu.RUnlock()
	return Stats{Enabled: r.set.Load().Enabled, Cached: n, Queued: len(*r.queue.Load()),
		Hits: r.stats.hits.Load(), Misses: r.stats.misses.Load(), Dropped: r.stats.dropped.Load(),
		Found: r.stats.found.Load(), NotFound: r.stats.notFound.Load(), Errors: r.stats.errors.Load()}
}

// dnsLookup queries server ("" = the system resolver) with the pure Go
// resolver.
func dnsLookup(ctx context.Context, server, addr string) ([]string, error) {
	res := net.DefaultResolver
	if server != "" {
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}}
	}
	return res.LookupAddr(ctx, addr)
}

// limiter is a token bucket of rate tokens per second with a burst of one
// second.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newLimiter(rate float64, now func() time.Time) *limiter {
	return &limiter{rate: rate, tokens: rate, last: now(), now: now}
}

func (l *limiter) setRate(rate float64) {
	l.mu.Lock()
	l.rate = rate
	l.tokens = min(l.tokens, rate)
	l.mu.Unlock()
}

func (l *limiter) wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := l.now()
		l.tokens = min(l.rate, l.tokens+now.Sub(l.last).Seconds()*l.rate)
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		d := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		t := time.NewTimer(max(d, time.Millisecond))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
