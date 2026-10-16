package beacon

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/query"
)

// ScopeTTL is how long a user's scope is cached (§3.2).
const ScopeTTL = 60 * time.Second

// errorTTL keeps a failed lookup for a few seconds so a page that fires
// several queries does not hit an unreachable Beacon for each one.
const errorTTL = 5 * time.Second

// FetchFunc fetches a user's scope (Client.Scope with the current settings).
type FetchFunc func(ctx context.Context, username string) (*ScopeReply, error)

// ScopeCache caches scopes per user (case-insensitive login).
type ScopeCache struct {
	Fetch FetchFunc
	TTL   time.Duration
	Now   func() time.Time

	mu      sync.Mutex
	entries map[string]*scopeEntry
	gen     uint64
}

type scopeEntry struct {
	mu    sync.Mutex
	at    time.Time
	gen   uint64
	reply *ScopeReply
	err   error
}

// NewScopeCache returns a cache over fetch.
func NewScopeCache(fetch FetchFunc) *ScopeCache {
	return &ScopeCache{Fetch: fetch, TTL: ScopeTTL}
}

func (c *ScopeCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Invalidate drops every cached scope (the connection settings changed).
func (c *ScopeCache) Invalidate() {
	c.mu.Lock()
	c.entries = nil
	c.gen++
	c.mu.Unlock()
}

// Get returns the user's scope reply, from the cache when fresh. Concurrent
// lookups of one user share one request.
func (c *ScopeCache) Get(ctx context.Context, username string) (*ScopeReply, time.Time, error) {
	key := strings.ToLower(strings.TrimSpace(username))
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*scopeEntry{}
	}
	e := c.entries[key]
	if e == nil {
		e = &scopeEntry{}
		c.entries[key] = e
	}
	gen := c.gen
	c.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	ttl := c.TTL
	if ttl <= 0 {
		ttl = ScopeTTL
	}
	if e.err != nil {
		ttl = min(ttl, errorTTL)
	}
	now := c.now()
	if !e.at.IsZero() && e.gen == gen && now.Sub(e.at) < ttl {
		return e.reply, e.at, e.err
	}
	reply, err := c.Fetch(ctx, username)
	if ctx.Err() != nil && err != nil {
		// The request was cancelled: do not cache that.
		return nil, now, err
	}
	e.reply, e.err, e.at, e.gen = reply, err, now, gen
	return reply, now, err
}

// QueryScope turns a scope reply into the ClickHouse restriction: nil
// (unrestricted) for mode "all", the CIs' source_refs and addresses
// otherwise; an unknown user sees nothing.
func QueryScope(r *ScopeReply) *query.Scope {
	if r == nil || !r.Known {
		return query.NewScope(nil, nil)
	}
	if r.Mode == ModeAll {
		return nil
	}
	var refs, ips []string
	for _, ci := range r.CIs {
		refs = append(refs, ci.SourceRefs...)
		ips = append(ips, ci.IPs...)
	}
	return query.NewScope(refs, ips)
}
