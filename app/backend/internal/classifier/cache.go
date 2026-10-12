package classifier

import (
	"reflect"
	"sync"
	"time"
)

func reflectMapStringAny() reflect.Type { return reflect.TypeOf(map[string]any{}) }

// ttlCache is a small bounded map with per-entry expiry. When full, expired
// entries are dropped, then the whole map if still full (results are cheap
// to recompute and the working set is the number of exporters/interfaces).
type ttlCache[K comparable, V any] struct {
	mu  sync.RWMutex
	m   map[K]ttlEntry[V]
	max int
	ttl time.Duration
}

type ttlEntry[V any] struct {
	v   V
	exp time.Time
}

func newTTLCache[K comparable, V any](max int, ttl time.Duration) *ttlCache[K, V] {
	return &ttlCache[K, V]{m: make(map[K]ttlEntry[V]), max: max, ttl: ttl}
}

func (c *ttlCache[K, V]) get(k K, now time.Time) (V, bool) {
	if c.ttl < 0 {
		var zero V
		return zero, false
	}
	c.mu.RLock()
	e, ok := c.m[k]
	c.mu.RUnlock()
	if !ok || now.After(e.exp) {
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *ttlCache[K, V]) put(k K, v V, now time.Time) {
	if c.ttl < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for kk, e := range c.m {
			if now.After(e.exp) {
				delete(c.m, kk)
			}
		}
		if len(c.m) >= c.max {
			clear(c.m)
		}
	}
	c.m[k] = ttlEntry[V]{v: v, exp: now.Add(c.ttl)}
}

func (c *ttlCache[K, V]) clear() {
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}
