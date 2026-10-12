package enrich

import (
	"cmp"
	"container/heap"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// unknownBatch collects unknown exporters / addresses of one batch so the
// shared tracker is locked once per batch. Maps are allocated lazily.
type unknownBatch struct {
	exporters map[netip.Addr]uint64
	addrs     map[netip.Addr]uint64
}

func (b *unknownBatch) exporter(a netip.Addr) {
	if b.exporters == nil {
		b.exporters = make(map[netip.Addr]uint64, 4)
	}
	b.exporters[a]++
}

func (b *unknownBatch) address(a netip.Addr, bytes uint64) {
	if b.addrs == nil {
		b.addrs = make(map[netip.Addr]uint64, 16)
	}
	b.addrs[a] += bytes
}

// unknownTracker keeps unknown exporters (bounded, oldest evicted) and the
// top-k unknown addresses by bytes with the Space-Saving algorithm (counts
// may be overestimated for entries that replaced an evicted one).
type unknownTracker struct {
	mu        sync.Mutex
	maxExp    int
	k         int
	exporters map[netip.Addr]*UnknownExporter
	addrIdx   map[netip.Addr]*ssItem
	heap      ssHeap
}

type ssItem struct {
	addr  netip.Addr
	bytes uint64
	index int
}

type ssHeap []*ssItem

func (h ssHeap) Len() int           { return len(h) }
func (h ssHeap) Less(i, j int) bool { return h[i].bytes < h[j].bytes }
func (h ssHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *ssHeap) Push(x any)        { it := x.(*ssItem); it.index = len(*h); *h = append(*h, it) }
func (h *ssHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

func newUnknownTracker(maxExp, k int) *unknownTracker {
	return &unknownTracker{maxExp: maxExp, k: k, exporters: map[netip.Addr]*UnknownExporter{}, addrIdx: map[netip.Addr]*ssItem{}}
}

func (t *unknownTracker) addrsEnabled() bool { return t.k > 0 }

func (t *unknownTracker) batch() *unknownBatch { return &unknownBatch{} }

func (t *unknownTracker) merge(b *unknownBatch, now time.Time) {
	if b.exporters == nil && b.addrs == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for a, n := range b.exporters {
		x := t.exporters[a]
		if x == nil {
			if len(t.exporters) >= t.maxExp {
				var oldest netip.Addr
				var ot time.Time
				for k, v := range t.exporters {
					if ot.IsZero() || v.LastSeen.Before(ot) {
						oldest, ot = k, v.LastSeen
					}
				}
				delete(t.exporters, oldest)
			}
			x = &UnknownExporter{Address: a}
			t.exporters[a] = x
		}
		x.LastSeen = now
		x.Flows += n
	}
	for a, n := range b.addrs {
		if it := t.addrIdx[a]; it != nil {
			it.bytes += n
			heap.Fix(&t.heap, it.index)
			continue
		}
		if len(t.heap) < t.k {
			it := &ssItem{addr: a, bytes: n}
			heap.Push(&t.heap, it)
			t.addrIdx[a] = it
			continue
		}
		minItem := t.heap[0]
		delete(t.addrIdx, minItem.addr)
		minItem.addr = a
		minItem.bytes += n
		t.addrIdx[a] = minItem
		heap.Fix(&t.heap, 0)
	}
}

func (t *unknownTracker) snapshot() Unknown {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := Unknown{Exporters: make([]UnknownExporter, 0, len(t.exporters)), Addresses: make([]UnknownAddress, 0, len(t.heap))}
	for _, x := range t.exporters {
		u.Exporters = append(u.Exporters, *x)
	}
	for _, it := range t.heap {
		u.Addresses = append(u.Addresses, UnknownAddress{Address: it.addr, Bytes: it.bytes})
	}
	slices.SortFunc(u.Exporters, func(a, b UnknownExporter) int {
		return cmp.Or(b.LastSeen.Compare(a.LastSeen), a.Address.Compare(b.Address))
	})
	slices.SortFunc(u.Addresses, func(a, b UnknownAddress) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), a.Address.Compare(b.Address))
	})
	return u
}

func (t *unknownTracker) reset() {
	t.mu.Lock()
	clear(t.exporters)
	clear(t.addrIdx)
	t.heap = nil
	t.mu.Unlock()
}

// forget drops entries the current snapshot now knows about.
func (t *unknownTracker) forget(knownExporter, knownAddr func(netip.Addr) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for a := range t.exporters {
		if knownExporter(a) {
			delete(t.exporters, a)
		}
	}
	kept := t.heap[:0]
	for _, it := range t.heap {
		if knownAddr(it.addr) {
			delete(t.addrIdx, it.addr)
			continue
		}
		kept = append(kept, it)
	}
	t.heap = kept
	for i, it := range t.heap {
		it.index = i
	}
	heap.Init(&t.heap)
}
