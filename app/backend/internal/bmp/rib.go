package bmp

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// PeerKey identifies a BGP peer monitored by a BMP router. The same peer
// seen pre-policy and post-policy is two Adj-RIB-In (Post false / true).
type PeerKey struct {
	Router        netip.Addr // address of the BMP speaker (TCP source)
	Distinguisher uint64     // peer distinguisher (RD of an L3VPN peer)
	Address       netip.Addr
	AS            uint32
	Post          bool // post-policy Adj-RIB-In (or Loc-RIB)
}

// Route is the result of a lookup. Its slices are shared with the RIB and
// must not be modified.
type Route struct {
	Prefix netip.Prefix
	Attrs
	// LargeText are the large communities formatted as "a:b:c".
	LargeText []string
	Peer      PeerKey
}

// attrSet is an interned set of path attributes shared by many routes.
type attrSet struct {
	Attrs
	large []string
	key   string
	refs  int
	size  int // estimated bytes
}

type path struct {
	peer  uint32
	attrs *attrSet
}

// lpm is an exact-match table per prefix length; lookups walk the
// non-empty lengths from the longest. It is compact (one map entry per
// prefix) and fast enough for the few dozen distinct lengths of a full table.
type lpm[K comparable] struct {
	byLen []map[K][]path
	lens  []int // non-empty lengths, descending
	n     int
}

func newLPM[K comparable](bits int) *lpm[K] { return &lpm[K]{byLen: make([]map[K][]path, bits+1)} }

func (t *lpm[K]) get(l int, k K) []path {
	if m := t.byLen[l]; m != nil {
		return m[k]
	}
	return nil
}

func (t *lpm[K]) set(l int, k K, ps []path) {
	m := t.byLen[l]
	if len(ps) == 0 {
		if m == nil {
			return
		}
		if _, ok := m[k]; ok {
			delete(m, k)
			t.n--
			if len(m) == 0 {
				t.byLen[l] = nil
				t.reindex()
			}
		}
		return
	}
	fresh := m == nil
	if fresh {
		m = map[K][]path{}
		t.byLen[l] = m
	}
	if _, ok := m[k]; !ok {
		t.n++
	}
	m[k] = ps
	if fresh {
		t.reindex()
	}
}

func (t *lpm[K]) reindex() {
	t.lens = t.lens[:0]
	for l := len(t.byLen) - 1; l >= 0; l-- {
		if len(t.byLen[l]) > 0 {
			t.lens = append(t.lens, l)
		}
	}
}

func key4(a netip.Addr, bits int) uint32 {
	b := a.As4()
	v := binary.BigEndian.Uint32(b[:])
	if bits == 0 {
		return 0
	}
	return v &^ (1<<(32-bits) - 1)
}

func key6(a netip.Addr, bits int) [16]byte {
	return netip.PrefixFrom(a, bits).Masked().Addr().As16()
}

type peerState struct {
	key    PeerKey
	routes int
	since  time.Time
	last   time.Time
}

// RIB holds the Adj-RIB-In of every monitored peer in two LPM tables.
// It is safe for concurrent use.
type RIB struct {
	mu    sync.RWMutex
	v4    *lpm[uint32]
	v6    *lpm[[16]byte]
	attrs map[string]*attrSet
	peers []*peerState // index = peer id; nil = free
	ids   map[PeerKey]uint32
	bytes int // estimated size of the attribute sets
	now   func() time.Time
}

// NewRIB returns an empty RIB.
func NewRIB() *RIB {
	return &RIB{v4: newLPM[uint32](32), v6: newLPM[[16]byte](128), attrs: map[string]*attrSet{},
		ids: map[PeerKey]uint32{}, now: time.Now}
}

// peerID returns the id of a peer, registering it.
func (r *RIB) peerID(k PeerKey) uint32 {
	if id, ok := r.ids[k]; ok {
		return id
	}
	now := r.now()
	st := &peerState{key: k, since: now, last: now}
	for i, p := range r.peers {
		if p == nil {
			r.peers[i] = st
			r.ids[k] = uint32(i)
			return uint32(i)
		}
	}
	r.peers = append(r.peers, st)
	r.ids[k] = uint32(len(r.peers) - 1)
	return uint32(len(r.peers) - 1)
}

// AddPeer registers a peer (Peer Up) without routes.
func (r *RIB) AddPeer(k PeerKey) {
	r.mu.Lock()
	r.peerID(k)
	r.mu.Unlock()
}

func attrKey(a *Attrs) string {
	b := make([]byte, 0, 32+4*len(a.ASPath)+4*len(a.Communities)+12*len(a.LargeCommunities))
	nh := a.NextHop.AsSlice()
	b = append(b, byte(len(nh)))
	b = append(b, nh...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(a.ASPath)))
	for _, v := range a.ASPath {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(a.Communities)))
	for _, v := range a.Communities {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	for _, v := range a.LargeCommunities {
		b = binary.BigEndian.AppendUint32(b, v.Global)
		b = binary.BigEndian.AppendUint32(b, v.Local1)
		b = binary.BigEndian.AppendUint32(b, v.Local2)
	}
	return string(b)
}

func (r *RIB) intern(a *Attrs) *attrSet {
	k := attrKey(a)
	if s, ok := r.attrs[k]; ok {
		s.refs++
		return s
	}
	s := &attrSet{Attrs: Attrs{ASPath: slices.Clip(a.ASPath), Communities: slices.Clip(a.Communities),
		LargeCommunities: slices.Clip(a.LargeCommunities), NextHop: a.NextHop}, key: k, refs: 1}
	if len(a.LargeCommunities) > 0 {
		s.large = make([]string, len(a.LargeCommunities))
		for i, c := range a.LargeCommunities {
			s.large[i] = c.String()
		}
	}
	s.size = 160 + 2*len(k)
	for _, l := range s.large {
		s.size += 16 + len(l)
	}
	r.attrs[k] = s
	r.bytes += s.size
	return s
}

func (r *RIB) release(s *attrSet) {
	s.refs--
	if s.refs <= 0 {
		delete(r.attrs, s.key)
		r.bytes -= s.size
	}
}

// replace sets (s != nil) or removes (s == nil) the path of peer in ps.
func (r *RIB) replace(ps []path, peer uint32, s *attrSet) ([]path, int) {
	delta := 0
	for i := range ps {
		if ps[i].peer == peer {
			r.release(ps[i].attrs)
			if s == nil {
				out := make([]path, 0, len(ps)-1)
				out = append(out, ps[:i]...)
				return append(out, ps[i+1:]...), -1
			}
			out := slices.Clone(ps)
			out[i].attrs = s
			return out, 0
		}
	}
	if s == nil {
		return ps, 0
	}
	out := make([]path, len(ps), len(ps)+1)
	copy(out, ps)
	delta = 1
	return append(out, path{peer: peer, attrs: s}), delta
}

func (r *RIB) setPath(p netip.Prefix, peer uint32, s *attrSet) int {
	a, bits := p.Addr(), p.Bits()
	if a.Is4() {
		k := key4(a, bits)
		ps, d := r.replace(r.v4.get(bits, k), peer, s)
		r.v4.set(bits, k, ps)
		return d
	}
	k := key6(a, bits)
	ps, d := r.replace(r.v6.get(bits, k), peer, s)
	r.v6.set(bits, k, ps)
	return d
}

// apply processes an UPDATE of a peer: withdrawals first, then announcements.
func (r *RIB) apply(k PeerKey, u *update) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.peerID(k)
	st := r.peers[id]
	st.last = r.now()
	for _, p := range u.withdrawn {
		st.routes += r.setPath(p, id, nil)
	}
	if len(u.announced) == 0 || !u.hasAttrs {
		return
	}
	for _, p := range u.announced {
		s := r.intern(&u.attrs)
		st.routes += r.setPath(p, id, s)
	}
}

func removeFrom[K comparable](r *RIB, t *lpm[K], drop func(uint32) bool) {
	type change struct {
		l  int
		k  K
		ps []path
	}
	var changes []change
	for l, m := range t.byLen {
		for k, ps := range m {
			var keep []path
			changed := false
			for _, p := range ps {
				if drop(p.peer) {
					r.release(p.attrs)
					changed = true
					continue
				}
				keep = append(keep, p)
			}
			if changed {
				changes = append(changes, change{l, k, keep})
			}
		}
	}
	for _, c := range changes {
		t.set(c.l, c.k, c.ps)
	}
}

// removePeers drops every route of the peers matching match and forgets them.
func (r *RIB) removePeers(match func(PeerKey) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	drop := map[uint32]bool{}
	for id, p := range r.peers {
		if p != nil && match(p.key) {
			drop[uint32(id)] = true
		}
	}
	if len(drop) == 0 {
		return 0
	}
	f := func(id uint32) bool { return drop[id] }
	removeFrom(r, r.v4, f)
	removeFrom(r, r.v6, f)
	for id := range drop {
		delete(r.ids, r.peers[id].key)
		r.peers[id] = nil
	}
	return len(drop)
}

// RemovePeer drops the routes of a peer (pre- and post-policy) after a Peer
// Down notification.
func (r *RIB) RemovePeer(k PeerKey) int {
	return r.removePeers(func(p PeerKey) bool {
		return p.Router == k.Router && p.Distinguisher == k.Distinguisher && p.Address == k.Address
	})
}

// RemoveRouter drops every peer of a BMP speaker (session closed).
func (r *RIB) RemoveRouter(router netip.Addr) int {
	return r.removePeers(func(p PeerKey) bool { return p.Router == router })
}

// better reports whether a is preferred to b: post-policy first, then the
// shorter AS path, then the older peer id (stable).
func (r *RIB) better(a, b path) bool {
	pa, pb := r.peers[a.peer], r.peers[b.peer]
	if pa.key.Post != pb.key.Post {
		return pa.key.Post
	}
	if la, lb := len(a.attrs.ASPath), len(b.attrs.ASPath); la != lb {
		return la < lb
	}
	return a.peer < b.peer
}

func (r *RIB) best(ps []path) path {
	b := ps[0]
	for _, p := range ps[1:] {
		if r.better(p, b) {
			b = p
		}
	}
	return b
}

// Lookup returns the most specific route covering a.
func (r *RIB) Lookup(a netip.Addr) (Route, bool) {
	a = a.Unmap()
	if !a.IsValid() {
		return Route{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		for _, l := range r.v4.lens {
			k := uint32(0)
			if l > 0 {
				k = v &^ (1<<(32-l) - 1)
			}
			if ps := r.v4.byLen[l][k]; len(ps) > 0 {
				return r.route(netip.PrefixFrom(a, l).Masked(), ps), true
			}
		}
		return Route{}, false
	}
	for _, l := range r.v6.lens {
		if ps := r.v6.byLen[l][key6(a, l)]; len(ps) > 0 {
			return r.route(netip.PrefixFrom(a, l).Masked(), ps), true
		}
	}
	return Route{}, false
}

func (r *RIB) route(p netip.Prefix, ps []path) Route {
	b := r.best(ps)
	return Route{Prefix: p, Attrs: b.attrs.Attrs, LargeText: b.attrs.large, Peer: r.peers[b.peer].key}
}

// Stats is the size of the RIB.
type Stats struct {
	PrefixesV4 int `json:"prefixes_v4"`
	PrefixesV6 int `json:"prefixes_v6"`
	Routes     int `json:"routes"` // paths: prefixes × peers
	AttrSets   int `json:"attribute_sets"`
	Peers      int `json:"peers"`
	// Bytes is an estimate of the memory held by the tables.
	Bytes int64 `json:"bytes"`
}

// Stats returns the current size.
func (r *RIB) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Stats{PrefixesV4: r.v4.n, PrefixesV6: r.v6.n, AttrSets: len(r.attrs)}
	for _, p := range r.peers {
		if p != nil {
			s.Peers++
			s.Routes += p.routes
		}
	}
	// map entry ≈ key + slice header + bucket overhead; path = 16 bytes.
	s.Bytes = int64(r.v4.n*(4+24+24)+r.v6.n*(16+24+24)+s.Routes*16) + int64(r.bytes)
	return s
}

// PeerInfo describes a peer for the status API.
type PeerInfo struct {
	Router        netip.Addr `json:"router"`
	Address       netip.Addr `json:"address"`
	AS            uint32     `json:"as"`
	Distinguisher uint64     `json:"distinguisher,omitempty"`
	PostPolicy    bool       `json:"post_policy"`
	Routes        int        `json:"routes"`
	Since         time.Time  `json:"since"`
	LastUpdate    time.Time  `json:"last_update"`
}

// Peers lists the peers, by router then peer address.
func (r *RIB) Peers() []PeerInfo {
	r.mu.RLock()
	out := make([]PeerInfo, 0, len(r.ids))
	for _, p := range r.peers {
		if p == nil {
			continue
		}
		out = append(out, PeerInfo{Router: p.key.Router, Address: p.key.Address, AS: p.key.AS, Distinguisher: p.key.Distinguisher,
			PostPolicy: p.key.Post, Routes: p.routes, Since: p.since, LastUpdate: p.last})
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Router.Compare(out[j].Router); c != 0 {
			return c < 0
		}
		if c := out[i].Address.Compare(out[j].Address); c != 0 {
			return c < 0
		}
		return !out[i].PostPolicy && out[j].PostPolicy
	})
	return out
}
