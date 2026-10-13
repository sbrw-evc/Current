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
	// RD is the route distinguisher of the table the route was found in
	// (0: global).
	RD uint64
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

// table is the routing table of one route distinguisher.
type table struct {
	v4 *lpm[uint32]
	v6 *lpm[[16]byte]
}

func newTable() *table { return &table{v4: newLPM[uint32](32), v6: newLPM[[16]byte](128)} }

func (t *table) empty() bool { return t.v4.n == 0 && t.v6.n == 0 }

// RIB holds the Adj-RIB-In of every monitored peer in LPM tables: one for
// the global routing table (RD 0) and one per VPN route distinguisher.
// It is safe for concurrent use.
type RIB struct {
	mu     sync.RWMutex
	tables map[uint64]*table
	attrs  map[string]*attrSet
	peers  []*peerState // index = peer id; nil = free
	ids    map[PeerKey]uint32
	bytes  int // estimated size of the attribute sets
	now    func() time.Time
}

// NewRIB returns an empty RIB.
func NewRIB() *RIB {
	return &RIB{tables: map[uint64]*table{0: newTable()}, attrs: map[string]*attrSet{},
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

// setPath sets or removes a path in the table of rd; empty VPN tables are
// dropped.
func (r *RIB) setPath(rd uint64, p netip.Prefix, peer uint32, s *attrSet) int {
	t := r.tables[rd]
	if t == nil {
		if s == nil {
			return 0
		}
		t = newTable()
		r.tables[rd] = t
	}
	a, bits := p.Addr(), p.Bits()
	var d int
	if a.Is4() {
		k := key4(a, bits)
		var ps []path
		ps, d = r.replace(t.v4.get(bits, k), peer, s)
		t.v4.set(bits, k, ps)
	} else {
		k := key6(a, bits)
		var ps []path
		ps, d = r.replace(t.v6.get(bits, k), peer, s)
		t.v6.set(bits, k, ps)
	}
	if rd != 0 && t.empty() {
		delete(r.tables, rd)
	}
	return d
}

// apply processes an UPDATE of a peer: withdrawals first, then announcements.
// Unicast prefixes go to the table of rd (the peer distinguisher of an RD
// instance or VRF Loc-RIB peer, 0 for the global table); VPN prefixes to the
// table of their own route distinguisher.
func (r *RIB) apply(k PeerKey, rd uint64, u *update) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.peerID(k)
	st := r.peers[id]
	st.last = r.now()
	for _, p := range u.withdrawn {
		st.routes += r.setPath(rd, p, id, nil)
	}
	for _, p := range u.vpnWithdrawn {
		st.routes += r.setPath(p.rd, p.prefix, id, nil)
	}
	if !u.hasAttrs {
		return
	}
	for _, p := range u.announced {
		st.routes += r.setPath(rd, p, id, r.intern(&u.attrs))
	}
	for _, p := range u.vpnAnnounced {
		st.routes += r.setPath(p.rd, p.prefix, id, r.intern(&u.attrs))
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
	for rd, t := range r.tables {
		removeFrom(r, t.v4, f)
		removeFrom(r, t.v6, f)
		if rd != 0 && t.empty() {
			delete(r.tables, rd)
		}
	}
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

// Lookup returns the most specific route covering a in the global table.
func (r *RIB) Lookup(a netip.Addr) (Route, bool) { return r.LookupRD(0, a) }

// LookupRD returns the most specific route covering a in the VPN table of
// rd. When no route with that distinguisher is known, the global table is
// used (the VRF is not monitored); a known VPN table without a covering
// route gives no route.
func (r *RIB) LookupRD(rd uint64, a netip.Addr) (Route, bool) {
	a = a.Unmap()
	if !a.IsValid() {
		return Route{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	t := r.tables[rd]
	if t == nil {
		rd, t = 0, r.tables[0]
	}
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		for _, l := range t.v4.lens {
			k := uint32(0)
			if l > 0 {
				k = v &^ (1<<(32-l) - 1)
			}
			if ps := t.v4.byLen[l][k]; len(ps) > 0 {
				return r.route(rd, netip.PrefixFrom(a, l).Masked(), ps), true
			}
		}
		return Route{}, false
	}
	for _, l := range t.v6.lens {
		if ps := t.v6.byLen[l][key6(a, l)]; len(ps) > 0 {
			return r.route(rd, netip.PrefixFrom(a, l).Masked(), ps), true
		}
	}
	return Route{}, false
}

func (r *RIB) route(rd uint64, p netip.Prefix, ps []path) Route {
	b := r.best(ps)
	return Route{Prefix: p, Attrs: b.attrs.Attrs, LargeText: b.attrs.large, Peer: r.peers[b.peer].key, RD: rd}
}

// Stats is the size of the RIB.
type Stats struct {
	PrefixesV4 int `json:"prefixes_v4"`
	PrefixesV6 int `json:"prefixes_v6"`
	Routes     int `json:"routes"` // paths: prefixes × peers
	// VPNPrefixes are the prefixes of the VPN tables (all distinguishers),
	// not counted in PrefixesV4 / PrefixesV6.
	VPNPrefixes int `json:"vpn_prefixes"`
	VRFs        int `json:"vrfs"` // route distinguishers with routes
	AttrSets    int `json:"attribute_sets"`
	Peers       int `json:"peers"`
	// Bytes is an estimate of the memory held by the tables.
	Bytes int64 `json:"bytes"`
}

// Stats returns the current size.
func (r *RIB) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g := r.tables[0]
	s := Stats{PrefixesV4: g.v4.n, PrefixesV6: g.v6.n, AttrSets: len(r.attrs)}
	n4, n6 := 0, 0
	for rd, t := range r.tables {
		n4, n6 = n4+t.v4.n, n6+t.v6.n
		if rd != 0 {
			s.VRFs++
			s.VPNPrefixes += t.v4.n + t.v6.n
		}
	}
	for _, p := range r.peers {
		if p != nil {
			s.Peers++
			s.Routes += p.routes
		}
	}
	// map entry ≈ key + slice header + bucket overhead; path = 16 bytes.
	s.Bytes = int64(n4*(4+24+24)+n6*(16+24+24)+s.Routes*16) + int64(r.bytes)
	return s
}

// PeerInfo describes a peer for the status API.
type PeerInfo struct {
	Router        netip.Addr `json:"router"`
	Address       netip.Addr `json:"address"`
	AS            uint32     `json:"as"`
	Distinguisher uint64     `json:"distinguisher,omitempty"`
	// RD is the distinguisher as text ("65000:1") for RD instance and VRF
	// Loc-RIB peers.
	RD         string    `json:"rd,omitempty"`
	PostPolicy bool      `json:"post_policy"`
	Routes     int       `json:"routes"`
	Since      time.Time `json:"since"`
	LastUpdate time.Time `json:"last_update"`
}

// Peers lists the peers, by router then peer address.
func (r *RIB) Peers() []PeerInfo {
	r.mu.RLock()
	out := make([]PeerInfo, 0, len(r.ids))
	for _, p := range r.peers {
		if p == nil {
			continue
		}
		pi := PeerInfo{Router: p.key.Router, Address: p.key.Address, AS: p.key.AS, Distinguisher: p.key.Distinguisher,
			PostPolicy: p.key.Post, Routes: p.routes, Since: p.since, LastUpdate: p.last}
		if pi.Distinguisher != 0 {
			pi.RD = FormatRD(pi.Distinguisher)
		}
		out = append(out, pi)
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
