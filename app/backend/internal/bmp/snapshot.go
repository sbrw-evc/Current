package bmp

import (
	"encoding/binary"
	"net/netip"
)

// Snapshots describe the routes of one router as BMP messages that the
// regular decoder replays: the Peer Up messages received on the session
// (they carry the negotiated capabilities, ADD-PATH included), then one
// Route Monitoring message per peer, table and attribute set with
// MP_REACH_NLRI (unicast in the peer's table, VPN for other route
// distinguishers).

const (
	snapshotChunk  = 512 << 10 // bytes of BMP messages per replication record
	snapshotUpdate = 16 << 10  // NLRI bytes per synthesized UPDATE
)

type dumpKey struct {
	peer  uint32
	rd    uint64
	v6    bool
	attrs *attrSet
}

type dumpGroup struct {
	key      PeerKey
	rd       uint64
	v6       bool
	attrs    Attrs
	prefixes []netip.Prefix
}

func dumpTable[K comparable](r *RIB, t *lpm[K], rd uint64, v6 bool, router netip.Addr, out map[dumpKey]*dumpGroup, order *[]dumpKey,
	prefix func(K, int) netip.Prefix) {
	for l, m := range t.byLen {
		for k, ps := range m {
			for _, p := range ps {
				st := r.peers[p.peer]
				if st.key.Router != router {
					continue
				}
				dk := dumpKey{p.peer, rd, v6, p.attrs}
				g := out[dk]
				if g == nil {
					g = &dumpGroup{key: st.key, rd: rd, v6: v6, attrs: p.attrs.Attrs}
					out[dk] = g
					*order = append(*order, dk)
				}
				g.prefixes = append(g.prefixes, prefix(k, l))
			}
		}
	}
}

// dump returns the routes of a router grouped by peer, table and attributes.
func (r *RIB) dump(router netip.Addr) []*dumpGroup {
	r.mu.RLock()
	defer r.mu.RUnlock()
	groups := map[dumpKey]*dumpGroup{}
	var order []dumpKey
	for rd, t := range r.tables {
		dumpTable(r, t.v4, rd, false, router, groups, &order, func(k uint32, l int) netip.Prefix {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], k)
			return netip.PrefixFrom(netip.AddrFrom4(b), l)
		})
		dumpTable(r, t.v6, rd, true, router, groups, &order, func(k [16]byte, l int) netip.Prefix {
			return netip.PrefixFrom(netip.AddrFrom16(k), l)
		})
	}
	out := make([]*dumpGroup, len(order))
	for i, k := range order {
		out[i] = groups[k]
	}
	return out
}

// snapshot encodes the state of a session as chunks of BMP messages.
func (s *Server) snapshot(st *sessionState) [][]byte {
	var chunks [][]byte
	var cur []byte
	add := func(m []byte) {
		if len(cur)+len(m) > snapshotChunk && len(cur) > 0 {
			chunks = append(chunks, cur)
			cur = nil
		}
		cur = append(cur, m...)
	}
	if st.init != nil {
		add(st.init)
	}
	for _, m := range st.peerUps {
		add(m)
	}
	for _, g := range s.rib.dump(st.router) {
		base := g.key
		base.Post = false
		for _, m := range encodeRoutes(g, st.caps[base]) {
			add(m)
		}
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// encodeRoutes returns Route Monitoring messages announcing a group.
func encodeRoutes(g *dumpGroup, caps *sessionCaps) [][]byte {
	k := g.key
	afi := uint16(afiIPv4)
	if g.v6 {
		afi = afiIPv6
	}
	safi := uint8(safiUnicast)
	if g.rd != k.Distinguisher {
		safi = safiVPN
	}
	addPath := caps.hasAddPath(afi, safi)

	// Per-peer header: an RD instance peer when the peer has a
	// distinguisher (its unicast routes go to that table, as for a VRF
	// Loc-RIB), post-policy flag as received, 4-byte AS_PATH.
	hdr := make([]byte, 0, perPeerHeaderLen)
	typ := byte(peerGlobal)
	if k.Distinguisher != 0 {
		typ = peerRD
	}
	flags := byte(0)
	if k.Post {
		flags |= flagL
	}
	a16 := k.Address.As16()
	if k.Address.Is4() {
		a16 = [16]byte{}
		a4 := k.Address.As4()
		copy(a16[12:], a4[:])
	} else {
		flags |= flagV
	}
	hdr = append(hdr, typ, flags)
	hdr = binary.BigEndian.AppendUint64(hdr, k.Distinguisher)
	hdr = append(hdr, a16[:]...)
	hdr = binary.BigEndian.AppendUint32(hdr, k.AS)
	hdr = append(hdr, make([]byte, 12)...) // BGP ID, timestamp

	// Path attributes other than MP_REACH.
	var attrs []byte
	attrs = appendAttr(attrs, 0x40, attrOrigin, []byte{0})
	var path []byte
	for rest := g.attrs.ASPath; len(rest) > 0; {
		n := min(len(rest), 255)
		path = append(path, segSequence, byte(n))
		for _, as := range rest[:n] {
			path = binary.BigEndian.AppendUint32(path, as)
		}
		rest = rest[n:]
	}
	attrs = appendAttr(attrs, 0x40, attrASPath, path)
	if len(g.attrs.Communities) > 0 {
		var v []byte
		for _, c := range g.attrs.Communities {
			v = binary.BigEndian.AppendUint32(v, c)
		}
		attrs = appendAttr(attrs, 0xc0, attrCommunities, v)
	}
	if len(g.attrs.LargeCommunities) > 0 {
		var v []byte
		for _, c := range g.attrs.LargeCommunities {
			v = binary.BigEndian.AppendUint32(v, c.Global)
			v = binary.BigEndian.AppendUint32(v, c.Local1)
			v = binary.BigEndian.AppendUint32(v, c.Local2)
		}
		attrs = appendAttr(attrs, 0xc0, attrLargeCommunities, v)
	}
	var nh []byte
	if safi == safiVPN {
		nh = make([]byte, 8) // RD 0
	}
	if g.attrs.NextHop.IsValid() {
		nh = append(nh, g.attrs.NextHop.AsSlice()...)
	}

	var out [][]byte
	emit := func(nlri []byte) {
		mp := binary.BigEndian.AppendUint16(nil, afi)
		mp = append(mp, safi, byte(len(nh)))
		mp = append(mp, nh...)
		mp = append(mp, 0)
		mp = append(mp, nlri...)
		pa := appendAttr(append([]byte(nil), attrs...), 0x80, attrMPReach, mp)
		body := make([]byte, 0, 4+len(pa))
		body = append(body, 0, 0) // no withdrawn routes
		body = binary.BigEndian.AppendUint16(body, uint16(len(pa)))
		body = append(body, pa...)
		msg := make([]byte, 16, bgpHeaderLen+len(body))
		for i := range msg {
			msg[i] = 0xff
		}
		msg = binary.BigEndian.AppendUint16(msg, uint16(bgpHeaderLen+len(body)))
		msg = append(msg, bgpUpdate)
		msg = append(msg, body...)
		bm := []byte{bmpVersion}
		bm = binary.BigEndian.AppendUint32(bm, uint32(commonHeaderLen+len(hdr)+len(msg)))
		bm = append(bm, MsgRouteMonitoring)
		bm = append(bm, hdr...)
		out = append(out, append(bm, msg...))
	}
	var nlri []byte
	for _, p := range g.prefixes {
		if addPath {
			nlri = append(nlri, 0, 0, 0, 0)
		}
		bits := p.Bits()
		addr := p.Addr().AsSlice()[:(bits+7)/8]
		if safi == safiVPN {
			nlri = append(nlri, byte(24+64+bits), 0x80, 0, 0)
			nlri = binary.BigEndian.AppendUint64(nlri, g.rd)
		} else {
			nlri = append(nlri, byte(bits))
		}
		nlri = append(nlri, addr...)
		if len(nlri) >= snapshotUpdate {
			emit(nlri)
			nlri = nlri[:0:0]
		}
	}
	if len(nlri) > 0 {
		emit(nlri)
	}
	return out
}

func appendAttr(b []byte, flags, code byte, v []byte) []byte {
	if len(v) > 255 {
		b = append(b, flags|0x10, code)
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	} else {
		b = append(b, flags, code, byte(len(v)))
	}
	return append(b, v...)
}
