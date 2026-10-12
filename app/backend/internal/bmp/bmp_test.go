package bmp

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ---- message builders (RFC 7854 / RFC 4271 wire format)

func bgpMsg(typ byte, body []byte) []byte {
	b := make([]byte, 16, bgpHeaderLen+len(body))
	for i := range b {
		b[i] = 0xff
	}
	b = binary.BigEndian.AppendUint16(b, uint16(bgpHeaderLen+len(body)))
	b = append(b, typ)
	return append(b, body...)
}

func bmpMsg(typ byte, body []byte) []byte {
	b := []byte{bmpVersion}
	b = binary.BigEndian.AppendUint32(b, uint32(commonHeaderLen+len(body)))
	b = append(b, typ)
	return append(b, body...)
}

func peerHdr(peerType, flags byte, addr netip.Addr, as uint32) []byte {
	b := []byte{peerType, flags}
	b = append(b, make([]byte, 8)...) // RD
	a16 := addr.As16()
	if addr.Is4() {
		a16 = [16]byte{}
		a4 := addr.As4()
		copy(a16[12:], a4[:])
	} else {
		b[1] |= flagV
	}
	b = append(b, a16[:]...)
	b = binary.BigEndian.AppendUint32(b, as)
	b = append(b, 10, 0, 0, 1)        // BGP ID
	b = append(b, make([]byte, 8)...) // timestamp
	return b
}

func attr(flags, code byte, v []byte) []byte {
	if len(v) > 255 {
		b := []byte{flags | 0x10, code}
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		return append(b, v...)
	}
	return append([]byte{flags, code, byte(len(v))}, v...)
}

func asPath4(as ...uint32) []byte {
	b := []byte{segSequence, byte(len(as))}
	for _, a := range as {
		b = binary.BigEndian.AppendUint32(b, a)
	}
	return attr(0x40, attrASPath, b)
}

func asPath2(as ...uint16) []byte {
	b := []byte{segSequence, byte(len(as))}
	for _, a := range as {
		b = binary.BigEndian.AppendUint16(b, a)
	}
	return attr(0x40, attrASPath, b)
}

func nlri(ps ...string) []byte {
	var b []byte
	for _, s := range ps {
		p := netip.MustParsePrefix(s)
		b = append(b, byte(p.Bits()))
		b = append(b, p.Addr().AsSlice()[:(p.Bits()+7)/8]...)
	}
	return b
}

func updateMsg(withdrawn, attrs, nl []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	b = append(b, withdrawn...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs)))
	b = append(b, attrs...)
	return bgpMsg(bgpUpdate, append(b, nl...))
}

func concat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

func openMsg(as uint16, caps ...[]byte) []byte {
	var cv []byte
	for _, c := range caps {
		cv = append(cv, c...)
	}
	param := append([]byte{2, byte(len(cv))}, cv...)
	b := []byte{4}
	b = binary.BigEndian.AppendUint16(b, as)
	b = append(b, 0, 90, 10, 0, 0, 1, byte(len(param)))
	return bgpMsg(bgpOpen, append(b, param...))
}

func capAS4(as uint32) []byte { return binary.BigEndian.AppendUint32([]byte{65, 4}, as) }

func capAddPath(afi uint16, safi, mode byte) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{69, 4}, afi), safi, mode)
}

func peerUp(peer []byte, sent, recv []byte) []byte {
	return bmpMsg(MsgPeerUp, concat(peer, make([]byte, 16), []byte{0, 179, 0xc3, 0x50}, sent, recv))
}

var router = netip.MustParseAddr("192.0.2.1")

func newTestServer(t *testing.T) (*Server, *RIB) {
	t.Helper()
	rib := NewRIB()
	return NewServer(Config{Listen: "127.0.0.1:0"}, rib), rib
}

func feed(t *testing.T, s *Server, msgs ...[]byte) *sessionState {
	t.Helper()
	st := &sessionState{router: router, caps: map[PeerKey]*sessionCaps{}}
	for _, m := range msgs {
		typ, l, err := parseCommonHeader(m)
		if err != nil || l != len(m) {
			t.Fatalf("bad test message: %v (%d/%d)", err, l, len(m))
		}
		if _, err := s.handle(st, typ, m[commonHeaderLen:]); err != nil {
			t.Fatalf("handle %s: %v", msgName(typ), err)
		}
	}
	return st
}

func TestRouteMonitoringIPv4(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("198.51.100.2")
	comm := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 65000<<16|100), 65000<<16|200)
	large := []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2}
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64500, 4200000001, 15169),
		attr(0x40, attrNextHop, []byte{198, 51, 100, 2}), attr(0xc0, attrCommunities, comm), attr(0xc0, attrLargeCommunities, large))
	feed(t, s,
		peerUp(peerHdr(peerGlobal, 0, peer, 64500), openMsg(65000, capAS4(65000)), openMsg(64500, capAS4(64500))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, attrs, nlri("8.8.8.0/24", "8.0.0.0/9")))),
	)
	r, ok := rib.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("no route for 8.8.8.8")
	}
	if r.Prefix.String() != "8.8.8.0/24" || !slices.Equal(r.ASPath, []uint32{64500, 4200000001, 15169}) || r.OriginAS() != 15169 {
		t.Fatalf("route = %+v", r)
	}
	if !slices.Equal(r.Communities, []uint32{65000<<16 | 100, 65000<<16 | 200}) || !slices.Equal(r.LargeText, []string{"65000:1:2"}) {
		t.Fatalf("communities = %v %v", r.Communities, r.LargeText)
	}
	if r.NextHop != peer || !r.Peer.Post {
		t.Fatalf("next hop %v post %v", r.NextHop, r.Peer.Post)
	}
	// Less specific.
	if r, ok := rib.Lookup(netip.MustParseAddr("8.100.0.1")); !ok || r.Prefix.String() != "8.0.0.0/9" {
		t.Fatalf("8.100.0.1 → %v %v", r.Prefix, ok)
	}
	// IPv4-mapped lookups work too.
	if _, ok := rib.Lookup(netip.MustParseAddr("::ffff:8.8.8.8")); !ok {
		t.Fatal("mapped lookup")
	}
	if _, ok := rib.Lookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Fatal("route for 9.9.9.9")
	}
	st := rib.Stats()
	if st.PrefixesV4 != 2 || st.Routes != 2 || st.AttrSets != 1 || st.Peers != 1 || st.Bytes <= 0 {
		t.Fatalf("stats %+v", st)
	}

	// Withdraw the /24: the /9 now covers 8.8.8.8.
	feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nlri("8.8.8.0/24"), nil, nil))))
	if r, ok := rib.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || r.Prefix.String() != "8.0.0.0/9" {
		t.Fatalf("after withdraw: %v %v", r.Prefix, ok)
	}
	// Peer down removes everything of that peer.
	feed(t, s, bmpMsg(MsgPeerDown, concat(peerHdr(peerGlobal, 0, peer, 64500), []byte{2, 0, 0})))
	if _, ok := rib.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("route after peer down")
	}
	if st := rib.Stats(); st.PrefixesV4 != 0 || st.Routes != 0 || st.AttrSets != 0 || st.Peers != 0 {
		t.Fatalf("stats after peer down %+v", st)
	}
}

func TestMPReachIPv6AndAddPath(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("2001:db8::2")
	nh := netip.MustParseAddr("2001:db8::2").As16()
	ll := netip.MustParseAddr("fe80::2").As16()
	// ADD-PATH negotiated for IPv6 unicast: NLRI carry 4-byte path ids.
	pfx := netip.MustParsePrefix("2a00:1450::/32")
	nl := append([]byte{0, 0, 0, 7, 32}, pfx.Addr().AsSlice()[:4]...)
	mp := concat(binary.BigEndian.AppendUint16(nil, afiIPv6), []byte{safiUnicast, 32}, nh[:], ll[:], []byte{0}, nl)
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64501, 15169), attr(0x80, attrMPReach, mp))
	st := feed(t, s,
		peerUp(peerHdr(peerGlobal, 0, peer, 64501),
			openMsg(65000, capAS4(65000), capAddPath(afiIPv6, safiUnicast, 1)),
			openMsg(64501, capAS4(64501), capAddPath(afiIPv6, safiUnicast, 2))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, peer, 64501), updateMsg(nil, attrs, nil))),
	)
	r, ok := rib.Lookup(netip.MustParseAddr("2a00:1450:4001::1"))
	if !ok || r.Prefix != pfx || r.OriginAS() != 15169 || r.NextHop != netip.MustParseAddr("2001:db8::2") || r.Peer.Post {
		t.Fatalf("route = %+v ok=%v", r, ok)
	}
	// MP_UNREACH withdraws it.
	un := concat(binary.BigEndian.AppendUint16(nil, afiIPv6), []byte{safiUnicast}, nl)
	m := bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, peer, 64501), updateMsg(nil, attr(0x80, attrMPUnreach, un), nil)))
	if _, err := s.handle(st, MsgRouteMonitoring, m[commonHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	if _, ok := rib.Lookup(netip.MustParseAddr("2a00:1450:4001::1")); ok {
		t.Fatal("route after MP_UNREACH")
	}
}

func TestTwoByteASPathWithAS4Path(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("198.51.100.3")
	as4 := []byte{segSequence, 2}
	as4 = binary.BigEndian.AppendUint32(as4, 4200000001)
	as4 = binary.BigEndian.AppendUint32(as4, 15169)
	attrs := concat(asPath2(64500, asTrans, asTrans), attr(0xc0, attrAS4Path, as4), attr(0x40, attrNextHop, []byte{198, 51, 100, 3}))
	feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagA, peer, 64500), updateMsg(nil, attrs, nlri("203.0.113.0/24")))))
	r, ok := rib.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || !slices.Equal(r.ASPath, []uint32{64500, 4200000001, 15169}) {
		t.Fatalf("route = %+v", r)
	}
}

func TestPostPolicyPreferred(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("198.51.100.4")
	pre := concat(asPath4(64500, 1, 2, 3), attr(0x40, attrNextHop, []byte{198, 51, 100, 4}))
	post := concat(asPath4(64500, 1, 2, 3, 3, 3), attr(0x40, attrNextHop, []byte{198, 51, 100, 4}))
	feed(t, s,
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, peer, 64500), updateMsg(nil, pre, nlri("192.0.2.0/24")))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, post, nlri("192.0.2.0/24")))),
	)
	r, _ := rib.Lookup(netip.MustParseAddr("192.0.2.1"))
	if !r.Peer.Post || len(r.ASPath) != 6 {
		t.Fatalf("post-policy route not preferred: %+v", r)
	}
	if st := rib.Stats(); st.Routes != 2 || st.PrefixesV4 != 1 || st.Peers != 2 {
		t.Fatalf("stats %+v", st)
	}
	// Policy "pre" ignores post-policy routes.
	if err := s.Apply(Settings{Policy: PolicyPre}); err != nil {
		t.Fatal(err)
	}
	feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, post, nlri("192.0.3.0/24")))))
	if _, ok := rib.Lookup(netip.MustParseAddr("192.0.3.1")); ok {
		t.Fatal("post-policy route accepted with policy pre")
	}
	if n := rib.RemoveRouter(router); n != 2 {
		t.Fatalf("removed %d peers", n)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := parseUpdate([]byte{0, 10, 0}, true, nil); err == nil {
		t.Fatal("short update accepted")
	}
	if _, err := parseNLRI([]byte{33, 1, 2, 3, 4, 5}, afiIPv4, false, nil); err == nil {
		t.Fatal("/33 accepted")
	}
	if _, err := parseNLRI([]byte{24, 1, 2}, afiIPv4, false, nil); err == nil {
		t.Fatal("truncated prefix accepted")
	}
	if _, err := (Settings{Policy: "x"}).Normalize(); err == nil {
		t.Fatal("bad policy accepted")
	}
	if _, err := (Settings{Routers: []string{"nope"}}).Normalize(); err == nil {
		t.Fatal("bad router accepted")
	}
}

func TestServerTCP(t *testing.T) {
	rib := NewRIB()
	m, err := NewMetrics(prometheus.NewRegistry(), rib)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{Listen: "127.0.0.1:0", Metrics: m}, rib)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("198.51.100.9")
	init := bmpMsg(MsgInitiation, concat([]byte{0, 2, 0, 3}, []byte("rt1")))
	attrs := concat(asPath4(64500, 13335), attr(0x40, attrNextHop, []byte{198, 51, 100, 9}))
	rm := bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, attrs, nlri("1.1.1.0/24"))))
	if _, err := c.Write(concat(init, rm)); err != nil {
		t.Fatal(err)
	}
	wait := func(cond func() bool) {
		t.Helper()
		for i := 0; i < 200 && !cond(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !cond() {
			t.Fatal("timeout")
		}
	}
	wait(func() bool { _, ok := rib.Lookup(netip.MustParseAddr("1.1.1.1")); return ok })
	wait(func() bool { ss := s.Sessions(); return len(ss) == 1 && ss[0].SysName == "rt1" })
	if ps := rib.Peers(); len(ps) != 1 || ps[0].Routes != 1 || ps[0].AS != 64500 {
		t.Fatalf("peers %+v", ps)
	}
	// Closing the session removes the routes of the router.
	_ = c.Close()
	wait(func() bool { _, ok := rib.Lookup(netip.MustParseAddr("1.1.1.1")); return !ok })

	// A router outside the allowed list is refused.
	if err := s.Apply(Settings{Routers: []string{"203.0.113.0/24"}}); err != nil {
		t.Fatal(err)
	}
	c2, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection not closed")
	}
	_ = c2.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkLookup(b *testing.B) {
	rib := NewRIB()
	k := PeerKey{Router: router, Address: router, AS: 1, Post: true}
	u := &update{hasAttrs: true, attrs: Attrs{ASPath: []uint32{1, 2, 3}}}
	for i := 0; i < 200000; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0})
		u.announced = append(u.announced, netip.PrefixFrom(a, 16+i%9).Masked())
	}
	rib.apply(k, u)
	addr := netip.MustParseAddr("10.20.30.40")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rib.Lookup(addr)
	}
}
