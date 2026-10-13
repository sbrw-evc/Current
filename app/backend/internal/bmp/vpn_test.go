package bmp

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func mustRD(t *testing.T, s string) uint64 {
	t.Helper()
	rd, err := ParseRD(s)
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

func peerHdrRD(peerType, flags byte, rd uint64, addr netip.Addr, as uint32) []byte {
	b := peerHdr(peerType, flags, addr, as)
	binary.BigEndian.PutUint64(b[2:10], rd)
	return b
}

// vpnNLRI encodes one labeled VPN prefix (label 100, bottom of stack).
func vpnNLRI(rd uint64, p string, withdraw bool) []byte {
	pfx := netip.MustParsePrefix(p)
	label := []byte{0x00, 0x06, 0x41} // 100<<4 | BoS
	if withdraw {
		label = []byte{0x80, 0, 0}
	}
	b := []byte{byte(24 + 64 + pfx.Bits())}
	b = append(b, label...)
	b = binary.BigEndian.AppendUint64(b, rd)
	return append(b, pfx.Addr().AsSlice()[:(pfx.Bits()+7)/8]...)
}

func TestRDText(t *testing.T) {
	for _, s := range []string{"65000:100", "192.0.2.1:7", "4200000000:12", "0:0"} {
		rd, err := ParseRD(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := FormatRD(rd); got != s {
			t.Fatalf("%s → %x → %s", s, rd, got)
		}
	}
	for _, s := range []string{"", "65000", ":1", "x:1", "192.0.2.1:70000", "4200000000:70000", "2001:db8::1:5"} {
		if _, err := ParseRD(s); err == nil {
			t.Fatalf("%q parsed", s)
		}
	}
}

func TestVPNRoutes(t *testing.T) {
	s, rib := newTestServer(t)
	pe := netip.MustParseAddr("10.0.0.2")
	red, blue := mustRD(t, "65000:1"), mustRD(t, "65000:2")
	nh := make([]byte, 8) // RD 0 + IPv4 next hop
	nh = append(nh, 10, 0, 0, 2)
	mp := concat(binary.BigEndian.AppendUint16(nil, afiIPv4), []byte{safiVPN, byte(len(nh))}, nh, []byte{0},
		vpnNLRI(red, "10.1.0.0/16", false), vpnNLRI(blue, "10.1.0.0/24", false))
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64600), attr(0x80, attrMPReach, mp))
	global := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64500, 15169), attr(0x40, attrNextHop, []byte{10, 0, 0, 9}))
	st := feed(t, s,
		peerUp(peerHdr(peerGlobal, 0, pe, 65000), openMsg(65000, capAS4(65000)), openMsg(65000, capAS4(65000))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, pe, 65000), updateMsg(nil, attrs, nil))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, pe, 65000), updateMsg(nil, global, nlri("10.0.0.0/8")))),
	)
	a := netip.MustParseAddr("10.1.0.5")
	if r, ok := rib.LookupRD(red, a); !ok || r.Prefix.String() != "10.1.0.0/16" || r.NextHop != pe || r.OriginAS() != 64600 {
		t.Fatalf("red: %+v %v", r, ok)
	}
	if r, ok := rib.LookupRD(blue, a); !ok || r.Prefix.String() != "10.1.0.0/24" {
		t.Fatalf("blue: %+v %v", r, ok)
	}
	// The global table does not see VPN routes.
	if r, ok := rib.Lookup(a); !ok || r.Prefix.String() != "10.0.0.0/8" {
		t.Fatalf("global: %+v %v", r, ok)
	}
	// A known VRF without a covering route gives no route; an unknown one
	// falls back to the global table.
	if _, ok := rib.LookupRD(blue, netip.MustParseAddr("10.1.1.1")); ok {
		t.Fatal("blue route for 10.1.1.1")
	}
	if r, ok := rib.LookupRD(mustRD(t, "65000:99"), a); !ok || r.Prefix.String() != "10.0.0.0/8" {
		t.Fatalf("unknown RD: %+v %v", r, ok)
	}
	if ss := rib.Stats(); ss.VRFs != 2 || ss.VPNPrefixes != 2 || ss.PrefixesV4 != 1 || ss.Routes != 3 {
		t.Fatalf("stats %+v", ss)
	}

	// Withdraw the blue prefix: its table goes away.
	un := concat(binary.BigEndian.AppendUint16(nil, afiIPv4), []byte{safiVPN}, vpnNLRI(blue, "10.1.0.0/24", true))
	m := bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, pe, 65000), updateMsg(nil, attr(0x80, attrMPUnreach, un), nil)))
	if _, err := s.handle(st, MsgRouteMonitoring, m[commonHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	if ss := rib.Stats(); ss.VRFs != 1 || ss.VPNPrefixes != 1 {
		t.Fatalf("stats after withdraw %+v", ss)
	}
	feed(t, s, bmpMsg(MsgPeerDown, concat(peerHdr(peerGlobal, 0, pe, 65000), []byte{2, 0, 0})))
	if ss := rib.Stats(); ss.VRFs != 0 || ss.VPNPrefixes != 0 || ss.Routes != 0 || ss.AttrSets != 0 {
		t.Fatalf("stats after peer down %+v", ss)
	}
}

func TestVPNIPv6NextHop(t *testing.T) {
	s, rib := newTestServer(t)
	pe := netip.MustParseAddr("2001:db8::2")
	rd := mustRD(t, "192.0.2.1:5")
	nh := concat(make([]byte, 8), pe.AsSlice())
	mp := concat(binary.BigEndian.AppendUint16(nil, afiIPv6), []byte{safiVPN, byte(len(nh))}, nh, []byte{0},
		vpnNLRI(rd, "2001:db8:100::/48", false))
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64600), attr(0x80, attrMPReach, mp))
	feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, pe, 65000), updateMsg(nil, attrs, nil))))
	if r, ok := rib.LookupRD(rd, netip.MustParseAddr("2001:db8:100::1")); !ok || r.NextHop != pe {
		t.Fatalf("route %+v %v", r, ok)
	}
}

// Unicast routes of an RD instance peer or a VRF Loc-RIB go to the table of
// the peer distinguisher.
func TestRDPeerUnicast(t *testing.T) {
	s, rib := newTestServer(t)
	ce := netip.MustParseAddr("172.16.0.2")
	rd := mustRD(t, "65000:7")
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64700), attr(0x40, attrNextHop, []byte{172, 16, 0, 2}))
	feed(t, s,
		bmpMsg(MsgRouteMonitoring, concat(peerHdrRD(peerRD, 0, rd, ce, 64700), updateMsg(nil, attrs, nlri("192.168.0.0/16")))),
		bmpMsg(MsgRouteMonitoring, concat(peerHdrRD(peerLocRIB, 0, rd, netip.IPv4Unspecified(), 0), updateMsg(nil, attrs, nlri("192.168.1.0/24")))),
	)
	if _, ok := rib.Lookup(netip.MustParseAddr("192.168.1.1")); ok {
		t.Fatal("VRF route in the global table")
	}
	r, ok := rib.LookupRD(rd, netip.MustParseAddr("192.168.1.1"))
	if !ok || r.Prefix.String() != "192.168.1.0/24" || !r.Peer.Post || r.Peer.Distinguisher != rd {
		t.Fatalf("route %+v %v", r, ok)
	}
}

func TestAdjRIBOutSkipped(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("198.51.100.2")
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(65000), attr(0x40, attrNextHop, []byte{198, 51, 100, 1}))
	feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagO|flagL, peer, 64500), updateMsg(nil, attrs, nlri("203.0.113.0/24")))))
	if _, ok := rib.Lookup(netip.MustParseAddr("203.0.113.1")); ok {
		t.Fatal("Adj-RIB-Out route in the RIB")
	}
	if st := rib.Stats(); st.Peers != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func evpnPrefixRoute(rd uint64, p string) []byte {
	pfx := netip.MustParsePrefix(p)
	v := binary.BigEndian.AppendUint64(nil, rd)
	v = append(v, make([]byte, 10+4)...) // ESI, Ethernet tag
	v = append(v, byte(pfx.Bits()))
	v = append(v, pfx.Addr().AsSlice()...)
	v = append(v, make([]byte, len(pfx.Addr().AsSlice()))...) // gateway
	v = append(v, 0x00, 0x06, 0x41)                           // label
	return append([]byte{evpnIPPrefix, byte(len(v))}, v...)
}

func evpnMACIPRoute(rd uint64, ip string) []byte {
	v := binary.BigEndian.AppendUint64(nil, rd)
	v = append(v, make([]byte, 10+4)...)
	v = append(v, 48, 0x02, 0, 0, 0, 0, 1)
	if ip == "" {
		v = append(v, 0)
	} else {
		a := netip.MustParseAddr(ip)
		v = append(v, byte(a.BitLen()))
		v = append(v, a.AsSlice()...)
	}
	v = append(v, 0x00, 0x06, 0x41)
	return append([]byte{evpnMACIP, byte(len(v))}, v...)
}

func TestEVPNRoutes(t *testing.T) {
	s, rib := newTestServer(t)
	pe := netip.MustParseAddr("10.0.0.2")
	rd := mustRD(t, "10.0.0.2:5")
	// A type 3 (inclusive multicast) route is skipped.
	imet := append([]byte{3, 17}, make([]byte, 17)...)
	nl := concat(evpnPrefixRoute(rd, "172.16.0.0/16"), evpnPrefixRoute(rd, "2001:db8:5::/48"), evpnMACIPRoute(rd, "172.16.1.10"),
		evpnMACIPRoute(rd, ""), imet)
	mp := concat(binary.BigEndian.AppendUint16(nil, afiL2VPN), []byte{safiEVPN, 4, 10, 0, 0, 2, 0}, nl)
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(), attr(0x80, attrMPReach, mp))
	st := feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, pe, 65000), updateMsg(nil, attrs, nil))))
	if r, ok := rib.LookupRD(rd, netip.MustParseAddr("172.16.1.10")); !ok || r.Prefix.String() != "172.16.1.10/32" || r.NextHop != pe {
		t.Fatalf("host route %+v %v", r, ok)
	}
	if r, ok := rib.LookupRD(rd, netip.MustParseAddr("172.16.9.9")); !ok || r.Prefix.String() != "172.16.0.0/16" {
		t.Fatalf("prefix route %+v %v", r, ok)
	}
	if r, ok := rib.LookupRD(rd, netip.MustParseAddr("2001:db8:5::1")); !ok || r.Prefix.String() != "2001:db8:5::/48" {
		t.Fatalf("v6 prefix route %+v %v", r, ok)
	}
	if ss := rib.Stats(); ss.VPNPrefixes != 3 || ss.VRFs != 1 {
		t.Fatalf("stats %+v", ss)
	}
	un := concat(binary.BigEndian.AppendUint16(nil, afiL2VPN), []byte{safiEVPN}, evpnMACIPRoute(rd, "172.16.1.10"))
	m := bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, pe, 65000), updateMsg(nil, attr(0x80, attrMPUnreach, un), nil)))
	if _, err := s.handle(st, MsgRouteMonitoring, m[commonHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	if r, _ := rib.LookupRD(rd, netip.MustParseAddr("172.16.1.10")); r.Prefix.String() != "172.16.0.0/16" {
		t.Fatalf("after withdraw %v", r.Prefix)
	}
}

func TestLabeledUnicast(t *testing.T) {
	s, rib := newTestServer(t)
	peer := netip.MustParseAddr("10.0.0.3")
	lu := func(p string, withdraw bool) []byte {
		pfx := netip.MustParsePrefix(p)
		label := []byte{0x00, 0x10, 0x01} // 256, bottom of stack
		if withdraw {
			label = []byte{0x80, 0, 0}
		}
		b := append([]byte{byte(24 + pfx.Bits())}, label...)
		return append(b, pfx.Addr().AsSlice()[:(pfx.Bits()+7)/8]...)
	}
	// Two labels on the first route: the stack ends at the bottom-of-stack bit.
	two := concat([]byte{byte(48 + 32), 0x00, 0x10, 0x00, 0x00, 0x20, 0x01}, []byte{192, 0, 2, 1})
	mp := concat(binary.BigEndian.AppendUint16(nil, afiIPv4), []byte{safiLabeled, 4, 10, 0, 0, 3, 0}, two, lu("198.51.100.0/24", false))
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64510), attr(0x80, attrMPReach, mp))
	st := feed(t, s, bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64510), updateMsg(nil, attrs, nil))))
	if r, ok := rib.Lookup(netip.MustParseAddr("192.0.2.1")); !ok || r.Prefix.String() != "192.0.2.1/32" || r.NextHop != peer {
		t.Fatalf("loopback %+v %v", r, ok)
	}
	if r, ok := rib.Lookup(netip.MustParseAddr("198.51.100.7")); !ok || r.OriginAS() != 64510 {
		t.Fatalf("prefix %+v %v", r, ok)
	}
	un := concat(binary.BigEndian.AppendUint16(nil, afiIPv4), []byte{safiLabeled}, lu("198.51.100.0/24", true))
	m := bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64510), updateMsg(nil, attr(0x80, attrMPUnreach, un), nil)))
	if _, err := s.handle(st, MsgRouteMonitoring, m[commonHeaderLen:]); err != nil {
		t.Fatal(err)
	}
	if _, ok := rib.Lookup(netip.MustParseAddr("198.51.100.7")); ok {
		t.Fatal("route after withdraw")
	}
}
