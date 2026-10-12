package enrich

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

type fakeRoutes map[netip.Addr]RouteInfo

func (r fakeRoutes) LookupRoute(a netip.Addr) (RouteInfo, bool) {
	v, ok := r[a.Unmap()]
	return v, ok
}

type staticIf map[uint32][3]any

func (s staticIf) Lookup(_ netip.Addr, idx uint32) (string, string, uint64, bool) {
	v, ok := s[idx]
	if !ok {
		return "", "", 0, false
	}
	return v[0].(string), v[1].(string), v[2].(uint64), true
}

func TestRoutingProvider(t *testing.T) {
	nh := netip.MustParseAddr("192.0.2.254")
	routes := fakeRoutes{
		google: {OriginAS: 15169, ASPath: []uint32{64500, 15169}, Communities: []uint32{65000<<16 | 100},
			LargeCommunities: []string{"65000:1:2"}, NextHop: nh},
		vmAddr: {OriginAS: 64999},
	}
	e, _ := newTestEnricher(t, Config{Routing: routes, ASProviders: []string{ASRouting, ASFlow, ASGeoIP}})
	f := &flow.Flow{ExporterAddress: edge, SrcAddr: vmAddr, DstAddr: google, SrcAS: 1, DstAS: 2, Bytes: 1}
	if err := e.Put(context.Background(), []*flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	if f.SrcAS != 64999 || f.DstAS != 15169 {
		t.Fatalf("AS %d → %d", f.SrcAS, f.DstAS)
	}
	if !slices.Equal(f.DstASPath, []uint32{64500, 15169}) || !slices.Equal(f.DstCommunities, []uint32{65000<<16 | 100}) ||
		!slices.Equal(f.DstLargeCommunities, []string{"65000:1:2"}) || f.NextHop != nh {
		t.Fatalf("route columns %v %v %v %v", f.DstASPath, f.DstCommunities, f.DstLargeCommunities, f.NextHop)
	}

	// The flow's AS first at run time; the BGP columns are still filled.
	if err := e.SetASProviders([]string{ASFlow, ASRouting}); err != nil {
		t.Fatal(err)
	}
	g := &flow.Flow{ExporterAddress: edge, SrcAddr: vmAddr, DstAddr: google, DstAS: 2, NextHop: netip.MustParseAddr("192.0.2.9"), Bytes: 1}
	_ = e.Put(context.Background(), []*flow.Flow{g})
	if g.SrcAS != 64999 || g.DstAS != 2 || len(g.DstASPath) != 2 || g.NextHop != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("flow first: %d %d %v %v", g.SrcAS, g.DstAS, g.DstASPath, g.NextHop)
	}
	if err := e.SetASProviders([]string{"bgp"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
	_ = e.SetASProviders(nil)
	if _, err := New(&capture{}, Config{ASProviders: []string{"nope"}}); err == nil {
		t.Fatal("unknown provider accepted by New")
	}
}

func TestIfNameChain(t *testing.T) {
	if IfNameChain(nil, nil) != nil {
		t.Fatal("empty chain is not nil")
	}
	col := staticIf{1: {"ge-0/0/1", "", uint64(0)}}
	snmp := staticIf{1: {"Gi1", "uplink", uint64(1e9)}, 2: {"Gi2", "", uint64(1e10)}}
	c := IfNameChain(col, nil, snmp)
	if n, d, s, ok := c.Lookup(edge, 1); !ok || n != "ge-0/0/1" || d != "uplink" || s != 1e9 {
		t.Fatalf("1: %q %q %d %v", n, d, s, ok)
	}
	if n, _, s, ok := c.Lookup(edge, 2); !ok || n != "Gi2" || s != 1e10 {
		t.Fatalf("2: %q %d %v", n, s, ok)
	}
	if _, _, _, ok := c.Lookup(edge, 3); ok {
		t.Fatal("3 found")
	}
}
