package enrich

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/inventory"
)

type fakeRoutes map[netip.Addr]RouteInfo

func (r fakeRoutes) LookupRoute(rd string, a netip.Addr) (RouteInfo, bool) {
	if rd != "" {
		return RouteInfo{}, false
	}
	v, ok := r[a.Unmap()]
	return v, ok
}

// vrfRoutes records the route distinguishers looked up.
type vrfRoutes struct{ rds []string }

func (r *vrfRoutes) LookupRoute(rd string, _ netip.Addr) (RouteInfo, bool) {
	r.rds = append(r.rds, rd)
	return RouteInfo{}, false
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

// Routes are looked up in the VRF of the input interface, which takes the
// VRF of its address in Inventory DB.
func TestRoutingVRF(t *testing.T) {
	dir := t.TempDir()
	ents, err := os.ReadDir("../inventory/testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range ents {
		b, err := os.ReadFile(filepath.Join("../inventory/testdata", de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if de.Name() == "ipam_ip-addresses.json" {
			// 10.1.0.1/24 on xe-0/0/2 goes into VRF prod (65000:1).
			b = bytes.Replace(b, []byte(`"address":"10.1.0.1/24","vrf":null`), []byte(`"address":"10.1.0.1/24","vrf":{"id":1,"name":"prod","rd":"65000:1"}`), 1)
		}
		if err := os.WriteFile(filepath.Join(dir, de.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := inventory.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := &staticInv{}
	inv.p.Store(snap)
	routes := &vrfRoutes{}
	e, _ := newTestEnricher(t, Config{Inventory: inv, Routing: routes})
	in := &flow.Flow{ExporterAddress: edge, InIf: 8, OutIf: 7, SrcAddr: vmAddr, DstAddr: google, Bytes: 1}
	out := &flow.Flow{ExporterAddress: edge, OutIf: 8, SrcAddr: vmAddr, DstAddr: google, Bytes: 1}
	glob := &flow.Flow{ExporterAddress: edge, InIf: 7, OutIf: 8, SrcAddr: vmAddr, DstAddr: google, Bytes: 1}
	if err := e.Put(context.Background(), []*flow.Flow{in, out, glob}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"65000:1", "65000:1", "65000:1", "65000:1", "", ""}; !slices.Equal(routes.rds, want) {
		t.Fatalf("lookups in %q, want %q", routes.rds, want)
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
