package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixtureServer serves testdata/*.json (real Ledger output) with
// limit/offset paging and xc-token auth.
func fixtureServer(t *testing.T, token string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("xc-token") != token {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"UNAUTHORIZED","message":"Authentication required"}`))
			return
		}
		p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
		b, err := os.ReadFile("testdata/" + strings.ReplaceAll(p, "/", "_") + ".json")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"NOT_FOUND","message":"no route"}`))
			return
		}
		var pg struct {
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(b, &pg); err != nil {
			t.Errorf("fixture %s: %v", p, err)
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit <= 0 {
			limit = 50
		}
		res := pg.Results[min(offset, len(pg.Results)):min(offset+limit, len(pg.Results))]
		var next *string
		if offset+limit < len(pg.Results) {
			n := fmt.Sprintf("/api/v1/%s/?limit=%d&offset=%d", p, limit, offset+limit)
			next = &n
		}
		json.NewEncoder(w).Encode(map[string]any{"count": len(pg.Results), "next": next, "previous": nil, "results": res})
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func fetchFixture(t *testing.T, pageSize int) *Snapshot {
	t.Helper()
	srv, _ := fixtureServer(t, "tok")
	c, err := NewClient(Config{URL: srv.URL, Token: "tok", PageSize: pageSize})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFetchSnapshot(t *testing.T) {
	for _, ps := range []int{1, 2, 1000} {
		t.Run(fmt.Sprint("page", ps), func(t *testing.T) { checkSnapshot(t, fetchFixture(t, ps)) })
	}
}

func checkSnapshot(t *testing.T, s *Snapshot) {
	st := s.Stats()
	if st.Devices != 2 || st.Interfaces != 6 || st.Prefixes != 3 || st.Circuits != 1 || st.VMs != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// Exporter by loopback (primary IPv4), by an interface address and by IPv6 (IPAM address only).
	for _, a := range []string{"192.0.2.1", "10.1.0.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		d, ok := s.Exporter(netip.MustParseAddr(a))
		if !ok {
			t.Fatalf("exporter %s not found", a)
		}
		want := Device{ID: 1, Kind: KindDevice, Name: "edge-01", Ref: "inventory-db:dcim.device:1", Site: "DC1", Region: "Europe",
			Role: "Edge router", Tenant: "NetOps", Platform: "JunOS", Manufacturer: "Juniper", Model: "MX204"}
		if d.ID != want.ID || d.Ref != want.Ref || d.Name != want.Name || d.Site != want.Site || d.Region != want.Region ||
			d.Role != want.Role || d.Tenant != want.Tenant || d.Platform != want.Platform || d.Manufacturer != want.Manufacturer ||
			d.Model != want.Model || len(d.Tags) != 1 || d.Tags[0] != "core" {
			t.Fatalf("exporter %s = %+v", a, d)
		}
		if d.PrimaryIP4 != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("primary ip4 = %v", d.PrimaryIP4)
		}
	}
	if _, ok := s.Exporter(netip.MustParseAddr("10.1.0.50")); !ok {
		t.Fatal("VM address should be an exporter candidate too")
	}
	if _, ok := s.Exporter(netip.MustParseAddr("203.0.113.1")); ok {
		t.Fatal("unexpected exporter")
	}

	// Interfaces.
	xe0, ok := s.Interface(1, 501)
	if !ok {
		t.Fatal("ifIndex 501 not found")
	}
	if xe0.Name != "xe-0/0/0" || xe0.Description != "Transit: Telia" || xe0.Speed != 10_000_000_000 ||
		xe0.Boundary != "external" || xe0.Provider != "Telia" || xe0.Circuit != "TEL-123" || xe0.Connectivity != "transit" ||
		xe0.CommitRate != 1_000_000_000 {
		t.Fatalf("xe-0/0/0 = %+v", xe0)
	}
	xe1, _ := s.InterfaceByName(1, "XE-0/0/1")
	if xe1 == nil || xe1.Boundary != "internal" || xe1.PeerDevice != "core-01" || xe1.PeerInterface != "xe-0/0/0" || xe1.IfIndex != 502 {
		t.Fatalf("xe-0/0/1 = %+v", xe1)
	}
	ae0, _ := s.Interface(1, 600)
	if ae0 == nil || ae0.Boundary != "internal" || ae0.Speed != 10_000_000_000 || ae0.Type != "lag" {
		t.Fatalf("ae0 = %+v", ae0)
	}
	xe2, _ := s.Interface(1, 503)
	if xe2 == nil || xe2.Boundary != "" {
		t.Fatalf("xe-0/0/2 = %+v", xe2)
	}
	if _, ok := s.Interface(1, 9999); ok {
		t.Fatal("unexpected ifIndex")
	}
	if n := len(s.Interfaces(1)); n != 5 {
		t.Fatalf("edge-01 has %d interfaces", n)
	}

	// Prefixes.
	p, ok := s.Prefix(netip.MustParseAddr("10.1.0.77"))
	if !ok || p.Prefix.String() != "10.1.0.0/24" || p.Role != "Servers" || p.Site != "DC1" || p.Tenant != "NetOps" ||
		p.VRF != "prod" || p.VLAN != 100 || p.Name != "servers" {
		t.Fatalf("prefix = %+v", p)
	}
	p, ok = s.Prefix(netip.MustParseAddr("10.200.0.1"))
	if !ok || p.Prefix.String() != "10.0.0.0/8" || p.Name != "RFC1918" {
		t.Fatalf("prefix = %+v", p)
	}
	p, ok = s.Prefix(netip.MustParseAddr("2001:db8:1::5"))
	if !ok || p.Prefix.String() != "2001:db8::/32" {
		t.Fatalf("prefix v6 = %+v", p)
	}
	if _, ok := s.Prefix(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("unexpected prefix")
	}

	// Addresses.
	a, ok := s.Address(netip.MustParseAddr("10.1.0.50"))
	if !ok || a.Ref != "inventory-db:virtualization.virtualmachine:1" || a.Host != "app.example.net" || a.Kind != KindVM {
		t.Fatalf("address = %+v", a)
	}
	a, ok = s.Address(netip.MustParseAddr("10.1.0.1"))
	if !ok || a.Ref != "inventory-db:dcim.device:1" || a.Host != "edge-01" {
		t.Fatalf("address = %+v", a)
	}
}

func TestClientErrors(t *testing.T) {
	srv, _ := fixtureServer(t, "tok")
	c, _ := NewClient(Config{URL: srv.URL + "/api/v1/", Token: "bad"})
	err := c.Ping(context.Background())
	he, ok := err.(*HTTPError)
	if !ok || he.Status != 401 || he.Message != "Authentication required" {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if _, err := NewClient(Config{URL: "ftp://x"}); err == nil {
		t.Fatal("want URL error")
	}
	c, _ = NewClient(Config{URL: srv.URL, Token: "tok"})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSyncer(t *testing.T) {
	srv, _ := fixtureServer(t, "tok")
	c, _ := NewClient(Config{URL: srv.URL, Token: "tok"})
	swapped := 0
	s := NewSyncer(c, SyncerConfig{Interval: time.Hour, OnSwap: func(*Snapshot) { swapped++ }})
	if s.Snapshot() == nil || s.Snapshot().Stats().Devices != 0 {
		t.Fatal("initial snapshot should be empty")
	}
	st, err := s.Sync(context.Background())
	if err != nil || !st.OK || st.Devices != 2 || swapped != 1 {
		t.Fatalf("sync = %+v, %v", st, err)
	}
	// A failing sync keeps the old snapshot.
	bad, _ := NewClient(Config{URL: srv.URL, Token: "nope"})
	s.fetcher = bad
	st, err = s.Sync(context.Background())
	if err == nil || st.OK || st.Error == "" || s.Snapshot().Stats().Devices != 2 || s.LastStats().OK {
		t.Fatalf("failed sync = %+v, %v", st, err)
	}

	// Run + Invalidate.
	s.fetcher = c
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !s.LastStats().OK && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	s.Invalidate()
	s.Invalidate()
	cancel()
	<-done
	if !s.LastStats().OK {
		t.Fatal("Run did not sync")
	}
}

func TestConnectivity(t *testing.T) {
	for _, c := range [][3]string{
		{"ip-transit", "IP Transit", "transit"},
		{"transit", "", "transit"},
		{"peering", "", "peering"},
		{"private-peering", "", "pni"},
		{"pni", "", "pni"},
		{"ix", "", "ix"},
		{"internet-exchange", "", "ix"},
		{"customer", "", "customer"},
		{"mpls-l3vpn", "", "mpls-l3vpn"},
		{"", "Dark Fiber", "dark-fiber"},
		{"", "", ""},
	} {
		if got := Connectivity(c[0], c[1]); got != c[2] {
			t.Errorf("Connectivity(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func i64(v int64) *int64 { return &v }

func TestBuildLAGAndCables(t *testing.T) {
	dev := &ref{ID: 1, Name: "r1"}
	r := &raw{
		devices:      []rawDevice{{ID: 1, Name: "r1"}, {ID: 2, Name: "r2"}},
		circuits:     []rawCircuit{{ID: 7, CID: "IX-1", Provider: &ref{ID: 3, Name: "DE-CIX"}, Type: &ref{ID: 4, Name: "IX", Slug: "ix"}}},
		circuitTypes: []rawCircuitType{{ID: 4, Name: "Internet exchange", Slug: "ix"}},
		providers:    []rawProvider{{ID: 3, Name: "DE-CIX"}},
		interfaces: []rawInterface{
			{ID: 10, Device: dev, Name: "bond0", Type: choice{Value: "lag"}, CustomFields: map[string]any{"snmp_index": "100"}},
			{ID: 11, Device: dev, Name: "eth0", LAG: &ref{ID: 10}, Speed: i64(1_000_000)},
			{ID: 12, Device: dev, Name: "eth1", LAG: &ref{ID: 10}, Speed: i64(1_000_000)},
			// No link_peers (older server): classified from cables.
			{ID: 13, Device: dev, Name: "eth2"},
			{ID: 20, Device: &ref{ID: 2, Name: "r2"}, Name: "eth9"},
		},
		cables: []rawCable{
			{ID: 1, ATerminations: []rawTermination{{ObjectType: "dcim.interface", ObjectID: 11}},
				BTerminations: []rawTermination{{ObjectType: "circuits.circuittermination", ObjectID: 1, Object: &peer{ID: 1, Circuit: &ref{ID: 7}}}}},
			{ID: 2, ATerminations: []rawTermination{{ObjectType: "dcim.interface", ObjectID: 20}},
				BTerminations: []rawTermination{{ObjectType: "dcim.interface", ObjectID: 13}}},
			{ID: 3, Status: choice{Value: "planned"}, ATerminations: []rawTermination{{ObjectType: "dcim.interface", ObjectID: 12}},
				BTerminations: []rawTermination{{ObjectType: "dcim.interface", ObjectID: 20}}},
		},
	}
	s := build(r, "snmp_index", time.Now())
	bond, ok := s.Interface(1, 100)
	if !ok || bond.Boundary != "external" || bond.Provider != "DE-CIX" || bond.Circuit != "IX-1" || bond.Connectivity != "ix" || bond.Speed != 2_000_000_000 {
		t.Fatalf("bond0 = %+v", bond)
	}
	eth2, _ := s.InterfaceByName(1, "eth2")
	if eth2.Boundary != "internal" || eth2.PeerDevice != "r2" || eth2.PeerInterface != "eth9" {
		t.Fatalf("eth2 = %+v", eth2)
	}
	eth1, _ := s.InterfaceByName(1, "eth1")
	if eth1.Boundary != "" {
		t.Fatalf("planned cable should not count: %+v", eth1)
	}
}

func TestTrieOverlapsAndVRF(t *testing.T) {
	r := &raw{
		vrfs: []rawVRF{{ID: 1, Name: "red"}},
		prefixes: []rawPrefix{
			{ID: 1, Prefix: "10.0.0.0/16", VRF: &ref{ID: 1}, Description: "red"},
			{ID: 2, Prefix: "10.0.0.0/16", Description: "global"},
			{ID: 3, Prefix: "10.0.1.0/24", Tags: []tag{{Name: "DMZ", Slug: "dmz"}}},
			{ID: 4, Prefix: "0.0.0.0/0", Description: "default"},
			{ID: 5, Prefix: "bad"},
			{ID: 6, Prefix: "::/0", Description: "v6 default"},
		},
	}
	s := build(r, "snmp_index", time.Now())
	cases := map[string]string{"10.0.0.1": "global", "10.0.1.200": "DMZ", "1.1.1.1": "default", "2a00::1": "v6 default"}
	for a, want := range cases {
		p, ok := s.Prefix(netip.MustParseAddr(a))
		if !ok || p.Name != want {
			t.Errorf("%s -> %+v, want %s", a, p, want)
		}
	}
}

func TestInterfaceVRF(t *testing.T) {
	five, six := 5, 6
	r := &raw{
		devices: []rawDevice{{ID: 1, Name: "pe1"}},
		vrfs:    []rawVRF{{ID: 1, Name: "red", RD: "65000:1"}, {ID: 2, Name: "blue", RD: "65000:2"}},
		interfaces: []rawInterface{
			{ID: 5, Device: &ref{ID: 1}, Name: "ge-0/0/1"},
			{ID: 6, Device: &ref{ID: 1}, Name: "ge-0/0/2", VRF: &ref{ID: 2}},
			{ID: 7, Device: &ref{ID: 1}, Name: "ge-0/0/3"},
		},
		addresses: []rawIPAddress{
			{ID: 1, Address: "10.0.0.1/30", VRF: &ref{ID: 1}, AssignedObjectType: "dcim.interface", AssignedObjectID: &five},
			{ID: 2, Address: "10.0.0.5/30", VRF: &ref{ID: 1}, AssignedObjectType: "dcim.interface", AssignedObjectID: &six},
		},
	}
	s := build(r, "snmp_index", time.Now())
	for name, want := range map[string]string{"ge-0/0/1": "red 65000:1", "ge-0/0/2": "blue 65000:2", "ge-0/0/3": " "} {
		it, ok := s.InterfaceByName(1, name)
		if !ok || it.VRF+" "+it.RD != want {
			t.Errorf("%s = %+v, want %s", name, it, want)
		}
	}
}

// Integration test against a running Ledger seeded like testdata:
// FLOW_TEST_INVENTORY_URL=http://localhost:8091 FLOW_TEST_INVENTORY_TOKEN=nc_...
func TestIntegration(t *testing.T) {
	u, tok := os.Getenv("FLOW_TEST_INVENTORY_URL"), os.Getenv("FLOW_TEST_INVENTORY_TOKEN")
	if u == "" || tok == "" {
		t.Skip("FLOW_TEST_INVENTORY_URL / FLOW_TEST_INVENTORY_TOKEN not set")
	}
	c, err := NewClient(Config{URL: u, Token: tok, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkSnapshot(t, s)
}

func BenchmarkLookups(b *testing.B) {
	r := &raw{}
	for i := 0; i < 20000; i++ {
		r.prefixes = append(r.prefixes, rawPrefix{ID: i + 1, Prefix: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)})
	}
	r.prefixes = append(r.prefixes, rawPrefix{ID: 99999, Prefix: "10.0.0.0/8"})
	s := build(r, "snmp_index", time.Now())
	a := netip.MustParseAddr("10.20.30.40")
	b.ResetTimer()
	for b.Loop() {
		if _, ok := s.Prefix(a); !ok {
			b.Fatal("miss")
		}
	}
}

func TestLoadDir(t *testing.T) {
	s, err := LoadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	checkSnapshot(t, s)
}
