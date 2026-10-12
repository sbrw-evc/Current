package enrich

import (
	"context"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/sbrw-evc/network/app/backend/internal/classifier"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/geoip"
	"github.com/sbrw-evc/network/app/backend/internal/geoip/geoiptest"
	"github.com/sbrw-evc/network/app/backend/internal/inventory"
)

type staticInv struct {
	p atomic.Pointer[inventory.Snapshot]
}

func (s *staticInv) Current() *inventory.Snapshot { return s.p.Load() }

func loadInv(t testing.TB) *staticInv {
	t.Helper()
	snap, err := inventory.LoadDir("../inventory/testdata")
	if err != nil {
		t.Fatal(err)
	}
	s := &staticInv{}
	s.p.Store(snap)
	return s
}

type ifNames map[uint32][3]string

func (m ifNames) Lookup(_ netip.Addr, idx uint32) (string, string, uint64, bool) {
	v, ok := m[idx]
	if !ok {
		return "", "", 0, false
	}
	return v[0], v[1], 1_000_000_000, true
}

type fakeGeo map[netip.Addr]geoip.Info

func (g fakeGeo) Lookup(a netip.Addr) geoip.Info { return g[a] }

type capture struct{ got []*flow.Flow }

func (c *capture) Put(_ context.Context, f []*flow.Flow) error {
	c.got = append(c.got, f...)
	return nil
}

var (
	edge   = netip.MustParseAddr("192.0.2.1")
	other  = netip.MustParseAddr("198.51.100.7")
	vmAddr = netip.MustParseAddr("10.1.0.50")
	google = netip.MustParseAddr("8.8.8.8")
)

func newTestEnricher(t testing.TB, cfg Config) (*Enricher, *capture) {
	t.Helper()
	c := &capture{}
	if cfg.Inventory == nil {
		cfg.Inventory = loadInv(t)
	}
	if cfg.GeoIP == nil {
		cfg.GeoIP = fakeGeo{google: {Country: "US", City: "Mountain View", ASN: 15169, ASName: "GOOGLE"}}
	}
	if cfg.IfNames == nil {
		// 7 is not in Inventory DB (no snmp_index), 8 only matches by name.
		cfg.IfNames = ifNames{7: {"et-0/0/7", "collector descr"}, 8: {"XE-0/0/2", "via name"}, 501: {"xe-0/0/0", "from collector"}}
	}
	e, err := New(c, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, c
}

func TestEnrich(t *testing.T) {
	reg := prometheus.NewRegistry()
	e, c := newTestEnricher(t, Config{Metrics: reg})
	f := &flow.Flow{
		ExporterAddress: edge, InIf: 501, OutIf: 502, SrcAddr: google, DstAddr: vmAddr, SrcAS: 0, DstAS: 64512,
		Proto: 6, SrcPort: 443, DstPort: 51000, Bytes: 1000, SamplingRate: 100,
	}
	if err := e.Put(context.Background(), []*flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	if len(c.got) != 1 {
		t.Fatal("not forwarded")
	}
	if f.ExporterName != "edge-01" || f.ExporterRef != "inventory-db:dcim.device:1" || f.ExporterSite != "DC1" ||
		f.ExporterRegion != "Europe" || f.ExporterRole != "Edge router" || f.ExporterTenant != "NetOps" {
		t.Fatalf("exporter = %+v", f)
	}
	if f.InIfName != "xe-0/0/0" || f.InIfDescription != "Transit: Telia" || f.InIfSpeed != 10e9 || f.InIfBoundary != "external" ||
		f.InIfConnectivity != "transit" || f.InIfProvider != "Telia" || f.InIfCircuit != "TEL-123" {
		t.Fatalf("in if = %+v", f)
	}
	if f.OutIfName != "xe-0/0/1" || f.OutIfBoundary != "internal" {
		t.Fatalf("out if = %+v", f)
	}
	if f.SrcCountry != "US" || f.SrcCity != "Mountain View" || f.SrcAS != 15169 || f.SrcNetPrefix.IsValid() {
		t.Fatalf("src = %+v", f)
	}
	if f.DstNetPrefix.String() != "10.1.0.0/24" || f.DstNetName != "servers" || f.DstNetRole != "Servers" || f.DstNetSite != "DC1" ||
		f.DstNetTenant != "NetOps" || f.DstNetVRF != "prod" || f.DstHost != "app.example.net" ||
		f.DstCI != "inventory-db:virtualization.virtualmachine:1" || f.DstAS != 64512 {
		t.Fatalf("dst = %+v", f)
	}
	if f.App != "https" {
		t.Fatalf("app = %q", f.App)
	}

	// Collector names: unknown in inventory, and joined by name.
	f2 := &flow.Flow{ExporterAddress: edge, InIf: 7, OutIf: 8, SrcAddr: netip.MustParseAddr("192.168.5.5"), SrcNetMask: 24,
		DstAddr: netip.MustParseAddr("192.168.5.6"), Bytes: 10, SamplingRate: 1}
	f3 := &flow.Flow{ExporterAddress: other, InIf: 1, SrcAddr: netip.MustParseAddr("10.9.9.9"), DstAddr: netip.MustParseAddr("172.16.0.1"),
		DstNetMask: 16, Bytes: 5}
	e.Put(context.Background(), []*flow.Flow{f2, f3})
	if f2.InIfName != "et-0/0/7" || f2.InIfDescription != "collector descr" || f2.InIfSpeed != 1e9 || f2.InIfBoundary != "" {
		t.Fatalf("collector if = %+v", f2)
	}
	if f2.OutIfName != "xe-0/0/2" || f2.OutIfDescription != "via name" || f2.OutIfSpeed != 10e9 {
		t.Fatalf("by-name if = %+v", f2)
	}
	if f2.SrcNetPrefix.String() != "192.168.5.0/24" || f2.SrcNetName != "" {
		t.Fatalf("mask prefix = %v", f2.SrcNetPrefix)
	}
	if f3.ExporterName != "198.51.100.7" || f3.ExporterRef != "" || f3.InIfName != "" {
		t.Fatalf("unknown exporter = %+v", f3)
	}
	if f3.SrcNetName != "RFC1918" {
		t.Fatalf("container prefix = %q", f3.SrcNetName)
	}

	u := e.Unknown()
	if len(u.Exporters) != 1 || u.Exporters[0].Address != other || u.Exporters[0].Flows != 1 {
		t.Fatalf("unknown exporters = %+v", u.Exporters)
	}
	// 10.9.9.9 is in 10/8; 192.168.5.5/6 and 172.16.0.1 are not. 8.8.8.8 is public: not tracked.
	if len(u.Addresses) != 3 || u.Addresses[0].Bytes != 10 || u.Addresses[2].Address != netip.MustParseAddr("172.16.0.1") {
		t.Fatalf("unknown addresses = %+v", u.Addresses)
	}

	if got := counterValue(e.m.flows); got != 3 {
		t.Fatalf("flows metric = %v", got)
	}
	if got := counterValue(e.m.ifCollector); got != 1 {
		t.Fatalf("collector metric = %v", got)
	}
	mfs, err := reg.Gather()
	if err != nil || len(mfs) < 8 {
		t.Fatalf("metrics = %d, %v", len(mfs), err)
	}
}

func TestClassifiersAndASOrder(t *testing.T) {
	cls, err := classifier.New(classifier.Config{
		Exporter:  []string{`exporter.name.startsWith("edge") ? {"group": "border", "site": "override"} : {}`},
		Interface: []string{`interface.description == "collector descr" ? {"boundary": "external", "provider": "acme", "connectivity": "peering"} : {}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := newTestEnricher(t, Config{Classifiers: cls, ASProviders: []string{ASFlowExceptPrivate, ASGeoIP}})
	f := &flow.Flow{ExporterAddress: edge, InIf: 7, SrcAddr: google, SrcAS: 64600, DstAddr: google, DstAS: 3356}
	e.Put(context.Background(), []*flow.Flow{f})
	if f.ExporterGroup != "border" || f.ExporterSite != "override" || f.ExporterName != "edge-01" {
		t.Fatalf("exporter = %+v", f)
	}
	if f.InIfBoundary != "external" || f.InIfProvider != "acme" || f.InIfConnectivity != "peering" {
		t.Fatalf("iface = %+v", f)
	}
	if f.SrcAS != 15169 || f.DstAS != 3356 {
		t.Fatalf("AS = %d %d", f.SrcAS, f.DstAS)
	}
	// Removing classifiers takes effect immediately.
	e.SetClassifiers(nil)
	f = &flow.Flow{ExporterAddress: edge, InIf: 7}
	e.Put(context.Background(), []*flow.Flow{f})
	if f.ExporterGroup != "" || f.InIfBoundary != "" {
		t.Fatalf("after removal = %+v", f)
	}
	if _, err := New(&capture{}, Config{ASProviders: []string{"bgp"}}); err == nil {
		t.Fatal("want error for unknown AS provider")
	}
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("want error for nil sink")
	}
}

func TestSnapshotSwapAndUnknownForget(t *testing.T) {
	inv := loadInv(t)
	e, _ := newTestEnricher(t, Config{Inventory: inv, UnknownAddresses: 2})
	put := func(fs ...*flow.Flow) { e.Put(context.Background(), fs) }
	put(&flow.Flow{ExporterAddress: edge, SrcAddr: netip.MustParseAddr("192.168.0.1"), Bytes: 100},
		&flow.Flow{ExporterAddress: edge, SrcAddr: netip.MustParseAddr("192.168.0.2"), Bytes: 50},
		&flow.Flow{ExporterAddress: edge, SrcAddr: netip.MustParseAddr("192.168.0.3"), Bytes: 10})
	u := e.Unknown()
	// Space-Saving: 192.168.0.3 replaced the smallest (0.2) and inherited its count.
	if len(u.Addresses) != 2 || u.Addresses[0].Address != netip.MustParseAddr("192.168.0.1") || u.Addresses[1].Bytes != 60 {
		t.Fatalf("top = %+v", u.Addresses)
	}
	// An empty snapshot: the exporter becomes unknown (cache invalidated).
	inv.p.Store(inventory.Empty())
	f := &flow.Flow{ExporterAddress: edge}
	put(f)
	if f.ExporterName != "192.0.2.1" || len(e.Unknown().Exporters) != 1 {
		t.Fatalf("after swap = %+v", f)
	}
	// Back to the full snapshot: forgotten from the unknown list.
	inv.p.Store(loadInv(t).Current())
	if len(e.Unknown().Exporters) != 0 {
		t.Fatal("known exporter still listed")
	}
	e.ResetUnknown()
	if u := e.Unknown(); len(u.Addresses) != 0 {
		t.Fatal("reset")
	}
}

func TestNoSources(t *testing.T) {
	c := &capture{}
	e, err := New(c, Config{})
	if err != nil {
		t.Fatal(err)
	}
	f := &flow.Flow{ExporterAddress: edge, InIf: 3, SrcAddr: google, SrcAS: 1, Proto: 17, DstPort: 53, SrcPort: 5000}
	if err := e.Put(context.Background(), []*flow.Flow{f, nil}); err != nil {
		t.Fatal(err)
	}
	if f.ExporterName != "192.0.2.1" || f.SrcAS != 1 || f.App != "dns" || f.InIfName != "" {
		t.Fatalf("flow = %+v", f)
	}
	if err := e.Put(context.Background(), nil); err != nil || len(c.got) != 2 {
		t.Fatal("empty batch")
	}
}

func TestCacheTTL(t *testing.T) {
	names := ifNames{7: {"a", ""}}
	e, _ := newTestEnricher(t, Config{IfNames: names, CacheTTL: time.Minute})
	now := time.Now()
	e.now = func() time.Time { return now }
	f := &flow.Flow{ExporterAddress: edge, InIf: 7}
	e.Put(context.Background(), []*flow.Flow{f})
	names[7] = [3]string{"b", ""}
	e.Put(context.Background(), []*flow.Flow{f})
	if f.InIfName != "a" {
		t.Fatalf("cached name = %q", f.InIfName)
	}
	now = now.Add(2 * time.Minute)
	e.Put(context.Background(), []*flow.Flow{f})
	if f.InIfName != "b" {
		t.Fatalf("expired name = %q", f.InIfName)
	}
}

func TestPrivateAS(t *testing.T) {
	for as, want := range map[uint32]bool{64512: true, 65535: true, 4200000000: true, 23456: true, 15169: false, 0: false} {
		if isPrivateAS(as) != want {
			t.Errorf("isPrivateAS(%d)", as)
		}
	}
	if !isInternalAddr(netip.MustParseAddr("100.64.1.1")) || !isInternalAddr(netip.MustParseAddr("fd00::1")) || isInternalAddr(google) {
		t.Fatal("isInternalAddr")
	}
}

func counterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	c.Write(&m)
	return m.GetCounter().GetValue()
}

// BenchmarkEnrich measures the enrichment path with a warm cache: a batch of
// 1000 flows over 4 interfaces, prefix + address + GeoIP lookups per side.
func BenchmarkEnrich(b *testing.B) { benchmarkEnrich(b, nil) }

// BenchmarkEnrichMMDB uses real MMDB files (City + ASN) for GeoIP.
func BenchmarkEnrichMMDB(b *testing.B) {
	dir := b.TempDir()
	var city, asn []geoiptest.Network
	for i := 1; i <= 200; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i), 0, 0, 0}), 8)
		city = append(city, geoiptest.Network{Prefix: p, Data: map[string]any{
			"country": map[string]any{"iso_code": "US"}, "city": map[string]any{"names": map[string]any{"en": "City " + strconv.Itoa(i)}}}})
		asn = append(asn, geoiptest.Network{Prefix: p, Data: map[string]any{
			"autonomous_system_number": uint32(64000 + i), "autonomous_system_organization": "AS " + strconv.Itoa(i)}})
	}
	geoiptest.Write(filepath.Join(dir, "city.mmdb"), "GeoLite2-City", city)
	geoiptest.Write(filepath.Join(dir, "asn.mmdb"), "GeoLite2-ASN", asn)
	db, err := geoip.Open(geoip.Config{Databases: []string{filepath.Join(dir, "city.mmdb"), filepath.Join(dir, "asn.mmdb")}})
	if err != nil {
		b.Fatal(err)
	}
	benchmarkEnrich(b, db)
}

func benchmarkEnrich(b *testing.B, geo GeoSource) {
	cls, _ := classifier.New(classifier.Config{
		Exporter:  []string{`{"group": "border"}`},
		Interface: []string{`interface.boundary == "" ? {"boundary": "internal"} : {}`},
	})
	e, _ := newTestEnricher(b, Config{Classifiers: cls, Metrics: prometheus.NewRegistry(), GeoIP: geo})
	e.next = flow.SinkFunc(func(context.Context, []*flow.Flow) error { return nil })
	batch := make([]*flow.Flow, 1000)
	ifs := []uint32{501, 502, 503, 600}
	for i := range batch {
		src := netip.AddrFrom4([4]byte{10, 1, 0, byte(i)})
		dst := netip.AddrFrom4([4]byte{byte(1 + i%200), byte(i), 8, 8})
		if i%3 == 0 {
			dst = google
		}
		batch[i] = &flow.Flow{ExporterAddress: edge, InIf: ifs[i%4], OutIf: ifs[(i+1)%4], SrcAddr: src, DstAddr: dst,
			Proto: 6, SrcPort: uint16(40000 + i), DstPort: 443, Bytes: 1500, Packets: 1, SamplingRate: 1000}
	}
	ctx := context.Background()
	e.Put(ctx, batch)
	b.ResetTimer()
	for b.Loop() {
		for _, f := range batch {
			f.App = ""
		}
		e.Put(ctx, batch)
	}
	b.ReportMetric(float64(b.N*len(batch))/b.Elapsed().Seconds(), "flows/s")
}
