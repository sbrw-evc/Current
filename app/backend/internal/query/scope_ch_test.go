package query_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

// TestScopeClickHouse runs every read path of the API through ScopedConn
// against a real ClickHouse (the rewritten SQL must be valid there, and only
// the flows of the scope may come back):
//
//	in scope by CI:      10.1.0.1 (SrcCI ref "app") → 10.2.0.1 (DstCI ref "db"), tcp/5432, 1000 B
//	in scope by address: 192.0.2.10 → 10.0.0.5 (no CI),                          udp/53,   300 B
//	out of scope:        198.51.100.7 → 10.3.0.9,                                 tcp/443,  7000 B
//
// one flow of each per minute over the last 40 minutes, plus app → db once a
// day for the 5 previous days with the response db → app (dependency
// discovery), sampling 1.
func TestScopeClickHouse(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	w, err := chstore.NewWriter(conn, cfg, chstore.WriterConfig{BatchSize: 1000, MaxDelay: 50 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const app, dbRef, edge = "inventory-db:dcim.device:5", "inventory-db:dcim.device:6", "inventory-db:dcim.device:2"
	now := time.Now().UTC().Truncate(time.Minute)
	mk := func(at time.Time, src, dst string, srcCI, dstCI string, sp, dp uint16, proto uint8, bytes uint64) *flow.Flow {
		return &flow.Flow{TimeReceived: at, SamplingRate: 1, ExporterAddress: netip.MustParseAddr("127.0.0.11"), ExporterName: "edge-01",
			ExporterRef: edge, SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst), SrcCI: srcCI, DstCI: dstCI,
			SrcPort: sp, DstPort: dp, Proto: proto, Bytes: bytes, Packets: 10, SrcAS: 64500, DstAS: 64501,
			InIf: 1, InIfName: "Te0/0/0", InIfSpeed: 10_000_000_000, InIfBoundary: "external",
			OutIf: 2, OutIfName: "Te0/1/0", OutIfSpeed: 10_000_000_000, OutIfBoundary: "internal"}
	}
	var fs []*flow.Flow
	for m := 1; m <= 40; m++ {
		at := now.Add(-time.Duration(m) * time.Minute)
		fs = append(fs,
			mk(at, "10.1.0.1", "10.2.0.1", app, dbRef, 40000+uint16(m), 5432, 6, 1000),
			mk(at, "192.0.2.10", "10.0.0.5", "", "", 53000, 53, 17, 300),
			mk(at, "198.51.100.7", "10.3.0.9", "", "", 443, 50000, 6, 7000))
	}
	for d := 1; d <= 5; d++ {
		for i := 0; i < 3; i++ {
			at := now.Add(-time.Duration(d)*24*time.Hour - time.Duration(i)*time.Minute)
			// The request and the response of the same connection: one pair.
			fs = append(fs, mk(at, "10.1.0.1", "10.2.0.1", app, dbRef, 41000, 5432, 6, 1000),
				mk(at, "10.2.0.1", "10.1.0.1", dbRef, app, 5432, 41000, 6, 4000))
		}
	}
	if err := w.Put(ctx, fs); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := w.Close(cctx); err != nil {
		t.Fatal(err)
	}

	q := query.New(query.ScopedConn(conn, cfg), query.Config{Storage: cfg})
	scope := query.NewScope([]string{app}, []string{"10.0.0.5"})
	sctx := query.WithScope(ctx, scope)
	start, end := now.Add(-45*time.Minute), now

	total := func(v any) float64 {
		ts, ok := v.(*query.TimeSeriesResponse)
		if !ok {
			t.Fatalf("not a time series: %T", v)
		}
		s := 0.0
		for _, p := range ts.Points {
			for _, x := range p {
				s += x
			}
		}
		return s
	}
	// Visualize, raw table: both scope parts (1000 + 300 B per minute), never the 7000 B flows.
	vreq := query.VisualizeRequest{Start: start, End: end, Points: 45, Units: "l3bps"}
	all, err := q.Visualize(ctx, vreq)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := q.Visualize(sctx, vreq)
	if err != nil {
		t.Fatal("scoped visualize:", err)
	}
	if a, s := total(all), total(scoped); s <= 0 || !near(s/a, 1300.0/8300.0) {
		t.Fatalf("visualize: scoped %v of %v, want the share %v", s, a, 1300.0/8300.0)
	}
	// Bidirectional and sankey.
	if _, err := q.Visualize(sctx, query.VisualizeRequest{Start: start, End: end, Dimensions: []string{"DstPort"}, Bidirectional: true}); err != nil {
		t.Fatal("bidirectional:", err)
	}
	sk, err := q.Visualize(sctx, query.VisualizeRequest{Start: start, End: end, Dimensions: []string{"SrcAddr", "DstPort"}, Graph: query.GraphSankey})
	if err != nil {
		t.Fatal("sankey:", err)
	}
	if s, ok := sk.(*query.SankeyResponse); ok {
		for _, r := range s.Rows {
			if r[0] == "198.51.100.7" {
				t.Fatalf("sankey leaks an out-of-scope address: %v", s.Rows)
			}
		}
	}
	// Aggregated tables (no addresses): only the CI part of the scope.
	agg, err := q.Visualize(sctx, query.VisualizeRequest{Start: now.Add(-20 * 24 * time.Hour), End: end, Points: 50, Dimensions: []string{"DstPort"}})
	if err != nil {
		t.Fatal("aggregates:", err)
	}
	for _, r := range agg.(*query.TimeSeriesResponse).Rows {
		if r[0] == "443" || r[0] == "50000" {
			t.Fatalf("aggregates leak out-of-scope ports: %v", agg.(*query.TimeSeriesResponse).Rows)
		}
	}
	// Flow search: only in-scope flows.
	res, err := q.SearchFlows(sctx, query.FlowsSearchRequest{Start: start, End: end, Limit: 1000})
	if err != nil {
		t.Fatal("flows search:", err)
	}
	col := map[string]int{}
	for i, c := range res.Columns {
		col[c] = i
	}
	if len(res.Rows) != 80 {
		t.Fatalf("flows search: %d rows, want 80", len(res.Rows))
	}
	for _, r := range res.Rows {
		if r[col["SrcCI"]] != app && r[col["DstAddr"]] != "10.0.0.5" {
			t.Fatalf("flows search leaks %v", r)
		}
	}
	// Widgets, last flow, exporters.
	if _, err := q.WidgetSummary(sctx); err != nil {
		t.Fatal("summary:", err)
	}
	top, err := q.WidgetTop(sctx, "dst-port", 10)
	if err != nil {
		t.Fatal("top:", err)
	}
	for _, it := range top.Top {
		if it.Name == "50000" {
			t.Fatalf("top leaks: %+v", top.Top)
		}
	}
	if _, err := q.WidgetGraph(sctx, 50); err != nil {
		t.Fatal("graph:", err)
	}
	last, err := q.LastFlow(sctx)
	if err != nil {
		t.Fatal("last flow:", err)
	}
	if last["SrcAddr"] == "198.51.100.7" {
		t.Fatalf("last flow leaks: %v", last)
	}
	if ex, err := q.Exporters(sctx, 0); err != nil || len(ex.Results) != 1 {
		t.Fatalf("exporters: %v %+v", err, ex)
	}
	// Inventory DB status and prefix addresses.
	ot, err := q.ObjectTraffic(sctx, query.ObjectTrafficRequest{Type: query.ObjectDevice, Targets: []query.ObjectTarget{{ID: "2", Ref: edge}}})
	if err != nil {
		t.Fatal("object traffic:", err)
	}
	full, err := q.ObjectTraffic(ctx, query.ObjectTrafficRequest{Type: query.ObjectDevice, Targets: []query.ObjectTarget{{ID: "2", Ref: edge}}})
	if err != nil {
		t.Fatal("object traffic:", err)
	}
	if ot["2"] == nil || full["2"] == nil || ot["2"].InBps <= 0 || ot["2"].InBps >= full["2"].InBps {
		t.Fatalf("object traffic: scoped %+v, full %+v", ot["2"], full["2"])
	}
	for _, typ := range []string{query.ObjectInterface, query.ObjectCircuit} {
		if _, err := q.ObjectTraffic(sctx, query.ObjectTrafficRequest{Type: typ, Targets: []query.ObjectTarget{{ID: "1", Ref: edge, IfName: "Te0/0/0", Circuit: "CID-1", P95: true}}}); err != nil {
			t.Fatalf("object traffic %s: %v", typ, err)
		}
	}
	pa, err := q.PrefixAddresses(sctx, netip.MustParsePrefix("10.0.0.0/8"), "", 0)
	if err != nil {
		t.Fatal("prefix addresses:", err)
	}
	for _, a := range pa {
		if a.Address == netip.MustParseAddr("10.3.0.9") {
			t.Fatalf("prefix addresses leak: %+v", pa)
		}
	}
	if len(pa) != 3 {
		t.Fatalf("prefix addresses: %+v", pa)
	}

	// Dependency discovery (background, unscoped) on the same data.
	pairs, err := q.DependencyPairs(ctx, query.DependencyParams{MinFlows: 10, MinDays: 3})
	if err != nil {
		t.Fatal("dependencies:", err)
	}
	if len(pairs) != 1 || pairs[0].ClientRef != app || pairs[0].ServerRef != dbRef || pairs[0].Port != 5432 || pairs[0].DaysSeen < 5 || pairs[0].Flows != 70 || pairs[0].Bytes != 40*1000+15*1000+15*4000 {
		t.Fatalf("dependency pairs: %+v", pairs)
	}
}
