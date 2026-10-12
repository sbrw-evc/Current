package query_test

import (
	"context"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

// Synthetic data, one flow of each kind per minute during one hour from
// base, sampling rate 10 (stored volumes below are already ×10):
//
//	SrcAS 100   → DstAS 65000  6000 B  in1 → out1  tcp
//	SrcAS 200   → DstAS 65000  3000 B  in1 → out1  tcp
//	SrcAS 300   → DstAS 65000  1200 B  in1 → out1  udp
//	SrcAS 400   → DstAS 65000   600 B  in1 → out1  udp
//	SrcAS 65000 → DstAS 100     500 B  out1 → in1  tcp (return traffic)
//
// Every flow has 100 packets (stored).
type fixture struct {
	q    *query.Querier
	conn driver.Conn
	cfg  chstore.Config
	base time.Time
}

func setup(t *testing.T) fixture {
	t.Helper()
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
	base := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	exporter := netip.MustParseAddr("192.0.2.1")
	type kind struct {
		src, dst uint32
		bytes    uint64
		proto    uint8
		reverse  bool
	}
	kinds := []kind{{100, 65000, 600, 6, false}, {200, 65000, 300, 6, false}, {300, 65000, 120, 17, false}, {400, 65000, 60, 17, false}, {65000, 100, 50, 6, true}}
	var fs []*flow.Flow
	for m := 0; m < 60; m++ {
		for i, k := range kinds {
			f := &flow.Flow{
				TimeReceived:    base.Add(time.Duration(m) * time.Minute),
				SamplingRate:    10,
				ExporterAddress: exporter,
				ExporterName:    "edge-01",
				SrcAddr:         netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}),
				DstAddr:         netip.MustParseAddr("2001:db8::1"),
				SrcAS:           k.src,
				DstAS:           k.dst,
				Proto:           k.proto,
				Bytes:           k.bytes,
				Packets:         10,
				InIf:            1, InIfName: "in1", InIfSpeed: 1_000_000, InIfBoundary: "external",
				OutIf: 2, OutIfName: "out1", OutIfSpeed: 2_000_000, OutIfBoundary: "internal",
			}
			if k.reverse {
				f.InIf, f.InIfName, f.InIfSpeed, f.InIfBoundary = 2, "out1", 2_000_000, "internal"
				f.OutIf, f.OutIfName, f.OutIfSpeed, f.OutIfBoundary = 1, "in1", 1_000_000, "external"
			}
			fs = append(fs, f)
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
	return fixture{q: query.New(conn, query.Config{Storage: cfg}), conn: conn, cfg: cfg, base: base}
}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-6*math.Max(1, math.Abs(b)) }

func allNear(v []float64, want float64) bool {
	for _, x := range v {
		if !near(x, want) {
			return false
		}
	}
	return true
}

func TestVisualize(t *testing.T) {
	fx := setup(t)
	ctx := context.Background()
	hour := func(r query.VisualizeRequest) query.VisualizeRequest {
		r.Start, r.End = fx.base, fx.base.Add(time.Hour)
		return r
	}
	ts := func(t *testing.T, r query.VisualizeRequest) *query.TimeSeriesResponse {
		t.Helper()
		out, err := fx.q.Visualize(ctx, hour(r))
		if err != nil {
			t.Fatal(err)
		}
		return out.(*query.TimeSeriesResponse)
	}

	t.Run("top-N and Other", func(t *testing.T) {
		r := ts(t, query.VisualizeRequest{Points: 60, Dimensions: []string{"SrcAS"}, Limit: 2})
		if r.Resolution != "1m" || len(r.T) != 60 || !r.T[0].Equal(fx.base) {
			t.Fatalf("resolution %s, %d points from %s", r.Resolution, len(r.T), r.T[0])
		}
		want := [][]string{{"AS100"}, {"AS200"}, {"Other"}}
		if !reflect.DeepEqual(r.Rows, want) {
			t.Fatalf("rows %v", r.Rows)
		}
		for i, v := range []float64{6000 * 8 / 60.0, 3000 * 8 / 60.0, (1200 + 600 + 500) * 8 / 60.0} {
			if !allNear(r.Points[i], v) || !near(r.Average[i], v) || !near(r.Min[i], v) || !near(r.Max[i], v) || !near(r.P95[i], v) {
				t.Errorf("row %v: points %v avg %v, want %v", r.Rows[i], r.Points[i][:3], r.Average[i], v)
			}
		}
		if !reflect.DeepEqual(r.Axis, []int{1, 1, 1}) || r.SQL == "" {
			t.Errorf("axis %v", r.Axis)
		}
	})

	t.Run("fill", func(t *testing.T) {
		// Two hours, the second one without data: filled with zeros.
		out, err := fx.q.Visualize(ctx, query.VisualizeRequest{Start: fx.base, End: fx.base.Add(2 * time.Hour), Points: 24, Dimensions: []string{"Proto"}})
		if err != nil {
			t.Fatal(err)
		}
		r := out.(*query.TimeSeriesResponse)
		if r.Resolution != "5m" || len(r.T) != 24 || !reflect.DeepEqual(r.Rows, [][]string{{"tcp"}, {"udp"}}) {
			t.Fatalf("resolution %s, %d points, rows %v", r.Resolution, len(r.T), r.Rows)
		}
		tcp := (6000 + 3000 + 500) * 8 / 60.0
		if !allNear(r.Points[0][:12], tcp) || !allNear(r.Points[0][12:], 0) || !near(r.Average[0], tcp/2) {
			t.Errorf("tcp %v", r.Points[0])
		}
	})

	t.Run("units", func(t *testing.T) {
		bytes, packets := 11300.0, 500.0
		for _, c := range []struct {
			units string
			want  float64
		}{
			{query.UnitsL3bps, bytes * 8 / 60},
			{query.UnitsL2bps, (bytes + 18*packets) * 8 / 60},
			{query.UnitsPps, packets / 60},
			// in1 (1 Mb/s) gets the first four, out1 (2 Mb/s) the return flow.
			{query.UnitsInL2Pct, ((10800+18*400)*8*100/1e6 + (500+18*100)*8*100/2e6) / 60},
			{query.UnitsOutL2Pct, ((10800+18*400)*8*100/2e6 + (500+18*100)*8*100/1e6) / 60},
		} {
			r := ts(t, query.VisualizeRequest{Points: 60, Units: c.units})
			if !reflect.DeepEqual(r.Rows, [][]string{{"Total"}}) || !allNear(r.Points[0], c.want) {
				t.Errorf("%s: rows %v points %v, want %v", c.units, r.Rows, r.Points[0][:2], c.want)
			}
		}
	})

	t.Run("bidirectional", func(t *testing.T) {
		r := ts(t, query.VisualizeRequest{Points: 60, Dimensions: []string{"SrcAS"}, Limit: 2, Bidirectional: true})
		want := [][]string{{"AS100"}, {"AS200"}, {"Other"}, {"AS65000"}, {"AS100"}}
		if !reflect.DeepEqual(r.Rows, want) || !reflect.DeepEqual(r.Axis, []int{1, 1, 1, 2, 2}) {
			t.Fatalf("rows %v axis %v", r.Rows, r.Axis)
		}
		if !near(r.Average[3], 10800*8/60.0) || !near(r.Average[4], 500*8/60.0) {
			t.Errorf("reverse averages %v", r.Average)
		}
	})

	t.Run("resolution", func(t *testing.T) {
		for _, c := range []struct {
			points int
			dims   []string
			span   time.Duration
			want   string
		}{
			{200, []string{"SrcAS"}, time.Hour, "raw"},
			{12, []string{"SrcAS"}, time.Hour, "5m"},
			{5, []string{"SrcAS"}, 10 * time.Hour, "1h"},
			{12, []string{"SrcAddr"}, time.Hour, "raw"},
		} {
			out, err := fx.q.Visualize(ctx, query.VisualizeRequest{Start: fx.base, End: fx.base.Add(c.span), Points: c.points, Dimensions: c.dims})
			if err != nil {
				t.Fatal(err)
			}
			r := out.(*query.TimeSeriesResponse)
			if r.Resolution != c.want {
				t.Errorf("%d points %v over %s: %s, want %s", c.points, c.dims, c.span, r.Resolution, c.want)
			}
			// Every resolution sees the same volume.
			var bits float64
			step := c.span.Seconds() / float64(len(r.T))
			if len(r.T) > 1 {
				step = r.T[1].Sub(r.T[0]).Seconds()
			}
			for _, p := range r.Points {
				for _, v := range p {
					bits += v * step
				}
			}
			if !near(bits, 11300*8*60) {
				t.Errorf("%s: total bits %v", r.Resolution, bits)
			}
		}
		out, _ := fx.q.Visualize(ctx, hour(query.VisualizeRequest{Points: 12, Dimensions: []string{"SrcAddr"}, Limit: 1}))
		if r := out.(*query.TimeSeriesResponse); r.Rows[0][0] != "10.0.0.1" {
			t.Errorf("IPv4 label %v", r.Rows)
		}
	})

	t.Run("filter", func(t *testing.T) {
		if fr, err := filter.Compile("Proto = 17"); err != nil || fr.SQL == "1" {
			t.Skip("filter parser not available")
		}
		r := ts(t, query.VisualizeRequest{Points: 60, Filter: "Proto = 17"})
		if !allNear(r.Points[0], 1800*8/60.0) {
			t.Errorf("filtered %v", r.Points[0][:2])
		}
		r = ts(t, query.VisualizeRequest{Points: 60, Filter: "SrcAddr = 10.0.0.1"})
		if r.Resolution != "raw" || !allNear(r.Points[0], 6000*8/60.0) {
			t.Errorf("filtered on SrcAddr: %s %v", r.Resolution, r.Points[0][:2])
		}
	})

	t.Run("sankey", func(t *testing.T) {
		out, err := fx.q.Visualize(ctx, hour(query.VisualizeRequest{Graph: query.GraphSankey, Points: 60, Dimensions: []string{"SrcAS", "InIfName"}, Limit: 2}))
		if err != nil {
			t.Fatal(err)
		}
		r := out.(*query.SankeyResponse)
		wantRows := [][]string{{"AS100", "in1"}, {"AS200", "in1"}, {"Other", "in1"}, {"Other", "out1"}}
		wantXps := []float64{800, 400, 240, 500 * 8 / 60.0}
		if !reflect.DeepEqual(r.Rows, wantRows) {
			t.Fatalf("rows %v", r.Rows)
		}
		for i := range wantXps {
			if !near(r.Xps[i], wantXps[i]) {
				t.Errorf("xps %v", r.Xps)
			}
		}
		if !reflect.DeepEqual(r.Nodes, []string{"SrcAS: AS100", "SrcAS: AS200", "SrcAS: Other", "InIfName: in1", "InIfName: out1"}) {
			t.Errorf("nodes %v", r.Nodes)
		}
		if len(r.Links) != 4 || r.Links[0] != (query.SankeyLink{Source: "SrcAS: AS100", Target: "InIfName: in1", Xps: 800}) {
			t.Errorf("links %v", r.Links)
		}
	})
}

func TestWidgetsSearchExporters(t *testing.T) {
	fx := setup(t)
	ctx := context.Background()
	now := fx.base.Add(30 * time.Minute) // window: minutes 25–29
	q := query.New(fx.conn, query.Config{Storage: fx.cfg, Now: func() time.Time { return now }})

	s, err := q.WidgetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !near(s.FlowsPerSecond, 25/300.0) || s.Exporters != 1 || !near(s.BpsInExternal, 10800*8/60.0) || !near(s.BpsOutExternal, 500*8/60.0) {
		t.Errorf("summary %+v", s)
	}

	top, err := q.WidgetTop(ctx, "src-as", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(top.Top) != 3 || top.Top[0].Name != "AS100" || !near(top.Top[0].Percent, 6000*100/11300.0) || top.Top[2].Name != "Other" {
		t.Errorf("top %+v", top.Top)
	}
	if _, err := q.WidgetTop(ctx, "nope", 0); err == nil {
		t.Error("unknown top accepted")
	}

	g, err := q.WidgetGraph(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	var bits float64
	for _, v := range g.Gbps {
		bits += v * 1e9 * g.T[1].Sub(g.T[0]).Seconds()
	}
	if len(g.T) != 144 || len(g.T) != len(g.Gbps) || !near(bits, 10800*8*30) {
		t.Errorf("graph %d points, %v bits", len(g.T), bits)
	}

	ex, err := q.Exporters(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Results) != 1 {
		t.Fatalf("exporters %+v", ex)
	}
	e := ex.Results[0]
	if e.Address != "192.0.2.1" || e.Name != "edge-01" || !reflect.DeepEqual(e.SamplingRates, []uint64{10}) || len(e.Interfaces) != 2 ||
		!e.LastSeen.Equal(fx.base.Add(29*time.Minute)) || !near(e.FlowsPerSecond, 25/300.0) {
		t.Fatalf("exporter %+v", e)
	}
	in1 := e.Interfaces[0]
	if in1.Index != 1 || in1.Name != "in1" || in1.Speed != 1_000_000 || in1.Boundary != "external" ||
		!near(in1.InBps, 10800*8/60.0) || !near(in1.OutBps, 500*8/60.0) {
		t.Errorf("in1 %+v", in1)
	}

	res, err := q.SearchFlows(ctx, query.FlowsSearchRequest{Start: fx.base, End: fx.base.Add(time.Hour), Limit: 3, Order: "bytes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Columns) != len(schema.Columns) || len(res.Rows) != 3 {
		t.Fatalf("search %d columns %d rows", len(res.Columns), len(res.Rows))
	}
	row := map[string]any{}
	for i, c := range res.Columns {
		row[c] = res.Rows[0][i]
	}
	if row["Bytes"] != uint64(6000) || row["SrcAddr"] != "10.0.0.1" || row["DstAddr"] != "2001:db8::1" || row["SrcAS"] != uint32(100) {
		t.Errorf("first row %v", row)
	}

	last, err := q.LastFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if last == nil || last["ExporterAddress"] != "192.0.2.1" {
		t.Errorf("last flow %v", last)
	}
}
