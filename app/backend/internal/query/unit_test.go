package query

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

func TestNormalize(t *testing.T) {
	start := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	ok := VisualizeRequest{Start: start, End: start.Add(time.Hour), Dimensions: []string{"SrcAS", "ExporterName"}}
	got, err := ok.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.Points != 200 || got.Limit != 10 || got.Units != UnitsL3bps || got.Graph != GraphStacked {
		t.Errorf("defaults: %+v", got)
	}
	bad := []func(r *VisualizeRequest){
		func(r *VisualizeRequest) { r.End = r.Start },
		func(r *VisualizeRequest) { r.Limit = 51 },
		func(r *VisualizeRequest) { r.Limit = -1 },
		func(r *VisualizeRequest) { r.Points = 4 },
		func(r *VisualizeRequest) { r.Points = 2001 },
		func(r *VisualizeRequest) { r.Units = "bps" },
		func(r *VisualizeRequest) { r.Graph = "pie" },
		func(r *VisualizeRequest) { r.Dimensions = []string{"Bytes"} },
		func(r *VisualizeRequest) { r.Dimensions = []string{"TCPFlags"} },
		func(r *VisualizeRequest) { r.Dimensions = []string{"SrcAS", "SrcAS"} },
		func(r *VisualizeRequest) { r.Dimensions = []string{"Nope; DROP"} },
		func(r *VisualizeRequest) { r.Graph, r.Dimensions = GraphSankey, nil },
	}
	for i, mod := range bad {
		r := ok
		mod(&r)
		_, err := r.normalize()
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("case %d: err = %v, want ValidationError", i, err)
		}
	}
}

func TestChooseResolution(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	cfg := chstore.Config{}
	cases := []struct {
		cols   []string
		span   time.Duration
		ago    time.Duration
		points int
		want   string
	}{
		{[]string{"SrcAS"}, time.Hour, time.Hour, 200, "raw"},           // 18s < 1m
		{[]string{"SrcAS"}, time.Hour, time.Hour, 60, "1m"},             // 60s
		{[]string{"SrcAS"}, time.Hour, time.Hour, 12, "5m"},             // 300s
		{[]string{"SrcAS"}, 10 * time.Hour, 10 * time.Hour, 5, "1h"},    // 2h
		{[]string{"SrcAddr"}, 10 * time.Hour, 10 * time.Hour, 5, "raw"}, // not in rollups
		{[]string{"SrcAS"}, 24 * time.Hour, 60 * 24 * time.Hour, 24, "1h"},
		// 5m is too old for a 100-day-old start: 1h.
		{[]string{"SrcAS"}, 24 * time.Hour, 100 * 24 * time.Hour, 288, "1h"},
		// raw expired, nothing fits the interval: finest that covers start.
		{[]string{"SrcAS"}, time.Hour, 20 * 24 * time.Hour, 200, "1m"},
		{nil, time.Hour, time.Hour, 60, "1m"},
	}
	for _, c := range cases {
		start := now.Add(-c.ago)
		got := chooseResolution(cfg, c.cols, start, start.Add(c.span), c.points, now)
		if got.Name != c.want {
			t.Errorf("%v span %s ago %s points %d: %s, want %s", c.cols, c.span, c.ago, c.points, got.Name, c.want)
		}
	}
}

func TestMakePlan(t *testing.T) {
	start := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := makePlan(chstore.Config{}.Rollups()[0], start, start.Add(time.Hour), 200)
	if p.step != 60 || p.buckets != 60 || p.start != start.Unix() || p.end != start.Add(time.Hour).Unix() {
		t.Errorf("plan %+v", p)
	}
	p = makePlan(chstore.Config{}.Raw(), start.Add(7*time.Second), start.Add(time.Hour), 100)
	if p.step != 36 || p.start%36 != 0 || p.buckets < 100 || p.buckets > 101 {
		t.Errorf("raw plan %+v", p)
	}
	s := sankeyPlan(chstore.Config{}.Rollups()[1], start.Add(time.Minute), start.Add(time.Hour+time.Minute))
	if s.start != start.Unix() || s.end != start.Add(65*time.Minute).Unix() || s.step != 3900 {
		t.Errorf("sankey plan %+v", s)
	}
}

func TestComputeStats(t *testing.T) {
	st := computeStats([]float64{123, 456})
	if st.avg != 289.5 || st.min != 123 || st.max != 456 || math.Abs(st.p95-439.35) > 1e-9 {
		t.Errorf("%+v", st)
	}
	v := make([]float64, 101)
	for i := range v {
		v[i] = float64(i)
	}
	if st := computeStats(v); st.p95 != 95 {
		t.Errorf("p95 = %v", st.p95)
	}
}

func TestFormatValue(t *testing.T) {
	q := &Querier{asName: func(asn uint32) string {
		if asn == 65000 {
			return "Example"
		}
		return ""
	}}
	cases := [][3]string{
		{"SrcAS", "65000", "AS65000 Example"},
		{"DstAS", "64512", "AS64512"},
		{"Proto", "6", "tcp"},
		{"Proto", "17", "udp"},
		{"Proto", "250", "250"},
		{"EType", "34525", "IPv6"},
		{"ExporterName", "", "Unknown"},
		{"SrcAddr", "::", "Unknown"},
		{"SrcAddr", "10.0.0.1", "10.0.0.1"},
		{"InIfName", "xe-0/0/0", "xe-0/0/0"},
	}
	for _, c := range cases {
		if got := q.formatValue(c[0], c[1]); got != c[2] {
			t.Errorf("%s %q: %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestQuoteString(t *testing.T) {
	if got := quoteString(`a'b\c`); got != `'a\'b\\c'` {
		t.Error(got)
	}
}

func TestTimeSeriesSQL(t *testing.T) {
	cfg := chstore.Config{Database: "db"}
	start := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := makePlan(cfg.Rollups()[0], start, start.Add(time.Hour), 60)
	sql := timeSeriesSQL(cfg.Table("flows_1m"), p, []string{"SrcAS", "SrcAddr"}, "Proto = 6", UnitsL2bps, 10)
	for _, want := range []string{
		"FROM `db`.`flows_1m`",
		"[toString(`SrcAS`), if(startsWith(toString(`SrcAddr`), '::ffff:'), substring(toString(`SrcAddr`), 8), toString(`SrcAddr`))]",
		"LIMIT 10",
		"toStartOfInterval(TimeReceived, INTERVAL 60 SECOND) AS t",
		"(sum(Bytes) + 18 * sum(Packets)) * 8 / 60 AS xps",
		"AND (Proto = 6)",
		"WITH FILL FROM toDateTime(1791795600) TO toDateTime(1791799200) STEP 60",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL lacks %q:\n%s", want, sql)
		}
	}
	total := timeSeriesSQL(cfg.Table("flows"), p, nil, "", UnitsPps, 10)
	if !strings.Contains(total, "AND (1)") || !strings.Contains(total, "toFloat64(sum(Packets)) / 60") || strings.Contains(total, " IN (") {
		t.Errorf("total SQL:\n%s", total)
	}
	sk := sankeySQL(cfg.Table("flows_1m"), sankeyPlan(p.res, start, start.Add(time.Hour)), []string{"SrcAS", "InIfName"}, "1", UnitsInL2Pct, 5)
	if strings.Count(sk, "LIMIT 5") != 2 || !strings.Contains(sk, "/ InIfSpeed") || !strings.Contains(sk, "/ 3600 AS xps") {
		t.Errorf("sankey SQL:\n%s", sk)
	}
}

func TestSankeyGraph(t *testing.T) {
	nodes, links := sankeyGraph([]string{"SrcAS", "InIfName"},
		[][]string{{"AS1", "a"}, {"AS2", "a"}, {"AS1", "b"}, {"AS1", "a"}}, []float64{1, 2, 3, 4})
	if !reflect.DeepEqual(nodes, []string{"SrcAS: AS1", "SrcAS: AS2", "InIfName: a", "InIfName: b"}) {
		t.Errorf("nodes %v", nodes)
	}
	want := []SankeyLink{{"SrcAS: AS1", "InIfName: a", 5}, {"SrcAS: AS1", "InIfName: b", 3}, {"SrcAS: AS2", "InIfName: a", 2}}
	if !reflect.DeepEqual(links, want) {
		t.Errorf("links %v", links)
	}
}

func TestSearchValidation(t *testing.T) {
	q := New(nil, Config{})
	start := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if _, _, _, err := q.searchSQL(FlowsSearchRequest{Start: start, End: start.Add(time.Hour), Limit: 1001}); err == nil {
		t.Error("limit 1001 accepted")
	}
	if _, _, _, err := q.searchSQL(FlowsSearchRequest{Start: start, End: start.Add(time.Hour), Order: "x"}); err == nil {
		t.Error("bad order accepted")
	}
	sql, names, _, err := q.searchSQL(FlowsSearchRequest{Start: start, End: start.Add(time.Hour), Order: "bytes"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "ORDER BY Bytes DESC") || !strings.Contains(sql, "LIMIT 100") || names[0] != "TimeReceived" {
		t.Errorf("%s", sql)
	}
}
