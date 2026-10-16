package wiring_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/bus"
	"github.com/sbrw-evc/current/app/backend/internal/classifier"
	"github.com/sbrw-evc/current/app/backend/internal/collector"
	"github.com/sbrw-evc/current/app/backend/internal/demoexporter"
	"github.com/sbrw-evc/current/app/backend/internal/query"
	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse/chtest"
	"github.com/sbrw-evc/current/app/backend/internal/wiring"
)

// TestPipelineEndToEnd runs demo exporter → collector → in-process bus →
// enricher (classifiers, collector interface names) → ClickHouse writer →
// query, in one process, without OpenBao or PostgreSQL.
// Enable with FLOW_TEST_E2E=1 (ClickHouse from FLOW_TEST_CLICKHOUSE).
func TestPipelineEndToEnd(t *testing.T) {
	if os.Getenv("FLOW_TEST_E2E") != "1" {
		t.Skip("set FLOW_TEST_E2E=1 to run the pipeline end-to-end test")
	}
	conn, db := chtest.Conn(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	storage := chstore.Config{Database: db}.WithDefaults()
	if err := chstore.Migrate(ctx, conn, storage); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	b := bus.NewInProcess(bus.InProcessConfig{}, nil, log)
	col, err := collector.New(collector.Config{NetFlowListen: "127.0.0.1:0", SFlowListen: "127.0.0.1:0",
		FlushInterval: 50 * time.Millisecond}, b, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := chstore.NewWriter(conn, storage, chstore.WriterConfig{MaxDelay: 200 * time.Millisecond, Logger: log}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := wiring.NewMeter(writer)
	en, err := wiring.NewEnricher(wm, wiring.EnricherConfig{IfNames: col.IfNames(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	set, err := classifier.New(classifier.Config{
		Exporter: []string{`exporter.address == "127.0.0.11" ? {"name": "edge-01", "role": "edge"} : ` +
			`exporter.address == "127.0.0.12" ? {"name": "edge-02", "role": "edge"} : {"name": "dc-sw-01"}`},
		Interface: []string{`interface.description.startsWith("Transit:") || interface.description.startsWith("IX:") || ` +
			`interface.description.startsWith("PNI:") ? {"boundary": "external"} : {"boundary": "internal"}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	en.E.SetClassifiers(set)

	pctx, pstop := context.WithCancel(ctx)
	done := make(chan struct{})
	pl := &wiring.Pipeline{Bus: b, Collector: col, Consumer: en.Sink(), Writer: writer, Log: log}
	go func() { pl.Run(pctx); close(done) }()

	dcfg := demoexporter.DefaultConfig(col.NetFlowAddr().String())
	dcfg.SFlowTarget = col.SFlowAddr().String()
	dcfg.FlowsPerSecond = 500
	dcfg.Tick = 20 * time.Millisecond
	dcfg.TemplateInterval = 200 * time.Millisecond
	dcfg.Seed = 7
	dcfg.Logger = log
	dctx, dstop := context.WithTimeout(ctx, 3*time.Second)
	if err := demoexporter.Run(dctx, dcfg); err != nil {
		t.Fatal(err)
	}
	dstop()
	time.Sleep(300 * time.Millisecond)
	reg := col.Exporters()
	pstop()
	<-done // collector flushed → bus drained → writer flushed
	if wm.Flows() < 500 {
		t.Fatalf("only %d flows reached the writer", wm.Flows())
	}

	q := query.New(conn, query.Config{Storage: storage})
	tr := &wiring.Traffic{Q: q}
	now := time.Now().UTC()
	body, _ := json.Marshal(map[string]any{"start": now.Add(-10 * time.Minute), "end": now.Add(time.Minute), "points": 20,
		"dimensions": []string{"ExporterName"}, "limit": 10, "units": "l3bps", "graph": "stacked",
		"filter": "InIfBoundary = 'external'"})
	out, err := tr.Visualize(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	ts := out.(*query.TimeSeriesResponse)
	var names []string
	for _, r := range ts.Rows {
		names = append(names, r[0])
	}
	// sFlow carries no interface names, so dc-sw-01 has no "Transit:"
	// description to classify (Ledger names it in production).
	for _, want := range []string{"edge-01", "edge-02"} {
		if !slices.Contains(names, want) {
			t.Errorf("visualize rows %v: %s missing", names, want)
		}
	}

	// Exporters: ClickHouse aggregates merged with the collector registry.
	resp, err := q.Exporters(ctx, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	merged := wiring.MergeExporters(resp.Results, reg)
	if len(merged) != 3 {
		t.Fatalf("exporters: %+v", merged)
	}
	for _, e := range merged {
		named := e.Address == "127.0.0.13" || (len(e.Interfaces) > 0 && e.Interfaces[0].Name != "") // sFlow: no names, speeds only
		if len(e.SamplingRates) == 0 || len(e.Interfaces) == 0 || !named {
			t.Errorf("exporter %s: rates %v interfaces %+v", e.Address, e.SamplingRates, e.Interfaces)
		}
	}

	// Filter: validation error is a 400, value completion reads ClickHouse.
	if _, err := tr.Visualize(ctx, json.RawMessage(`{"filter":"Nope = 1","dimensions":[]}`)); err == nil {
		t.Error("bad filter accepted")
	} else if s, ok := err.(interface{ HTTPStatus() int }); !ok || s.HTTPStatus() != 400 {
		t.Errorf("bad filter: %v (want a 400)", err)
	}
	f := &wiring.Filter{Conn: conn, Storage: storage}
	c, err := f.Complete(ctx, json.RawMessage(`{"what":"value","column":"ExporterName","prefix":"edge"}`))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := json.Marshal(c)
	var comp struct {
		Completions []struct{ Label string } `json:"completions"`
	}
	_ = json.Unmarshal(cb, &comp)
	if len(comp.Completions) != 2 {
		t.Errorf("value completion: %s", cb)
	}
}
