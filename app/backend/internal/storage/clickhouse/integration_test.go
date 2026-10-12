package clickhouse_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

func TestMigrateIdempotentAndUpgrade(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}

	// Start from an "older" registry without App and SrcCity.
	full := schema.Columns
	var old []schema.Column
	for _, c := range full {
		if c.Name != "App" && c.Name != "SrcCity" {
			old = append(old, c)
		}
	}
	schema.Columns = old
	err := chstore.Migrate(ctx, conn, cfg)
	if err == nil {
		err = chstore.Migrate(ctx, conn, cfg) // idempotent
	}
	if err == nil {
		err = chstore.Check(ctx, conn, cfg)
	}
	schema.Columns = full
	if err != nil {
		t.Fatal(err)
	}

	// The current registry has more columns: Check reports it, Migrate fixes it.
	if err := chstore.Check(ctx, conn, cfg); !errors.Is(err, chstore.ErrSchemaOutdated) {
		t.Fatalf("check after registry change: %v", err)
	}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	if err := chstore.Check(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	var key, mv string
	if err := conn.QueryRow(ctx, "SELECT sorting_key FROM system.tables WHERE database = ? AND name = 'flows_1m'", db).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if len(key) < 5 || key[len(key)-3:] != "App" {
		t.Errorf("flows_1m sorting key not extended: %s", key)
	}
	if err := conn.QueryRow(ctx, "SELECT as_select FROM system.tables WHERE database = ? AND name = 'flows_1m_mv'", db).Scan(&mv); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mv, "App") {
		t.Errorf("MV not recreated with App: %s", mv)
	}

	// A TTL change is applied.
	cfg.RawTTL = 3 * 24 * time.Hour
	if err := chstore.Check(ctx, conn, cfg); !errors.Is(err, chstore.ErrSchemaOutdated) {
		t.Fatalf("check after TTL change: %v", err)
	}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	var engine string
	if err := conn.QueryRow(ctx, "SELECT engine_full FROM system.tables WHERE database = ? AND name = 'flows'", db).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(engine, "toIntervalSecond(259200)") {
		t.Errorf("TTL not changed: %s", engine)
	}
}

func TestWriterRoundTrip(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	w, err := chstore.NewWriter(conn, cfg, chstore.WriterConfig{BatchSize: 3, MaxDelay: 50 * time.Millisecond}, reg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var fs []*flow.Flow
	for i := 0; i < 7; i++ {
		fs = append(fs, &flow.Flow{
			TimeReceived:    now,
			SamplingRate:    uint64(i % 2 * 100), // 0 → 1, 100
			ExporterAddress: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:         netip.MustParseAddr("10.0.0.1"),
			DstAddr:         netip.MustParseAddr("2001:db8::1"),
			SrcNetPrefix:    netip.MustParsePrefix("10.0.0.0/8"),
			SrcAS:           65000,
			Proto:           6,
			InIf:            7,
			InIfName:        "xe-0/0/0",
			Bytes:           10,
			Packets:         1,
			App:             "https",
		})
	}
	if err := w.Put(ctx, fs[:5]); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(ctx, fs[5:]); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := w.Close(cctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(ctx, fs); !errors.Is(err, chstore.ErrClosed) {
		t.Errorf("put after close: %v", err)
	}

	var n, bytes, packets uint64
	var exp, src, dst, prefix string
	var inIf uint32
	err = conn.QueryRow(ctx, "SELECT count(), sum(Bytes), sum(Packets), toString(any(ExporterAddress)), toString(any(SrcAddr)), toString(any(DstAddr)), any(SrcNetPrefix), any(InIfIndex) FROM "+cfg.Table("flows")).
		Scan(&n, &bytes, &packets, &exp, &src, &dst, &prefix, &inIf)
	if err != nil {
		t.Fatal(err)
	}
	// 4 flows at rate 1 (0 → 1), 3 at rate 100.
	if n != 7 || bytes != 4*10+3*1000 || packets != 4+300 {
		t.Errorf("count %d bytes %d packets %d", n, bytes, packets)
	}
	if exp != "::ffff:192.0.2.1" || src != "::ffff:10.0.0.1" || dst != "2001:db8::1" || prefix != "10.0.0.0/8" || inIf != 7 {
		t.Errorf("values %s %s %s %s %d", exp, src, dst, prefix, inIf)
	}
	for _, tbl := range []string{"flows_1m", "flows_5m", "flows_1h"} {
		var b uint64
		if err := conn.QueryRow(ctx, "SELECT sum(Bytes) FROM "+cfg.Table(tbl)+" WHERE App = 'https' AND SrcAS = 65000").Scan(&b); err != nil {
			t.Fatal(err)
		}
		if b != 3040 {
			t.Errorf("%s bytes = %d", tbl, b)
		}
	}
	if got := metric(t, reg, "flow_clickhouse_writer_rows_written_total"); got != 7 {
		t.Errorf("rows_written = %v", got)
	}
}

func metric(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			m := mf.GetMetric()[0]
			if m.Counter != nil {
				return m.Counter.GetValue()
			}
			return m.Gauge.GetValue()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

// TestWriterDropsWhenDown needs no server: inserts to a closed port fail,
// the queue fills up and the overflow is dropped and counted.
func TestWriterDropsWhenDown(t *testing.T) {
	conn, err := ch.Open(&ch.Options{Addr: []string{"127.0.0.1:1"}, DialTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reg := prometheus.NewRegistry()
	w, err := chstore.NewWriter(conn, chstore.Config{Database: "nowhere"}, chstore.WriterConfig{
		BatchSize: 2, QueueSize: 4, MaxDelay: 10 * time.Millisecond, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	fs := make([]*flow.Flow, 10)
	for i := range fs {
		fs[i] = &flow.Flow{TimeReceived: time.Now()}
	}
	if err := w.Put(context.Background(), fs); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := metric(t, reg, "flow_clickhouse_writer_dropped_total"); got != 6 {
		t.Errorf("dropped = %v, want 6", got)
	}
	if got := metric(t, reg, "flow_clickhouse_writer_errors_total"); got < 1 {
		t.Errorf("errors = %v", got)
	}
	if got := metric(t, reg, "flow_clickhouse_writer_queue_length"); got != 4 {
		t.Errorf("queue length = %v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := w.Close(ctx); err == nil {
		t.Error("close with unwritable flows returned nil")
	}
	if got := metric(t, reg, "flow_clickhouse_writer_dropped_total"); got != 10 {
		t.Errorf("dropped after close = %v, want 10", got)
	}
}
