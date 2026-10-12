package clickhouse

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

func TestEveryColumnHasBuilder(t *testing.T) {
	names, bs, err := insertColumns()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(schema.Columns) || len(bs) != len(names) {
		t.Fatalf("got %d columns, want %d", len(names), len(schema.Columns))
	}
	for name := range builders {
		if _, ok := schema.ByName(name); !ok {
			t.Errorf("builder for unknown column %s", name)
		}
	}
}

func TestBuildersConvert(t *testing.T) {
	f := &flow.Flow{
		SamplingRate:    0,
		Bytes:           100,
		Packets:         2,
		ExporterAddress: netip.MustParseAddr("192.0.2.1"),
		SrcNetPrefix:    netip.MustParsePrefix("10.1.2.3/8"),
	}
	fs := []*flow.Flow{f}
	if got := builders["Bytes"](fs).([]uint64)[0]; got != 100 {
		t.Errorf("bytes with rate 0 = %d, want 100", got)
	}
	f.SamplingRate = 10
	if got := builders["Bytes"](fs).([]uint64)[0]; got != 1000 {
		t.Errorf("bytes with rate 10 = %d", got)
	}
	if got := builders["Packets"](fs).([]uint64)[0]; got != 20 {
		t.Errorf("packets = %d", got)
	}
	if got := builders["ExporterAddress"](fs).([]netip.Addr)[0]; got.String() != "::ffff:192.0.2.1" {
		t.Errorf("exporter = %s", got)
	}
	if got := builders["SrcAddr"](fs).([]netip.Addr)[0]; got.String() != "::" {
		t.Errorf("invalid addr = %s", got)
	}
	if got := builders["SrcNetPrefix"](fs).([]string)[0]; got != "10.0.0.0/8" {
		t.Errorf("prefix = %q", got)
	}
	if got := builders["DstNetPrefix"](fs).([]string)[0]; got != "" {
		t.Errorf("empty prefix = %q", got)
	}
}

func TestDDL(t *testing.T) {
	cfg := Config{Database: "x", RawTTL: 48 * time.Hour}
	raw := RawTableDDL(cfg)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS `x`.`flows`",
		"PARTITION BY toYYYYMMDD(TimeReceived)",
		"ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName, TimeReceived)",
		"TTL TimeReceived + toIntervalSecond(172800)",
		"`SrcAddr` IPv6",
		"`TimeReceived` DateTime CODEC(DoubleDelta, LZ4)",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("raw DDL lacks %q:\n%s", want, raw)
		}
	}
	r := cfg.Rollups()[2]
	agg := RollupTableDDL(cfg, r)
	for _, want := range []string{
		"`x`.`flows_1h`", "SummingMergeTree((Bytes, Packets))", "toYYYYMM(TimeReceived)",
		"TTL TimeReceived + toIntervalSecond(63072000)", "`SrcAS` UInt32",
	} {
		if !strings.Contains(agg, want) {
			t.Errorf("rollup DDL lacks %q:\n%s", want, agg)
		}
	}
	for _, c := range schema.Columns {
		if !c.Rollup && !c.Metric && c.Name != "TimeReceived" && strings.Contains(agg, "`"+c.Name+"` ") {
			t.Errorf("rollup DDL has non-rollup column %s", c.Name)
		}
	}
	mv := MVDDL(cfg, r)
	if !strings.Contains(mv, "TO `x`.`flows_1h` AS SELECT toStartOfInterval(TimeReceived, INTERVAL 3600 SECOND) AS TimeReceived") ||
		strings.Contains(mv, "`SrcAddr`") {
		t.Errorf("MV DDL:\n%s", mv)
	}
}

func TestConfig(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.Database != "flow" || c.RawTTL != 15*24*time.Hour || c.TTL1h != 730*24*time.Hour {
		t.Errorf("defaults %+v", c)
	}
	if err := (Config{Database: "a;drop"}).Validate(); err == nil {
		t.Error("bad database name accepted")
	}
	if QuoteIdent("a`b") != "`a\\`b`" {
		t.Error(QuoteIdent("a`b"))
	}
}
