package clickhouse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/schema"
)

// SchemaVersion is bumped on structural changes that the column diff does
// not cover (engines, keys). Column additions are handled automatically.
const SchemaVersion = 1

// RawColumns returns the columns of the raw flows table, in table order.
func RawColumns() []schema.Column { return schema.Columns }

// RollupColumns returns the columns of the aggregated tables: TimeReceived,
// every Rollup column, then the metrics.
func RollupColumns() []schema.Column {
	var out []schema.Column
	for _, c := range schema.Columns {
		if c.Name == "TimeReceived" || c.Rollup || c.Metric {
			out = append(out, c)
		}
	}
	return out
}

// rollupKeyColumns are the dimension columns of the aggregated tables (the
// SummingMergeTree key besides TimeReceived).
func rollupKeyColumns() []string {
	var out []string
	for _, c := range schema.Columns {
		if c.Rollup && !c.Metric {
			out = append(out, c.Name)
		}
	}
	return out
}

func columnDef(c schema.Column) string {
	def := QuoteIdent(c.Name) + " " + c.Type
	if c.Kind == schema.KindTime {
		def += " CODEC(DoubleDelta, LZ4)"
	}
	return def
}

func ttlExpr(ttl time.Duration) string {
	return fmt.Sprintf("TimeReceived + toIntervalSecond(%d)", int64(ttl/time.Second))
}

func columnsDDL(cols []schema.Column) string {
	defs := make([]string, len(cols))
	for i, c := range cols {
		defs[i] = "    " + columnDef(c)
	}
	return strings.Join(defs, ",\n")
}

// RawTableDDL is the CREATE statement of the raw flows table.
func RawTableDDL(cfg Config) string {
	cfg = cfg.WithDefaults()
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
%s
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(TimeReceived)
PRIMARY KEY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName)
ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName, TimeReceived)
TTL %s
SETTINGS ttl_only_drop_parts = 1`,
		cfg.Table(TableFlows), columnsDDL(RawColumns()), ttlExpr(cfg.RawTTL))
}

func partitionFor(r Resolution) string {
	if r.Interval >= time.Hour {
		return "toYYYYMM(TimeReceived)"
	}
	return "toYYYYMMDD(TimeReceived)"
}

// RollupTableDDL is the CREATE statement of one aggregated table.
func RollupTableDDL(cfg Config, r Resolution) string {
	keys := append([]string{"TimeReceived"}, rollupKeyColumns()...)
	pk := keys
	if len(pk) > 3 {
		pk = pk[:3]
	}
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
%s
) ENGINE = SummingMergeTree((Bytes, Packets))
PARTITION BY %s
PRIMARY KEY (%s)
ORDER BY (%s)
TTL %s
SETTINGS ttl_only_drop_parts = 1`,
		cfg.Table(r.Table), columnsDDL(RollupColumns()), partitionFor(r),
		strings.Join(pk, ", "), strings.Join(keys, ", "), ttlExpr(r.TTL))
}

// MVName is the materialized view feeding an aggregated table.
func MVName(r Resolution) string { return r.Table + "_mv" }

// RollupSelect is the SELECT of the materialized view feeding r.
func RollupSelect(cfg Config, r Resolution) string {
	parts := []string{fmt.Sprintf("toStartOfInterval(TimeReceived, INTERVAL %d SECOND) AS TimeReceived", int64(r.Interval/time.Second))}
	for _, k := range rollupKeyColumns() {
		parts = append(parts, QuoteIdent(k))
	}
	parts = append(parts, "sum(Bytes) AS Bytes", "sum(Packets) AS Packets")
	return fmt.Sprintf("SELECT %s FROM %s GROUP BY ALL", strings.Join(parts, ", "), cfg.Table(TableFlows))
}

// MVDDL is the CREATE statement of the materialized view feeding r.
func MVDDL(cfg Config, r Resolution) string {
	return fmt.Sprintf("CREATE MATERIALIZED VIEW IF NOT EXISTS %s TO %s AS %s",
		cfg.Table(MVName(r)), cfg.Table(r.Table), RollupSelect(cfg, r))
}

// SchemaVersionDDL is the CREATE statement of the migration bookkeeping table.
func SchemaVersionDDL(cfg Config) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    object String,
    hash String,
    version UInt32,
    applied_at DateTime64(3)
) ENGINE = ReplacingMergeTree(applied_at)
ORDER BY object`, cfg.Table(TableSchemaVersion))
}

func hashOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// columnsHash fingerprints a column list (names and types).
func columnsHash(cols []schema.Column) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, c.Name+" "+c.Type)
	}
	return hashOf(parts...)
}

// expectedObjects maps each bookkept object to its expected fingerprint.
func expectedObjects(cfg Config) map[string]string {
	cfg = cfg.WithDefaults()
	v := fmt.Sprint(SchemaVersion)
	out := map[string]string{
		TableFlows: hashOf(v, columnsHash(RawColumns()), ttlExpr(cfg.RawTTL)),
	}
	for _, r := range cfg.Rollups() {
		out[r.Table] = hashOf(v, columnsHash(RollupColumns()), ttlExpr(r.TTL))
		out[MVName(r)] = hashOf(v, RollupSelect(cfg, r))
	}
	return out
}

func normType(t string) string { return strings.ReplaceAll(t, " ", "") }
