package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// ddlContext adds the settings our DDL needs: the registry uses
// LowCardinality(IPv6), which ClickHouse rejects by default, and changing a
// TTL must not rewrite every part synchronously.
func ddlContext(ctx context.Context) context.Context {
	return ch.Context(ctx, ch.WithSettings(ch.Settings{
		"allow_suspicious_low_cardinality_types": 1,
		"materialize_ttl_after_modify":           0,
	}))
}

// Migrate creates or upgrades the database, the raw table, the aggregated
// tables and their materialized views. It is idempotent: columns added to
// the registry are added with ALTER TABLE (and to the aggregated tables'
// sorting key), TTL changes are applied, and materialized views whose query
// changed are recreated.
func Migrate(ctx context.Context, conn driver.Conn, cfg Config) error {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	ctx = ddlContext(ctx)
	exec := func(q string, args ...any) error {
		if err := conn.Exec(ctx, q, args...); err != nil {
			return fmt.Errorf("clickhouse migrate: %w\nquery: %s", err, q)
		}
		return nil
	}
	if err := exec("CREATE DATABASE IF NOT EXISTS " + QuoteIdent(cfg.Database)); err != nil {
		return err
	}
	if err := exec(SchemaVersionDDL(cfg)); err != nil {
		return err
	}
	stored, err := readVersions(ctx, conn, cfg)
	if err != nil {
		return err
	}
	expected := expectedObjects(cfg)
	record := func(object string) error {
		if stored[object] == expected[object] {
			return nil
		}
		return exec(fmt.Sprintf("INSERT INTO %s (object, hash, version, applied_at) VALUES (?, ?, ?, now64(3))",
			cfg.Table(TableSchemaVersion)), object, expected[object], uint32(SchemaVersion))
	}

	// Raw table.
	if err := exec(RawTableDDL(cfg)); err != nil {
		return err
	}
	if err := syncColumns(ctx, conn, cfg, TableFlows, RawColumns(), false); err != nil {
		return err
	}
	if stored[TableFlows] != expected[TableFlows] {
		if err := exec(fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s", cfg.Table(TableFlows), ttlExpr(cfg.RawTTL))); err != nil {
			return err
		}
	}
	if err := record(TableFlows); err != nil {
		return err
	}

	// Aggregated tables, then their views.
	for _, r := range cfg.Rollups() {
		if err := exec(RollupTableDDL(cfg, r)); err != nil {
			return err
		}
		if err := syncColumns(ctx, conn, cfg, r.Table, RollupColumns(), true); err != nil {
			return err
		}
		if stored[r.Table] != expected[r.Table] {
			if err := exec(fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s", cfg.Table(r.Table), ttlExpr(r.TTL))); err != nil {
				return err
			}
		}
		if err := record(r.Table); err != nil {
			return err
		}

		mv := MVName(r)
		exists, err := tableExists(ctx, conn, cfg, mv)
		if err != nil {
			return err
		}
		if !exists || stored[mv] != expected[mv] {
			if err := exec("DROP VIEW IF EXISTS " + cfg.Table(mv)); err != nil {
				return err
			}
			if err := exec(MVDDL(cfg, r)); err != nil {
				return err
			}
		}
		if err := record(mv); err != nil {
			return err
		}
	}
	return nil
}

type existingColumn struct{ name, typ string }

func listColumns(ctx context.Context, conn driver.Conn, cfg Config, table string) ([]existingColumn, error) {
	rows, err := conn.Query(ctx, "SELECT name, type FROM system.columns WHERE database = ? AND table = ? ORDER BY position", cfg.Database, table)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: list columns of %s: %w", table, err)
	}
	defer rows.Close()
	var out []existingColumn
	for rows.Next() {
		var c existingColumn
		if err := rows.Scan(&c.name, &c.typ); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func tableExists(ctx context.Context, conn driver.Conn, cfg Config, table string) (bool, error) {
	var n uint64
	err := conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = ?", cfg.Database, table).Scan(&n)
	return n > 0, err
}

// syncColumns adds missing columns (keeping registry order with AFTER) and
// fixes changed types. For the aggregated tables the new dimension columns
// are also appended to the sorting key, which ClickHouse allows only in the
// same ALTER that adds them.
func syncColumns(ctx context.Context, conn driver.Conn, cfg Config, table string, want []schema.Column, extendKey bool) error {
	have, err := listColumns(ctx, conn, cfg, table)
	if err != nil {
		return err
	}
	haveType := make(map[string]string, len(have))
	for _, c := range have {
		haveType[c.name] = c.typ
	}
	var adds, newKeys, modifies []string
	prev := ""
	for _, c := range want {
		t, ok := haveType[c.Name]
		switch {
		case !ok:
			clause := "ADD COLUMN IF NOT EXISTS " + columnDef(c)
			if prev != "" {
				clause += " AFTER " + QuoteIdent(prev)
			} else {
				clause += " FIRST"
			}
			adds = append(adds, clause)
			if extendKey && !c.Metric && c.Kind != schema.KindTime {
				newKeys = append(newKeys, QuoteIdent(c.Name))
			}
		case normType(t) != normType(c.Type):
			modifies = append(modifies, "MODIFY COLUMN "+QuoteIdent(c.Name)+" "+c.Type)
		}
		prev = c.Name
	}
	if len(adds) > 0 {
		clauses := adds
		if len(newKeys) > 0 {
			var key string
			if err := conn.QueryRow(ctx, "SELECT sorting_key FROM system.tables WHERE database = ? AND name = ?", cfg.Database, table).Scan(&key); err != nil {
				return fmt.Errorf("clickhouse: sorting key of %s: %w", table, err)
			}
			clauses = append(clauses, fmt.Sprintf("MODIFY ORDER BY (%s, %s)", key, strings.Join(newKeys, ", ")))
		}
		q := fmt.Sprintf("ALTER TABLE %s %s", cfg.Table(table), strings.Join(clauses, ", "))
		if err := conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("clickhouse migrate: %w\nquery: %s", err, q)
		}
	}
	for _, m := range modifies {
		q := fmt.Sprintf("ALTER TABLE %s %s", cfg.Table(table), m)
		if err := conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("clickhouse migrate: %w\nquery: %s", err, q)
		}
	}
	return nil
}

func readVersions(ctx context.Context, conn driver.Conn, cfg Config) (map[string]string, error) {
	rows, err := conn.Query(ctx, fmt.Sprintf("SELECT object, argMax(hash, applied_at) FROM %s GROUP BY object", cfg.Table(TableSchemaVersion)))
	if err != nil {
		return nil, fmt.Errorf("clickhouse: read schema_version: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var o, h string
		if err := rows.Scan(&o, &h); err != nil {
			return nil, err
		}
		out[o] = h
	}
	return out, rows.Err()
}

// ErrSchemaOutdated is wrapped by Check when Migrate needs to run.
var ErrSchemaOutdated = errors.New("clickhouse: schema is outdated, run migrations")

// Check verifies, without changing anything, that the schema matches the
// registry and the configured TTLs. The error wraps ErrSchemaOutdated and
// lists the objects that differ.
func Check(ctx context.Context, conn driver.Conn, cfg Config) error {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if ok, err := tableExists(ctx, conn, cfg, TableSchemaVersion); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: %s missing", ErrSchemaOutdated, TableSchemaVersion)
	}
	stored, err := readVersions(ctx, conn, cfg)
	if err != nil {
		return err
	}
	var bad []string
	for obj, h := range expectedObjects(cfg) {
		if stored[obj] != h {
			bad = append(bad, obj)
		}
	}
	checkCols := func(table string, want []schema.Column) error {
		have, err := listColumns(ctx, conn, cfg, table)
		if err != nil {
			return err
		}
		m := map[string]string{}
		for _, c := range have {
			m[c.name] = c.typ
		}
		for _, c := range want {
			if t, ok := m[c.Name]; !ok || normType(t) != normType(c.Type) {
				bad = append(bad, table+"."+c.Name)
			}
		}
		return nil
	}
	if err := checkCols(TableFlows, RawColumns()); err != nil {
		return err
	}
	for _, r := range cfg.Rollups() {
		if err := checkCols(r.Table, RollupColumns()); err != nil {
			return err
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("%w: %s", ErrSchemaOutdated, strings.Join(bad, ", "))
	}
	return nil
}
