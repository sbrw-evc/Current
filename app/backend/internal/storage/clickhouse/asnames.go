package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// TableASNames holds the AS names the enrichers learned from GeoIP, so that
// processes without GeoIP (the api role) can name ASes in labels.
const TableASNames = "asn_names"

// ASNamesDDL is the CREATE statement of the AS names table. One row per AS
// survives the merges: the most recently updated name.
func ASNamesDDL(cfg Config) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    asn UInt32,
    name String,
    updated_at DateTime64(9)
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asn`, cfg.WithDefaults().Table(TableASNames))
}

// EnsureASNames creates the AS names table (Migrate does it too; this is for
// processes that write or read the table without migrating).
func EnsureASNames(ctx context.Context, conn driver.Conn, cfg Config) error {
	if err := conn.Exec(ctx, ASNamesDDL(cfg)); err != nil {
		return fmt.Errorf("clickhouse: create %s: %w", TableASNames, err)
	}
	return nil
}

// WriteASNames stores AS names (empty names and AS 0 are skipped).
func WriteASNames(ctx context.Context, conn driver.Conn, cfg Config, names map[uint32]string, now time.Time) error {
	if len(names) == 0 {
		return nil
	}
	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf("INSERT INTO %s (asn, name, updated_at)", cfg.WithDefaults().Table(TableASNames)))
	if err != nil {
		return fmt.Errorf("clickhouse: %s: %w", TableASNames, err)
	}
	n := 0
	for asn, name := range names {
		if asn == 0 || name == "" {
			continue
		}
		if err := batch.Append(asn, name, now.UTC()); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("clickhouse: %s: %w", TableASNames, err)
		}
		n++
	}
	if n == 0 {
		_ = batch.Abort()
		return nil
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("clickhouse: %s: %w", TableASNames, err)
	}
	return nil
}

// ReadASNames returns every stored AS name (the latest per AS).
func ReadASNames(ctx context.Context, conn driver.Conn, cfg Config) (map[uint32]string, error) {
	rows, err := conn.Query(ctx, fmt.Sprintf("SELECT asn, argMax(name, updated_at) FROM %s GROUP BY asn",
		cfg.WithDefaults().Table(TableASNames)))
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %s: %w", TableASNames, err)
	}
	defer rows.Close()
	out := map[uint32]string{}
	for rows.Next() {
		var asn uint32
		var name string
		if err := rows.Scan(&asn, &name); err != nil {
			return nil, err
		}
		out[asn] = name
	}
	return out, rows.Err()
}
