// Package clickhouse stores flows in ClickHouse: schema migrations derived
// from the column registry (internal/schema), and a batching writer that
// implements flow.Sink.
package clickhouse

import (
	"fmt"
	"regexp"
	"time"
)

// Table names inside the configured database.
const (
	TableFlows         = "flows"
	TableSchemaVersion = "schema_version"
)

// Defaults for Config.
const (
	DefaultDatabase = "flow"
	DefaultRawTTL   = 15 * 24 * time.Hour
	Default1mTTL    = 30 * 24 * time.Hour
	Default5mTTL    = 90 * 24 * time.Hour
	Default1hTTL    = 730 * 24 * time.Hour
)

// Config describes where and how long flows are stored. It is shared by the
// migrations, the writer and the querier (internal/query).
type Config struct {
	Database string        // default "flow"
	RawTTL   time.Duration // flows; default 15 days
	TTL1m    time.Duration // flows_1m; default 30 days
	TTL5m    time.Duration // flows_5m; default 90 days
	TTL1h    time.Duration // flows_1h; default 730 days
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// WithDefaults returns c with zero fields replaced by the defaults.
func (c Config) WithDefaults() Config {
	if c.Database == "" {
		c.Database = DefaultDatabase
	}
	if c.RawTTL <= 0 {
		c.RawTTL = DefaultRawTTL
	}
	if c.TTL1m <= 0 {
		c.TTL1m = Default1mTTL
	}
	if c.TTL5m <= 0 {
		c.TTL5m = Default5mTTL
	}
	if c.TTL1h <= 0 {
		c.TTL1h = Default1hTTL
	}
	return c
}

// Validate checks the database name (it is inlined in SQL as an identifier).
func (c Config) Validate() error {
	if !identRe.MatchString(c.Database) {
		return fmt.Errorf("clickhouse: invalid database name %q", c.Database)
	}
	return nil
}

// Resolution is one aggregation level of the flows.
type Resolution struct {
	Name     string        // "raw", "1m", "5m", "1h"
	Table    string        // table name inside the database
	Interval time.Duration // 0 for raw
	TTL      time.Duration
}

// Raw returns the raw flows resolution.
func (c Config) Raw() Resolution {
	c = c.WithDefaults()
	return Resolution{Name: "raw", Table: TableFlows, TTL: c.RawTTL}
}

// Rollups returns the aggregated resolutions, finest first.
func (c Config) Rollups() []Resolution {
	c = c.WithDefaults()
	return []Resolution{
		{Name: "1m", Table: "flows_1m", Interval: time.Minute, TTL: c.TTL1m},
		{Name: "5m", Table: "flows_5m", Interval: 5 * time.Minute, TTL: c.TTL5m},
		{Name: "1h", Table: "flows_1h", Interval: time.Hour, TTL: c.TTL1h},
	}
}

// QuoteIdent quotes a ClickHouse identifier with backquotes.
func QuoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '`')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '`', '\\':
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(append(out, '`'))
}

// Table returns the fully qualified, quoted name of a table.
func (c Config) Table(name string) string {
	c = c.WithDefaults()
	return QuoteIdent(c.Database) + "." + QuoteIdent(name)
}
