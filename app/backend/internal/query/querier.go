package query

import (
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
)

// Config of the Querier.
type Config struct {
	// Storage is the same configuration the migrations ran with: database
	// name and table TTLs (used to choose the resolution).
	Storage chstore.Config
	// ASName optionally names ASes in labels ("AS65000 Example").
	ASName ASNamer
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
}

// Querier runs the read queries.
type Querier struct {
	conn   driver.Conn
	store  chstore.Config
	asName ASNamer
	now    func() time.Time
}

// New returns a Querier over conn.
func New(conn driver.Conn, cfg Config) *Querier {
	q := &Querier{conn: conn, store: cfg.Storage.WithDefaults(), asName: cfg.ASName, now: cfg.Now}
	if q.now == nil {
		q.now = time.Now
	}
	return q
}

func (q *Querier) table(r chstore.Resolution) string { return q.store.Table(r.Table) }
