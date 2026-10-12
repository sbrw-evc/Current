package wiring

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

// ASNamesFlush is how often learned AS names are written to ClickHouse.
const ASNamesFlush = time.Minute

// RangeASNames calls fn for every AS name learned from GeoIP lookups.
func (g *GeoSwap) RangeASNames(fn func(asn uint32, name string)) {
	g.names.Range(func(k, v any) bool {
		fn(k.(uint32), v.(string))
		return true
	})
}

// ASNamePersister writes the AS names the enricher learns from GeoIP into
// the ClickHouse table asn_names, so that the api role (and any process
// without GeoIP) names ASes in labels through query.ASNames.
type ASNamePersister struct {
	Geo      *GeoSwap
	Conn     driver.Conn
	Storage  chstore.Config
	Interval time.Duration // default ASNamesFlush
	Log      *slog.Logger
	Now      func() time.Time

	written map[uint32]string
}

// Flush writes the names that are new or changed since the last flush.
func (p *ASNamePersister) Flush(ctx context.Context) (int, error) {
	if p.written == nil {
		p.written = map[uint32]string{}
	}
	fresh := map[uint32]string{}
	p.Geo.RangeASNames(func(asn uint32, name string) {
		if p.written[asn] != name {
			fresh[asn] = name
		}
	})
	if len(fresh) == 0 {
		return 0, nil
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	if err := chstore.WriteASNames(ctx, p.Conn, p.Storage, fresh, now()); err != nil {
		return 0, err
	}
	for k, v := range fresh {
		p.written[k] = v
	}
	return len(fresh), nil
}

// Run flushes every Interval until ctx ends, then once more.
func (p *ASNamePersister) Run(ctx context.Context) {
	every := p.Interval
	if every <= 0 {
		every = ASNamesFlush
	}
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	ready := false
	failing := false
	for {
		select {
		case <-ctx.Done():
			if ready {
				fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, _ = p.Flush(fctx)
				cancel()
			}
			return
		case <-t.C:
		}
		var err error
		if !ready {
			if err = chstore.EnsureASNames(ctx, p.Conn, p.Storage); err == nil {
				ready = true
			}
		}
		if ready {
			var n int
			if n, err = p.Flush(ctx); err == nil && n > 0 {
				log.Debug("AS names stored", "count", n)
			}
		}
		if err != nil && !failing {
			log.Warn("AS names not stored in ClickHouse", "err", err)
		}
		failing = err != nil
	}
}
