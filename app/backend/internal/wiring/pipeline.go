package wiring

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/bus"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

// Pipeline runs the bus with its producer (collector) and consumer
// (enricher → writer), whichever this process has, and stops them in order.
type Pipeline struct {
	Bus       bus.Bus
	Collector *collector.Collector // nil when this process does not collect
	Consumer  flow.Sink            // nil when this process does not enrich
	Writer    *chstore.Writer      // closed after the consumer stopped
	Log       *slog.Logger
	// CloseTimeout bounds the final writer flush (default 30 s).
	CloseTimeout time.Duration
}

// Run blocks until ctx is done and everything has stopped. Shutdown order:
// the collector stops and flushes into the bus first; only then the bus
// consumer is cancelled (the in-process bus drains its buffer), then the
// writer flushes to ClickHouse, then the bus is closed.
func (p *Pipeline) Run(ctx context.Context) {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	colDone := make(chan struct{})
	if p.Collector != nil {
		go func() {
			defer close(colDone)
			if err := p.Collector.Run(ctx); err != nil {
				log.Error("collector stopped", "err", err)
			}
		}()
	} else {
		close(colDone)
	}
	if p.Consumer != nil {
		cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		go func() {
			select {
			case <-ctx.Done():
			case <-cctx.Done():
				return
			}
			<-colDone
			cancel()
		}()
		for {
			err := p.Bus.Consume(cctx, p.Consumer)
			if cctx.Err() != nil {
				break
			}
			log.Error("bus consumer stopped, retrying", "err", err)
			select {
			case <-cctx.Done():
			case <-time.After(5 * time.Second):
			}
			if cctx.Err() != nil {
				break
			}
		}
		cancel()
		if p.Writer != nil {
			d := p.CloseTimeout
			if d <= 0 {
				d = 30 * time.Second
			}
			wctx, wcancel := context.WithTimeout(context.Background(), d)
			if err := p.Writer.Close(wctx); err != nil {
				log.Error("ClickHouse writer closed with flows lost", "err", err)
			}
			wcancel()
		}
	}
	<-colDone
	if err := p.Bus.Close(); err != nil {
		log.Warn("bus close", "err", err)
	}
}
