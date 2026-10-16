package bus

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// InProcessConfig configures the in-process bus.
type InProcessConfig struct {
	// Size is the number of batches buffered; Put blocks when full, which
	// pushes back on the collector (whose UDP queues then drop and count).
	Size int
	// Workers is the number of goroutines calling the consumer sink.
	Workers int
	// RetryDelay is the pause before redelivering a refused batch.
	RetryDelay time.Duration
	// DrainTimeout bounds delivering what is still buffered once Consume's
	// context is canceled.
	DrainTimeout time.Duration
}

// InProcess is a bounded channel with the Bus shape, for single-binary mode.
type InProcess struct {
	cfg InProcessConfig
	ch  chan []*flow.Flow
	m   *metrics
	log *slog.Logger
}

// NewInProcess creates an in-process bus; reg may be nil.
func NewInProcess(cfg InProcessConfig, reg prometheus.Registerer, log *slog.Logger) *InProcess {
	if cfg.Size <= 0 {
		cfg.Size = 256
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = time.Second
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = 5 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &InProcess{
		cfg: cfg,
		ch:  make(chan []*flow.Flow, cfg.Size),
		m:   newMetrics(reg, "inprocess"),
		log: log.With("component", "bus", "bus", "inprocess"),
	}
}

// Put enqueues a copy of the batch, waiting for room until ctx is done.
func (b *InProcess) Put(ctx context.Context, flows []*flow.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	batch := append([]*flow.Flow(nil), flows...) // the caller reuses its slice
	select {
	case b.ch <- batch:
		b.m.publishedBatches.Inc()
		b.m.publishedFlows.Add(float64(len(batch)))
		return nil
	case <-ctx.Done():
		b.m.publishErrors.Inc()
		return ctx.Err()
	}
}

// Consume runs the workers until ctx is canceled, then drains the buffer.
// Deliveries (and the drain) may outlive ctx by at most DrainTimeout.
func (b *InProcess) Consume(ctx context.Context, sink flow.Sink) error {
	deliverCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		t := time.AfterFunc(b.cfg.DrainTimeout, cancel)
		context.AfterFunc(deliverCtx, func() { t.Stop() })
	})
	defer stop()

	var wg sync.WaitGroup
	for range b.cfg.Workers {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case batch := <-b.ch:
					b.deliver(deliverCtx, sink, batch)
				}
			}
		})
	}
	wg.Wait()

	for deliverCtx.Err() == nil {
		select {
		case batch := <-b.ch:
			b.deliver(deliverCtx, sink, batch)
		default:
			return nil
		}
	}
	if n := len(b.ch); n > 0 {
		b.log.Warn("drain timeout, batches left in buffer", "batches", n)
	}
	return nil
}

// deliver calls the sink until it accepts the batch or ctx ends.
func (b *InProcess) deliver(ctx context.Context, sink flow.Sink, batch []*flow.Flow) {
	for {
		err := sink.Put(ctx, batch)
		if err == nil {
			b.m.consumedBatches.Inc()
			b.m.consumedFlows.Add(float64(len(batch)))
			return
		}
		b.m.retries.Inc()
		b.log.Warn("sink refused batch, retrying", "flows", len(batch), "err", err)
		t := time.NewTimer(b.cfg.RetryDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			b.log.Warn("batch dropped on shutdown", "flows", len(batch))
			return
		case <-t.C:
		}
	}
}

// Close is a no-op: the channel is garbage collected with the bus.
func (b *InProcess) Close() error { return nil }
