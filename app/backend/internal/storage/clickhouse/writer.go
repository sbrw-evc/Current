package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// WriterConfig tunes the batching writer.
type WriterConfig struct {
	BatchSize     int           // flows per INSERT; default 50000
	MaxDelay      time.Duration // max time a flow waits before being sent; default 5s
	QueueSize     int           // max flows held in memory (incl. the batch being sent); default 1000000
	MinBackoff    time.Duration // first retry delay; default 200ms
	MaxBackoff    time.Duration // retry delay cap; default 30s
	InsertTimeout time.Duration // timeout of one INSERT; default 60s
	Logger        *slog.Logger  // default slog.Default()
}

func (c WriterConfig) withDefaults() WriterConfig {
	if c.BatchSize <= 0 {
		c.BatchSize = 50000
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = 5 * time.Second
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1000000
	}
	if c.QueueSize < c.BatchSize {
		c.QueueSize = c.BatchSize
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = 200 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.InsertTimeout <= 0 {
		c.InsertTimeout = 60 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// ErrClosed is returned by Put after Close.
var ErrClosed = errors.New("clickhouse writer: closed")

// Writer batches flows into the raw flows table. It implements flow.Sink.
// Put never blocks on ClickHouse: flows are queued in memory, and when the
// queue is full (ClickHouse down or too slow) new flows are dropped and
// counted.
type Writer struct {
	conn   driver.Conn
	cfg    WriterConfig
	insert string
	build  []builder

	mu       sync.Mutex
	queue    []*flow.Flow
	inflight int
	closed   bool
	closeCtx context.Context
	lost     int // flows of the batch abandoned on close

	wake    chan struct{}
	closing chan struct{}
	done    chan struct{}

	rows, batches, errs, drops prometheus.Counter
	queueLen                   prometheus.Gauge
}

// NewWriter starts a writer. reg may be nil (no metrics registered).
func NewWriter(conn driver.Conn, cfg Config, wc WriterConfig, reg prometheus.Registerer) (*Writer, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	names, bs, err := insertColumns()
	if err != nil {
		return nil, err
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = QuoteIdent(n)
	}
	w := &Writer{
		conn:    conn,
		cfg:     wc.withDefaults(),
		insert:  fmt.Sprintf("INSERT INTO %s (%s)", cfg.Table(TableFlows), strings.Join(quoted, ", ")),
		build:   bs,
		wake:    make(chan struct{}, 1),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
		rows: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "clickhouse_writer", Name: "rows_written_total",
			Help: "Flows written to ClickHouse.",
		}),
		batches: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "clickhouse_writer", Name: "batches_total",
			Help: "Batches successfully inserted into ClickHouse.",
		}),
		errs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "clickhouse_writer", Name: "errors_total",
			Help: "Failed INSERT attempts (each is retried).",
		}),
		drops: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "clickhouse_writer", Name: "dropped_total",
			Help: "Flows dropped because the queue was full or the writer was closed before they could be written.",
		}),
		queueLen: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "flow", Subsystem: "clickhouse_writer", Name: "queue_length",
			Help: "Flows waiting to be written, including the batch being sent.",
		}),
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{w.rows, w.batches, w.errs, w.drops, w.queueLen} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("clickhouse writer: register metrics: %w", err)
			}
		}
	}
	go w.run()
	return w, nil
}

// Put queues flows. It returns ErrClosed after Close; flows that do not fit
// in the queue are dropped (counted) without error.
func (w *Writer) Put(_ context.Context, flows []*flow.Flow) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	room := w.cfg.QueueSize - len(w.queue) - w.inflight
	n := len(flows)
	if n > room {
		n = max(room, 0)
	}
	w.queue = append(w.queue, flows[:n]...)
	full := len(w.queue) >= w.cfg.BatchSize
	w.queueLen.Set(float64(len(w.queue) + w.inflight))
	w.mu.Unlock()
	if dropped := len(flows) - n; dropped > 0 {
		w.drops.Add(float64(dropped))
	}
	if full {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Close stops accepting flows and writes what is queued, retrying until ctx
// is done. Flows still queued then are dropped and an error is returned.
func (w *Writer) Close(ctx context.Context) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		<-w.done
		return nil
	}
	w.closed = true
	w.closeCtx = ctx
	w.mu.Unlock()
	close(w.closing)
	<-w.done
	w.mu.Lock()
	left := len(w.queue)
	lost := w.lost
	w.queue = nil
	w.queueLen.Set(0)
	w.mu.Unlock()
	if left > 0 {
		w.drops.Add(float64(left))
	}
	if left+lost > 0 {
		return fmt.Errorf("clickhouse writer: %d flows dropped on close: %w", left+lost, ctx.Err())
	}
	return nil
}

// take removes up to BatchSize flows from the queue; with partial false it
// only takes a full batch.
func (w *Writer) take(partial bool) []*flow.Flow {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(w.queue)
	if n == 0 || (!partial && n < w.cfg.BatchSize) {
		return nil
	}
	n = min(n, w.cfg.BatchSize)
	batch := make([]*flow.Flow, n)
	copy(batch, w.queue)
	rest := copy(w.queue, w.queue[n:])
	clear(w.queue[rest:])
	w.queue = w.queue[:rest]
	w.inflight = n
	return batch
}

func (w *Writer) sent() {
	w.mu.Lock()
	w.inflight = 0
	w.queueLen.Set(float64(len(w.queue)))
	w.mu.Unlock()
}

func (w *Writer) run() {
	defer close(w.done)
	timer := time.NewTimer(w.cfg.MaxDelay)
	defer timer.Stop()
	for {
		partial := false
		closing := false
		select {
		case <-w.wake:
		case <-timer.C:
			partial = true
		case <-w.closing:
			partial, closing = true, true
		}
		for {
			batch := w.take(partial)
			if batch == nil {
				break
			}
			ok := w.send(batch)
			w.sent()
			if !ok {
				// Only when closing and the close context expired.
				w.drops.Add(float64(len(batch)))
				w.mu.Lock()
				w.lost = len(batch)
				w.mu.Unlock()
				return
			}
		}
		if closing {
			return
		}
		if partial {
			timer.Reset(w.cfg.MaxDelay)
		}
	}
}

// send inserts batch, retrying with exponential backoff. It gives up only
// when the writer is closing and the close context is done.
func (w *Writer) send(batch []*flow.Flow) bool {
	backoff := w.cfg.MinBackoff
	for {
		err := w.insertOnce(batch)
		if err == nil {
			w.rows.Add(float64(len(batch)))
			w.batches.Inc()
			return true
		}
		w.errs.Inc()
		w.cfg.Logger.Warn("clickhouse insert failed, retrying", "rows", len(batch), "backoff", backoff, "err", err)
		var closeDone <-chan struct{}
		select {
		case <-w.closing:
			w.mu.Lock()
			closeDone = w.closeCtx.Done()
			w.mu.Unlock()
		default:
		}
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-closeDone:
			t.Stop()
			return false
		case <-w.closingIfNil(closeDone):
			// Close started during the wait: retry now with its deadline.
			t.Stop()
		}
		backoff = min(backoff*2, w.cfg.MaxBackoff)
	}
}

// closingIfNil returns the closing channel while Close has not started (so a
// pending backoff wakes up when it does), and nil afterwards.
func (w *Writer) closingIfNil(closeDone <-chan struct{}) <-chan struct{} {
	if closeDone != nil {
		return nil
	}
	return w.closing
}

func (w *Writer) insertOnce(batch []*flow.Flow) error {
	ctx := context.Background()
	w.mu.Lock()
	if w.closeCtx != nil {
		ctx = w.closeCtx
	}
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, w.cfg.InsertTimeout)
	defer cancel()
	b, err := w.conn.PrepareBatch(ctx, w.insert)
	if err != nil {
		return err
	}
	for i, build := range w.build {
		if err := b.Column(i).Append(build(batch)); err != nil {
			_ = b.Abort()
			return fmt.Errorf("column %d: %w", i, err)
		}
	}
	return b.Send()
}
