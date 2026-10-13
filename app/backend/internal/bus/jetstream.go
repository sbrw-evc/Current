package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// JetStreamConfig configures the NATS JetStream bus.
type JetStreamConfig struct {
	// URL of the NATS server(s), comma separated.
	URL string
	// Options are extra connection options (credentials, TLS, name...).
	Options []nats.Option

	// Stream is created if missing (and its limits updated if possible).
	Stream   string
	Subject  string
	MaxBytes int64
	MaxAge   time.Duration
	Replicas int

	// MaxFlowsPerMessage splits large batches so that messages stay well
	// under the server max_payload (1 MiB by default).
	MaxFlowsPerMessage int

	// Durable is the name of the durable pull consumer shared by all
	// consumer processes (they load-balance).
	Durable string
	// Workers is the number of goroutines pulling and calling the sink.
	Workers int
	// PullBatch is how many messages each worker keeps buffered.
	PullBatch int
	// AckWait is how long the server waits for an ack before redelivering.
	AckWait time.Duration
	// NakDelay is the redelivery delay after the sink refused a batch.
	NakDelay time.Duration
}

func (c JetStreamConfig) withDefaults() JetStreamConfig {
	if c.URL == "" {
		c.URL = nats.DefaultURL
	}
	if c.Stream == "" {
		c.Stream = "FLOWS"
	}
	if c.Subject == "" {
		c.Subject = "flow.raw"
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = 1 << 30
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 24 * time.Hour
	}
	if c.Replicas <= 0 {
		c.Replicas = 1
	}
	if c.MaxFlowsPerMessage <= 0 {
		c.MaxFlowsPerMessage = 2000
	}
	if c.Durable == "" {
		c.Durable = "enricher"
	}
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.PullBatch <= 0 {
		c.PullBatch = 8
	}
	if c.AckWait <= 0 {
		c.AckWait = time.Minute
	}
	if c.NakDelay <= 0 {
		c.NakDelay = 5 * time.Second
	}
	return c
}

// JetStream is the NATS JetStream bus.
type JetStream struct {
	cfg JetStreamConfig
	nc  *nats.Conn
	js  jetstream.JetStream
	m   *metrics
	log *slog.Logger
	buf sync.Pool
}

// NewJetStream connects to NATS and makes sure the stream exists with the
// configured limits; reg may be nil.
func NewJetStream(ctx context.Context, cfg JetStreamConfig, reg prometheus.Registerer, log *slog.Logger) (*JetStream, error) {
	cfg = cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "bus", "bus", "jetstream")
	opts := append([]nats.Option{
		nats.Name("umbrella-flow"),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn("nats disconnected", "err", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) { log.Info("nats reconnected", "url", nc.ConnectedUrl()) }),
	}, cfg.Options...)
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("bus: connect %s: %w", cfg.URL, err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	b := &JetStream{cfg: cfg, nc: nc, js: js, m: newMetrics(reg, "jetstream"), log: log}
	if err := b.ensureStream(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

func (b *JetStream) ensureStream(ctx context.Context) error {
	sc := jetstream.StreamConfig{
		Name:        b.cfg.Stream,
		Description: "Umbrella Flow: decoded flow batches from collectors",
		Subjects:    []string{b.cfg.Subject},
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardOld,
		MaxBytes:    b.cfg.MaxBytes,
		MaxAge:      b.cfg.MaxAge,
		Storage:     jetstream.FileStorage,
		Replicas:    b.cfg.Replicas,
	}
	_, err := b.js.CreateOrUpdateStream(ctx, sc)
	if err == nil {
		return nil
	}
	// An existing stream we cannot update (e.g. managed elsewhere with
	// another storage type) is fine as long as it exists.
	if _, gerr := b.js.Stream(ctx, b.cfg.Stream); gerr == nil {
		b.log.Warn("stream exists but could not be updated", "stream", b.cfg.Stream, "err", err)
		return nil
	}
	return fmt.Errorf("bus: create stream %s: %w", b.cfg.Stream, err)
}

// JetStream returns the JetStream context (for other streams on the same
// connection, e.g. BMP replication).
func (b *JetStream) JetStream() jetstream.JetStream { return b.js }

// Put publishes flows, split into messages of at most MaxFlowsPerMessage,
// and waits for the server acknowledgements.
func (b *JetStream) Put(ctx context.Context, flows []*flow.Flow) error {
	bufp, _ := b.buf.Get().(*[]byte)
	if bufp == nil {
		bufp = new([]byte)
	}
	defer b.buf.Put(bufp)
	for len(flows) > 0 {
		n := min(len(flows), b.cfg.MaxFlowsPerMessage)
		*bufp = flow.MarshalBatch((*bufp)[:0], flows[:n])
		// Publish copies the payload into the connection buffer, so the
		// buffer can be reused once it returns.
		if _, err := b.js.Publish(ctx, b.cfg.Subject, *bufp); err != nil {
			b.m.publishErrors.Inc()
			return fmt.Errorf("bus: publish: %w", err)
		}
		b.m.publishedBatches.Inc()
		b.m.publishedFlows.Add(float64(n))
		flows = flows[n:]
	}
	return nil
}

// Consume creates (or updates) the durable pull consumer and runs Workers
// pullers until ctx is canceled. Batches are acked once the sink accepted
// them, naked with NakDelay when it refused them, and terminated when they
// cannot be decoded.
func (b *JetStream) Consume(ctx context.Context, sink flow.Sink) error {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, b.cfg.Stream, jetstream.ConsumerConfig{
		Durable:       b.cfg.Durable,
		Description:   "Umbrella Flow enricher",
		FilterSubject: b.cfg.Subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       b.cfg.AckWait,
		MaxDeliver:    -1,
		MaxAckPending: max(1000, b.cfg.Workers*b.cfg.PullBatch*4),
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("bus: consumer %s: %w", b.cfg.Durable, err)
	}

	errs := make(chan error, b.cfg.Workers)
	var wg sync.WaitGroup
	for range b.cfg.Workers {
		wg.Go(func() {
			if err := b.pull(ctx, cons, sink); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	return <-errs // nil when every worker stopped on ctx
}

func (b *JetStream) pull(ctx context.Context, cons jetstream.Consumer, sink flow.Sink) error {
	it, err := cons.Messages(jetstream.PullMaxMessages(b.cfg.PullBatch))
	if err != nil {
		return fmt.Errorf("bus: pull: %w", err)
	}
	stop := context.AfterFunc(ctx, it.Stop)
	defer stop()
	defer it.Stop()
	for {
		msg, err := it.Next()
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgIteratorClosed) || ctx.Err() != nil {
				return nil
			}
			b.log.Warn("pull failed", "err", err)
			continue
		}
		flows, err := flow.UnmarshalBatch(msg.Data())
		if err != nil {
			b.m.rejected.Inc()
			b.log.Error("undecodable message dropped", "subject", msg.Subject(), "bytes", len(msg.Data()), "err", err)
			_ = msg.Term()
			continue
		}
		if err := sink.Put(ctx, flows); err != nil {
			b.m.retries.Inc()
			b.log.Warn("sink refused batch, redelivery scheduled", "flows", len(flows), "delay", b.cfg.NakDelay, "err", err)
			_ = msg.NakWithDelay(b.cfg.NakDelay)
			continue
		}
		if err := msg.Ack(); err != nil {
			b.log.Warn("ack failed, batch may be redelivered", "err", err)
		}
		b.m.consumedBatches.Inc()
		b.m.consumedFlows.Add(float64(len(flows)))
	}
}

// Close drains and closes the NATS connection.
func (b *JetStream) Close() error {
	if err := b.nc.Drain(); err != nil {
		b.nc.Close()
		return err
	}
	return nil
}
