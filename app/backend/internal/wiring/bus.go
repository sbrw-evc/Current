package wiring

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/bus"
	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// BusConfig selects the bus.
type BusConfig struct {
	// NATSURL empty = in-process bus (single process only).
	NATSURL string
	// NATSToken is the resolved NATS token (never logged).
	NATSToken string
	// Name of the NATS connection (role).
	Name string
}

// ErrNATSRequired is returned when a split role has no NATS URL.
var ErrNATSRequired = errors.New("NATS is required when the collector and the enricher run as separate processes: set FLOW_NATS_URL (collector) and the bus URL in the setup wizard (flow.json nats.url)")

// NewBus returns the in-process bus when cfg.NATSURL is empty and inProcessOK,
// the JetStream bus otherwise.
func NewBus(ctx context.Context, cfg BusConfig, inProcessOK bool, reg prometheus.Registerer, log *slog.Logger) (bus.Bus, *BusStatus, error) {
	if cfg.NATSURL == "" {
		if !inProcessOK {
			return nil, nil, ErrNATSRequired
		}
		b := bus.NewInProcess(bus.InProcessConfig{}, reg, log)
		return b, &BusStatus{Kind: "in-process"}, nil
	}
	opts := []nats.Option{nats.Name("current " + cfg.Name)}
	if cfg.NATSToken != "" {
		opts = append(opts, nats.Token(cfg.NATSToken))
	}
	b, err := bus.NewJetStream(ctx, bus.JetStreamConfig{URL: cfg.NATSURL, Options: opts}, reg, log)
	if err != nil {
		return nil, nil, err
	}
	return b, &BusStatus{Kind: "nats-jetstream", URL: redactURL(cfg.NATSURL)}, nil
}

// redactURL drops credentials from a URL list for display.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

// BusStatus is the bus component of GET /api/status.
type BusStatus struct {
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
	In   *Meter `json:"-"` // what the collector published
	Out  *Meter `json:"-"` // what the consumer received
}

// Status implements app.StatusReporter.
func (s *BusStatus) Status(context.Context) any {
	out := map[string]any{"kind": s.Kind}
	if s.URL != "" {
		out["url"] = s.URL
	}
	if s.In != nil {
		out["published"] = s.In.snapshot()
	}
	if s.Out != nil {
		out["consumed"] = s.Out.snapshot()
	}
	return out
}

// Meter is a flow.Sink wrapper counting what passes through it.
type Meter struct {
	next    flow.Sink
	flows   atomic.Uint64
	batches atomic.Uint64
	errors  atomic.Uint64
	last    atomic.Int64 // unix nanos of the last batch
	lastErr atomic.Pointer[string]
}

// NewMeter wraps next.
func NewMeter(next flow.Sink) *Meter { return &Meter{next: next} }

// Put counts and forwards the batch.
func (m *Meter) Put(ctx context.Context, flows []*flow.Flow) error {
	err := m.next.Put(ctx, flows)
	if err != nil {
		m.errors.Add(1)
		msg := err.Error()
		m.lastErr.Store(&msg)
		return err
	}
	m.flows.Add(uint64(len(flows)))
	m.batches.Add(1)
	m.last.Store(time.Now().UnixNano())
	return nil
}

// Flows returns the number of flows passed on.
func (m *Meter) Flows() uint64 { return m.flows.Load() }

type meterSnapshot struct {
	Flows     uint64     `json:"flows"`
	Batches   uint64     `json:"batches"`
	Errors    uint64     `json:"errors"`
	LastBatch *time.Time `json:"last_batch,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

func (m *Meter) snapshot() meterSnapshot {
	s := meterSnapshot{Flows: m.flows.Load(), Batches: m.batches.Load(), Errors: m.errors.Load()}
	if n := m.last.Load(); n != 0 {
		t := time.Unix(0, n).UTC()
		s.LastBatch = &t
	}
	if e := m.lastErr.Load(); e != nil {
		s.LastError = *e
	}
	return s
}

// Status implements app.StatusReporter.
func (m *Meter) Status(context.Context) any { return m.snapshot() }
