// Package bus carries flow batches from the collector to the enricher:
// through NATS JetStream when roles run as separate processes, or through a
// bounded in-process channel in single-binary mode. Both have the same
// shape: Put publishes (flow.Sink), Consume delivers to another flow.Sink.
package bus

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// Bus decouples flow producers from consumers.
type Bus interface {
	// Put publishes a batch. It does not retain the slice.
	flow.Sink
	// Consume delivers batches to sink until ctx is canceled. A batch the
	// sink refuses is redelivered later.
	Consume(ctx context.Context, sink flow.Sink) error
	// Close releases resources (connections). Call it after Consume
	// returned and producers stopped.
	Close() error
}

var (
	_ Bus = (*JetStream)(nil)
	_ Bus = (*InProcess)(nil)
)

type metrics struct {
	publishedBatches prometheus.Counter
	publishedFlows   prometheus.Counter
	publishErrors    prometheus.Counter
	consumedBatches  prometheus.Counter
	consumedFlows    prometheus.Counter
	retries          prometheus.Counter
	rejected         prometheus.Counter
}

func newMetrics(reg prometheus.Registerer, kind string) *metrics {
	c := func(name, help string) prometheus.Counter {
		return prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "bus", Name: name, Help: help,
			ConstLabels: prometheus.Labels{"bus": kind},
		})
	}
	m := &metrics{
		publishedBatches: c("published_batches_total", "Batches published."),
		publishedFlows:   c("published_flows_total", "Flows published."),
		publishErrors:    c("publish_errors_total", "Batches that could not be published."),
		consumedBatches:  c("consumed_batches_total", "Batches delivered to the consumer sink and acknowledged."),
		consumedFlows:    c("consumed_flows_total", "Flows delivered to the consumer sink and acknowledged."),
		retries:          c("retries_total", "Batches refused by the consumer sink and scheduled for redelivery."),
		rejected:         c("rejected_total", "Messages dropped because they could not be decoded."),
	}
	if reg != nil {
		reg.MustRegister(m.publishedBatches, m.publishedFlows, m.publishErrors,
			m.consumedBatches, m.consumedFlows, m.retries, m.rejected)
	}
	return m
}
