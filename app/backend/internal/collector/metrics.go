package collector

import (
	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	packets      *prometheus.CounterVec // exporter, type
	flows        *prometheus.CounterVec // exporter, type
	decodeErrors *prometheus.CounterVec // exporter, type
	drops        *prometheus.CounterVec // exporter, listener
	templates    *prometheus.GaugeVec   // exporter, type
	sinkErrors   prometheus.Counter
	sinkDropped  prometheus.Counter
	batchSize    prometheus.Histogram
	exporters    prometheus.GaugeFunc
}

func newMetrics(reg prometheus.Registerer, exporters func() float64) *metrics {
	const ns, sub = "flow", "collector"
	m := &metrics{
		packets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "packets_total",
			Help: "Datagrams received, per exporter and flow type.",
		}, []string{"exporter", "type"}),
		flows: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "flows_total",
			Help: "Flow records decoded, per exporter and flow type.",
		}, []string{"exporter", "type"}),
		decodeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "decode_errors_total",
			Help: "Datagrams that failed to decode (fully or partly, e.g. unknown template).",
		}, []string{"exporter", "type"}),
		drops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "dropped_packets_total",
			Help: "Datagrams dropped because the decoding queue was full.",
		}, []string{"exporter", "listener"}),
		templates: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns, Subsystem: sub, Name: "templates",
			Help: "NetFlow v9 / IPFIX templates known, per exporter.",
		}, []string{"exporter", "type"}),
		sinkErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "sink_errors_total",
			Help: "Batches the sink refused.",
		}),
		sinkDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Subsystem: sub, Name: "sink_dropped_flows_total",
			Help: "Flows lost because the sink refused their batch.",
		}),
		batchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: ns, Subsystem: sub, Name: "batch_flows",
			Help:    "Flows per batch handed to the sink.",
			Buckets: prometheus.ExponentialBuckets(1, 4, 8),
		}),
		exporters: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: ns, Subsystem: sub, Name: "exporters",
			Help: "Exporters seen since start.",
		}, exporters),
	}
	if reg != nil {
		reg.MustRegister(m.packets, m.flows, m.decodeErrors, m.drops, m.templates,
			m.sinkErrors, m.sinkDropped, m.batchSize, m.exporters)
	}
	return m
}

// exporterCounters are the per-(exporter, type) counters, resolved once.
type exporterCounters struct {
	packets, flows, errors prometheus.Counter
}

func (m *metrics) forExporter(exporter, typ string) *exporterCounters {
	return &exporterCounters{
		packets: m.packets.WithLabelValues(exporter, typ),
		flows:   m.flows.WithLabelValues(exporter, typ),
		errors:  m.decodeErrors.WithLabelValues(exporter, typ),
	}
}
