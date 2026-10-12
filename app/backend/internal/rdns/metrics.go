package rdns

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Registerer is prometheus.Registerer.
type Registerer = prometheus.Registerer

type metrics struct {
	duration prometheus.Histogram
}

func (m *metrics) observe(d time.Duration) {
	if m != nil && m.duration != nil {
		m.duration.Observe(d.Seconds())
	}
}

func newMetrics(reg Registerer, r *Resolver) (*metrics, error) {
	m := &metrics{duration: prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "flow_rdns_query_duration_seconds", Help: "Duration of reverse DNS queries.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	})}
	if reg == nil {
		return m, nil
	}
	counter := func(name, help string, v func() uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, func() float64 { return float64(v()) })
	}
	lookups := prometheus.NewDesc("flow_rdns_lookups_total", "Answers of reverse DNS queries by result (found, not_found, error).", []string{"result"}, nil)
	collectors := []prometheus.Collector{
		m.duration,
		counter("flow_rdns_cache_hits_total", "PTR lookups answered from the cache (including stale names being refreshed).", r.stats.hits.Load),
		counter("flow_rdns_cache_misses_total", "PTR lookups of addresses not in the cache.", r.stats.misses.Load),
		counter("flow_rdns_dropped_total", "Lookups not queued because the queue was full.", r.stats.dropped.Load),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "flow_rdns_cache_entries", Help: "Addresses in the PTR cache."},
			func() float64 { return float64(r.Stats().Cached) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "flow_rdns_queue_length", Help: "Lookups waiting for a worker."},
			func() float64 { return float64(len(*r.queue.Load())) }),
		&resultCollector{desc: lookups, r: r},
	}
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

type resultCollector struct {
	desc *prometheus.Desc
	r    *Resolver
}

func (c *resultCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *resultCollector) Collect(ch chan<- prometheus.Metric) {
	for _, v := range []struct {
		label string
		n     uint64
	}{{"found", c.r.stats.found.Load()}, {"not_found", c.r.stats.notFound.Load()}, {"error", c.r.stats.errors.Load()}} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(v.n), v.label)
	}
}
