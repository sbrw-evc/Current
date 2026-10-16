package enrich

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registerer is prometheus.Registerer.
type Registerer = prometheus.Registerer

type metrics struct {
	flows       prometheus.Counter
	batches     prometheus.Counter
	unknownExp  prometheus.Counter
	ifaces      *prometheus.CounterVec
	ifInventory prometheus.Counter
	ifCollector prometheus.Counter
	ifNone      prometheus.Counter
	netPrefix   prometheus.Counter
	netMask     prometheus.Counter
	netNone     prometheus.Counter
	cacheHit    prometheus.Counter
	cacheMiss   prometheus.Counter
}

func newMetrics(reg Registerer, e *Enricher) (*metrics, error) {
	ifaces := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_enrich_interfaces_total", Help: "Interface lookups by the source that answered (inventory, collector, none).",
	}, []string{"source"})
	nets := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_enrich_networks_total", Help: "Address network lookups by result (prefix = IPAM prefix, mask = flow mask, none).",
	}, []string{"result"})
	cache := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_enrich_exporter_cache_total", Help: "Exporter cache lookups by result.",
	}, []string{"result"})
	m := &metrics{
		flows:       prometheus.NewCounter(prometheus.CounterOpts{Name: "flow_enrich_flows_total", Help: "Flows enriched."}),
		batches:     prometheus.NewCounter(prometheus.CounterOpts{Name: "flow_enrich_batches_total", Help: "Batches enriched."}),
		unknownExp:  prometheus.NewCounter(prometheus.CounterOpts{Name: "flow_enrich_unknown_exporter_flows_total", Help: "Flows from exporters without a Ledger device."}),
		ifaces:      ifaces,
		ifInventory: ifaces.WithLabelValues("inventory"), ifCollector: ifaces.WithLabelValues("collector"), ifNone: ifaces.WithLabelValues("none"),
		netPrefix: nets.WithLabelValues("prefix"), netMask: nets.WithLabelValues("mask"), netNone: nets.WithLabelValues("none"),
		cacheHit: cache.WithLabelValues("hit"), cacheMiss: cache.WithLabelValues("miss"),
	}
	if reg == nil {
		return m, nil
	}
	collectors := []prometheus.Collector{
		m.flows, m.batches, m.unknownExp, ifaces, nets, cache,
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "flow_enrich_classifier_errors_total", Help: "Classifier rule evaluation errors.",
		}, func() float64 {
			if s := e.cls.Load(); s != nil {
				n, _ := s.EvalErrors()
				return float64(n)
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "flow_enrich_unknown_exporters", Help: "Exporters seen without a Ledger device.",
		}, func() float64 {
			e.unknown.mu.Lock()
			defer e.unknown.mu.Unlock()
			return float64(len(e.unknown.exporters))
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "flow_enrich_inventory_age_seconds", Help: "Age of the Ledger snapshot in use.",
		}, func() float64 {
			at := e.snapshot().At()
			if at.IsZero() {
				return 0
			}
			return e.now().Sub(at).Seconds()
		}),
	}
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *metrics) publish(st *batchStats) {
	m.batches.Inc()
	m.flows.Add(float64(st.flows))
	add := func(c prometheus.Counter, n int) {
		if n > 0 {
			c.Add(float64(n))
		}
	}
	add(m.unknownExp, st.unknownExporter)
	add(m.ifInventory, st.ifInventory)
	add(m.ifCollector, st.ifCollector)
	add(m.ifNone, st.ifNone)
	add(m.netPrefix, st.netPrefix)
	add(m.netMask, st.netMask)
	add(m.netNone, st.netNone)
	add(m.cacheHit, st.cacheHits)
	add(m.cacheMiss, st.cacheMisses)
}
