package detector

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	registered bool
	ifaceBPS   *prometheus.GaugeVec
	ifaceRatio *prometheus.GaugeVec
	evals      *prometheus.CounterVec
	errors     *prometheus.CounterVec
	events     *prometheus.CounterVec
	alerts     *prometheus.GaugeVec
	outbox     prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) (*metrics, error) {
	ifLabels := []string{"exporter", "ifname", "direction"}
	m := &metrics{
		ifaceBPS: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_interface_bps", Help: "Interface bit rate from flows over the last complete minute.",
		}, ifLabels),
		ifaceRatio: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_interface_utilization_ratio", Help: "Interface bit rate divided by the interface speed (0..1).",
		}, ifLabels),
		evals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "detector", Name: "evaluations_total", Help: "Rule evaluations.",
		}, []string{"rule"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "detector", Name: "evaluation_errors_total", Help: "Failed rule evaluations.",
		}, []string{"rule"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "flow", Subsystem: "detector", Name: "events_total", Help: "Events produced, by status.",
		}, []string{"status"}),
		alerts: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "flow", Subsystem: "detector", Name: "alerts", Help: "Alerts by state.",
		}, []string{"state"}),
		outbox: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "flow", Subsystem: "detector", Name: "outbox_events", Help: "Events waiting to be delivered to Umbrella.",
		}),
	}
	if reg == nil {
		return m, nil
	}
	for _, c := range []prometheus.Collector{m.ifaceBPS, m.ifaceRatio, m.evals, m.errors, m.events, m.alerts, m.outbox} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("detector: register metrics: %w", err)
		}
	}
	m.registered = true
	return m, nil
}

func (d *Detector) updateAlertGaugesLocked() {
	counts := map[string]int{StatePending: 0, StateFiring: 0, StateResolving: 0}
	for _, states := range d.alerts {
		for _, st := range states {
			counts[st.State]++
		}
	}
	for s, n := range counts {
		d.m.alerts.WithLabelValues(s).Set(float64(n))
	}
}

// refreshInterfaceMetrics sets the per-interface gauges from the last
// complete minute of flows_1m (all interfaces, no filter).
func (d *Detector) refreshInterfaceMetrics(ctx context.Context, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	start, end := d.rollupWindow(now, time.Minute)
	rows, err := d.ifaceRows(ctx, d.store.Table(d.store.Rollups()[0].Table), start, end, "1")
	if err != nil {
		return err
	}
	d.m.ifaceBPS.Reset()
	d.m.ifaceRatio.Reset()
	for _, r := range rows {
		exp := deviceCI(r.name, r.exporter)
		d.m.ifaceBPS.WithLabelValues(exp, r.ifname, r.dir).Set(r.bps)
		if r.speed > 0 {
			d.m.ifaceRatio.WithLabelValues(exp, r.ifname, r.dir).Set(r.bps / float64(r.speed))
		}
	}
	return nil
}
