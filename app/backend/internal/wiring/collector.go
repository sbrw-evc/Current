package wiring

import (
	"context"
	"log/slog"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Collector adapts the collector for the API: sampling override reloads and
// the status component.
type Collector struct {
	C   *collector.Collector
	St  *store.Store // nil: overrides are not applied
	Log *slog.Logger
}

// SamplingOverrides converts the stored overrides for the collector. The
// collector applies a rate per exporter prefix; per-interface overrides
// (if_index ≠ 0) are not supported by it and are skipped.
func SamplingOverrides(in []store.SamplingOverride) (out []collector.SamplingOverride, skipped int) {
	for _, o := range in {
		if o.IfIndex != 0 {
			skipped++
			continue
		}
		out = append(out, collector.SamplingOverride{Prefix: o.Exporter, Rate: o.Rate})
	}
	return out, skipped
}

// ApplySampling reads the overrides from PostgreSQL and applies them.
func (c *Collector) ApplySampling(ctx context.Context) error {
	if c.St == nil {
		return nil
	}
	list, err := c.St.SamplingOverrides(ctx)
	if err != nil {
		return err
	}
	ov, skipped := SamplingOverrides(list)
	c.C.SetSamplingOverrides(ov)
	if skipped > 0 && c.Log != nil {
		c.Log.Warn("per-interface sampling overrides are not supported by the collector; skipped", "count", skipped)
	}
	return nil
}

// Reload implements app.Reloader.
func (c *Collector) Reload(ctx context.Context, what string) error {
	if what == app.ReloadSampling {
		return c.ApplySampling(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (c *Collector) Status(context.Context) any {
	out := map[string]any{}
	if a := c.C.NetFlowAddr(); a != nil {
		out["netflow"] = a.String()
	}
	if a := c.C.SFlowAddr(); a != nil {
		out["sflow"] = a.String()
	}
	exps := c.C.Exporters()
	var fps float64
	var flows, errs uint64
	for _, e := range exps {
		fps += e.FlowsPerSecond
		flows += e.Flows
		errs += e.DecodeErrors
	}
	out["exporters"] = len(exps)
	out["flows_per_second"] = fps
	out["flows"] = flows
	out["decode_errors"] = errs
	return out
}
