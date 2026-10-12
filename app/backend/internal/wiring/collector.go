package wiring

import (
	"context"
	"log/slog"
	"sync"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Collector adapts the collector for the API: sampling override reloads and
// the status component. The sampling override loading lives in sampling.go.
type Collector struct {
	C   *collector.Collector
	St  *store.Store // nil: overrides are read through OpenStore, if set
	Log *slog.Logger
	// Env are the overrides of FLOW_SAMPLING_OVERRIDES; they win over the
	// stored ones for the same exporter prefix and interface.
	Env []collector.SamplingOverride
	// OpenStore connects PostgreSQL lazily (standalone collector role, which
	// learns the connection from flow.json on the shared data volume); it is
	// retried on each refresh until it succeeds.
	OpenStore func(ctx context.Context) (*store.Store, error)

	smu     sync.Mutex
	lastErr string
	opened  bool // St was opened through OpenStore (closed by RunSampling)
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
