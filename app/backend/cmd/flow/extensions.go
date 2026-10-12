package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/wiring"
)

// enrichExtensions starts reverse DNS and threat intelligence for an
// enricher process and adds them to ec.
func enrichExtensions(ctx context.Context, ec *wiring.EnricherConfig, st *store.Store, deps *app.Deps,
	reg prometheus.Registerer, log *slog.Logger, goRun func(func())) error {
	r, err := wiring.NewRDNS(st, reg, log)
	if err != nil {
		return fmt.Errorf("reverse DNS: %w", err)
	}
	t, err := wiring.NewThreat(st, reg, log)
	if err != nil {
		return fmt.Errorf("threat intelligence: %w", err)
	}
	ec.PTR, ec.Threats = r.R, t.U
	deps.Reloaders = append(deps.Reloaders, r, t)
	deps.Components["rdns"], deps.Components["threat"] = r, t
	goRun(func() { r.Run(ctx) })
	goRun(func() { t.Run(ctx) })
	return nil
}

// flowLogsIngest serves the cloud flow log endpoints in an API process. The
// flows go to the bus of this process (role all), or to NATS JetStream when
// the API runs alone and a bus URL is configured; otherwise the endpoints
// answer 501.
func flowLogsIngest(ctx context.Context, role config.Role, env config.Env, cfg config.File, vault *secrets.Client,
	st *store.Store, sink flow.Sink, deps *app.Deps, reg prometheus.Registerer, log *slog.Logger) error {
	if !role.Runs(config.RoleAPI) {
		return nil
	}
	if sink == nil {
		natsURL := env.NATSURL
		if natsURL == "" {
			natsURL = cfg.NATS.URL
		}
		if natsURL == "" {
			return nil
		}
		token, err := cfg.NATSToken(vault)
		if err != nil {
			return err
		}
		b, _, err := wiring.NewBus(ctx, wiring.BusConfig{NATSURL: natsURL, NATSToken: token, Name: string(role) + "-flowlogs"}, false, reg, log)
		if err != nil {
			return fmt.Errorf("flow logs bus: %w", err)
		}
		go func() { <-ctx.Done(); _ = b.Close() }()
		sink = b
	}
	fl, err := wiring.NewFlowLogs(sink, st, vault, reg, log)
	if err != nil {
		return err
	}
	deps.FlowLogs = fl.H
	deps.Reloaders = append(deps.Reloaders, fl)
	return nil
}
