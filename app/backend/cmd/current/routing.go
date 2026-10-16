package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/bus"
	"github.com/sbrw-evc/current/app/backend/internal/collector"
	"github.com/sbrw-evc/current/app/backend/internal/devices"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/snmp"
	"github.com/sbrw-evc/current/app/backend/internal/store"
	"github.com/sbrw-evc/current/app/backend/internal/wiring"
)

// routingExtension starts the gNMI and SNMP pollers and the BMP receiver
// (FLOW_BMP_ADDR, default :10179) of the enricher process; all stay idle until
// their settings enable them.
func routingExtension(ctx context.Context, ec *wiring.EnricherConfig, st *store.Store, vault *secrets.Client,
	col *collector.Collector, b bus.Bus, deps *app.Deps, reg prometheus.Registerer, log *slog.Logger, goRun func(func())) error {
	r, err := wiring.NewRouting(st, vault, reg, log)
	if err != nil {
		return fmt.Errorf("gNMI / SNMP / BMP: %w", err)
	}
	r.GNMI.UseCollector(col)
	// With NATS, enricher replicas share their BMP sessions.
	if js, ok := b.(*bus.JetStream); ok {
		r.BMP.UseJetStream(js.JetStream())
	}
	r.SNMP.UseCollector(col)
	// The SNMP credentials of managed devices also name their interfaces.
	r.SNMP.Extra = func(ctx context.Context) ([]snmp.Profile, error) { return devices.SNMPProfiles(ctx, st, vault) }
	ec.Routing = r
	deps.Routing = r
	deps.Reloaders = append(deps.Reloaders, r)
	deps.Components["gnmi"], deps.Components["snmp"], deps.Components["bmp"] = r.GNMI, r.SNMP, r.BMP
	goRun(func() { r.Run(ctx) })
	return nil
}
