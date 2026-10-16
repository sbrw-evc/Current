package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/devices"
	"github.com/sbrw-evc/current/app/backend/internal/inventory"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/store"
	"github.com/sbrw-evc/current/app/backend/internal/wiring"
)

// devicesExtension starts the network device manager (docs/devices.md) in
// the API process: the registry, the poll scheduler (one replica polls per
// tick, PostgreSQL advisory lock), clients and the network map. Device down /
// up events go to Beacon through the detector's sender when the detector
// runs here, else through a sender of their own with the same settings.
func devicesExtension(ctx context.Context, dataDir string, st *store.Store, vault *secrets.Client, p pipelineParts,
	deps *app.Deps, goRun func(func())) {
	log := slog.Default()
	inv := p.inventory
	if inv == nil { // api role: a snapshot for the binding of devices
		inv = wiring.NewInventory(st, vault, log, nil)
		deps.Reloaders = append(deps.Reloaders, inv)
		goRun(func() { inv.Run(ctx) })
	}
	var sink devices.EventSink
	if p.detector != nil {
		sink = p.detector.Sender
	} else {
		ev := wiring.NewDeviceEvents(st, vault, log)
		deps.Reloaders = append(deps.Reloaders, ev)
		deps.Components["device_events"] = ev
		goRun(func() { ev.Run(ctx) })
		sink = ev.Sender
	}
	svc := devices.New(devices.Config{Store: st, Vault: vault, Events: sink, Log: log,
		Inventory: func() *inventory.Snapshot { return inv.Current() },
		OUI:       devices.NewOUI(filepath.Join(dataDir, "devices"), log)})
	deps.Devices = svc
	if t, ok := deps.Exporters.(*wiring.Traffic); ok {
		t.Devices = svc
	}
	goRun(func() {
		svc.Run(ctx)
		svc.Close()
	})
}
