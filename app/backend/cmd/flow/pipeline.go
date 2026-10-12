package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/bus"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/wiring"
)

// storageConfig is the ClickHouse layout from flow.json (database, retention).
func storageConfig(cfg config.File) chstore.Config {
	r := cfg.ClickHouse.Retention.WithDefaults()
	return chstore.Config{Database: cfg.ClickHouse.Database, RawTTL: config.Days(r.RawDays),
		TTL1m: config.Days(r.D1m), TTL5m: config.Days(r.D5m), TTL1h: config.Days(r.D1h)}.WithDefaults()
}

// newCollector binds the UDP listeners; flows go to sink.
func newCollector(env config.Env, defaultRate uint64, sink bus.Bus, reg prometheus.Registerer) (*collector.Collector, error) {
	return collector.New(collector.Config{NetFlowListen: env.NetFlowAddr, SFlowListen: env.SFlowAddr,
		DefaultSamplingRate: defaultRate}, sink, reg, slog.Default())
}

// runCollectorOnly is the collector role: UDP → NATS JetStream. The NATS URL
// comes from FLOW_NATS_URL; a token is taken from OpenBao when a flow.json
// (shared data volume) names one.
func runCollectorOnly(ctx context.Context, env config.Env, register func(string, app.StatusReporter)) (*wiring.Pipeline, error) {
	if env.NATSURL == "" {
		return nil, wiring.ErrNATSRequired
	}
	token := ""
	if cfg, found, err := config.Read(env.DataDir); err == nil && found && cfg.NATS.Token != "" {
		vault, err := cfg.OpenBao.Client()
		if err != nil || vault == nil {
			return nil, fmt.Errorf("NATS token: OpenBao: %v", err)
		}
		if err := vault.Ready(ctx, env.StartupWait); err != nil {
			return nil, fmt.Errorf("NATS token: OpenBao %s: %w", cfg.OpenBao.Addr, err)
		}
		if token, err = cfg.NATSToken(vault); err != nil {
			return nil, err
		}
	}
	b, bs, err := wiring.NewBus(ctx, wiring.BusConfig{NATSURL: env.NATSURL, NATSToken: token, Name: "collector"}, false,
		prometheus.DefaultRegisterer, slog.Default())
	if err != nil {
		return nil, err
	}
	in := wiring.NewMeter(b)
	bs.In = in
	col, err := newCollector(env, 0, meteredBus{b, in}, prometheus.DefaultRegisterer)
	if err != nil {
		b.Close()
		return nil, err
	}
	register("bus", bs)
	register("collector", &wiring.Collector{C: col})
	return &wiring.Pipeline{Bus: b, Collector: col}, nil
}

// meteredBus counts what the collector publishes.
type meteredBus struct {
	bus.Bus
	in *wiring.Meter
}

func (m meteredBus) Put(ctx context.Context, flows []*flow.Flow) error { return m.in.Put(ctx, flows) }

// migrateClickHouse applies the ClickHouse schema, waiting up to wait for the server.
func migrateClickHouse(ctx context.Context, conn driver.Conn, st chstore.Config, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := chstore.Migrate(ctx, conn, st)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		slog.Info("waiting for ClickHouse", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// pipelineParts is what launch builds for the pipeline roles.
type pipelineParts struct {
	collector *collector.Collector
	enricher  *wiring.Enricher
	inventory *wiring.Inventory
	detector  *wiring.Detector
}

// startPipeline starts the components of role that need flow.json: the
// collector (role all), the enricher with the writer, the Inventory DB loop
// and the detector, and fills deps (reloaders, status components).
func startPipeline(ctx context.Context, role config.Role, env config.Env, cfg config.File, vault *secrets.Client,
	st *store.Store, chConn driver.Conn, deps *app.Deps, goRun func(func())) (pipelineParts, error) {
	var p pipelineParts
	reg := prometheus.DefaultRegisterer
	log := slog.Default()
	storage := storageConfig(cfg)
	register := func(name string, s app.StatusReporter) { deps.Components[name] = s }

	enrich := role.Runs(config.RoleEnricher)
	if (enrich || role.Runs(config.RoleDetector)) && chConn == nil {
		return p, errors.New("ClickHouse is not available")
	}
	if enrich || role.Runs(config.RoleDetector) {
		p.inventory = wiring.NewInventory(st, vault, log, nil)
		deps.Reloaders = append(deps.Reloaders, p.inventory)
		register("inventory", p.inventory)
		goRun(func() { p.inventory.Run(ctx) })
	}

	if enrich {
		if err := migrateClickHouse(ctx, chConn, storage, env.StartupWait); err != nil {
			return p, fmt.Errorf("ClickHouse schema: %w", err)
		}
		natsURL := env.NATSURL
		if natsURL == "" {
			natsURL = cfg.NATS.URL
		}
		token, err := cfg.NATSToken(vault)
		if err != nil {
			return p, err
		}
		b, bs, err := wiring.NewBus(ctx, wiring.BusConfig{NATSURL: natsURL, NATSToken: token, Name: string(role)},
			role == config.RoleAll, reg, log)
		if err != nil {
			return p, fmt.Errorf("bus: %w", err)
		}
		register("bus", bs)
		pl := &wiring.Pipeline{Bus: b, Log: log}
		if role.Runs(config.RoleCollector) {
			var col setup.Collector
			_, _ = st.Setting(ctx, setup.SettingCollector, &col)
			in := wiring.NewMeter(b)
			bs.In = in
			if p.collector, err = newCollector(env, col.DefaultSamplingRate, meteredBus{b, in}, reg); err != nil {
				b.Close()
				return p, fmt.Errorf("collector: %w", err)
			}
			wc := &wiring.Collector{C: p.collector, St: st, Log: log}
			if err := wc.ApplySampling(ctx); err != nil {
				log.Warn("sampling overrides not applied", "err", err)
			}
			deps.Reloaders = append(deps.Reloaders, wc)
			register("collector", wc)
			pl.Collector = p.collector
		}
		writer, err := chstore.NewWriter(chConn, storage, chstore.WriterConfig{Logger: log}, reg)
		if err != nil {
			b.Close()
			return p, fmt.Errorf("ClickHouse writer: %w", err)
		}
		wm := wiring.NewMeter(writer)
		register("writer", wm)
		ec := wiring.EnricherConfig{Store: st, Inventory: p.inventory, Metrics: reg, Log: log}
		if p.collector != nil {
			ec.IfNames = p.collector.IfNames()
		}
		if p.enricher, err = wiring.NewEnricher(wm, ec); err != nil {
			b.Close()
			return p, fmt.Errorf("enricher: %w", err)
		}
		bs.Out = wiring.NewMeter(p.enricher.Sink())
		p.enricher.Refresh(ctx)
		deps.Reloaders = append(deps.Reloaders, p.enricher)
		register("enricher", p.enricher)
		pl.Consumer, pl.Writer = bs.Out, writer
		goRun(func() { p.enricher.Run(ctx) })
		goRun(func() { pl.Run(ctx) })
		if p.collector != nil {
			slog.Info("pipeline started", "bus", bs.Kind, "collector", true, "netflow", env.NetFlowAddr, "sflow", env.SFlowAddr)
		} else {
			slog.Info("pipeline started", "bus", bs.Kind, "collector", false)
		}
	}

	if role.Runs(config.RoleDetector) {
		dc := wiring.DetectorConfig{Conn: chConn, Storage: storage, Store: st, Vault: vault, Collector: p.collector,
			Inventory: p.inventory.Current, Metrics: reg, Log: log}
		d, err := wiring.NewDetector(ctx, dc)
		if err != nil {
			return p, fmt.Errorf("detector: %w", err)
		}
		p.detector = d
		deps.Reloaders = append(deps.Reloaders, d)
		register("detector", d)
		goRun(func() { d.Run(ctx) })
	}
	return p, nil
}

// apiDeps fills the traffic dependencies of the HTTP application.
func apiDeps(cfg config.File, st *store.Store, chConn driver.Conn, p pipelineParts, deps *app.Deps) {
	storage := storageConfig(cfg)
	if chConn != nil {
		qc := query.Config{Storage: storage}
		if p.enricher != nil {
			qc.ASName = p.enricher.Geo.ASName
		}
		t := &wiring.Traffic{Q: query.New(chConn, qc), Collector: p.collector}
		deps.Visualizer, deps.Flows, deps.Exporters, deps.Widgets = t, t, t, t
		deps.Filter = &wiring.Filter{Conn: chConn, Storage: storage}
	} else {
		deps.Filter = &wiring.Filter{Storage: storage}
	}
	inv := &wiring.InventoryAPI{Local: p.inventory, Store: st}
	if p.enricher != nil {
		inv.Unknown = p.enricher.Unknown
	}
	deps.Inventory = inv.Syncer()
	deps.Classifiers = wiring.Classifiers{}
	deps.Detector = &wiring.DetectorAPI{Local: p.detector, Store: st}
}
