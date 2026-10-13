package wiring

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/apps"
	"github.com/sbrw-evc/network/app/backend/internal/classifier"
	"github.com/sbrw-evc/network/app/backend/internal/enrich"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/flowlogs"
	"github.com/sbrw-evc/network/app/backend/internal/geoip"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// GeoSwap is an enrich.GeoSource whose databases can be replaced at run time.
type GeoSwap struct {
	db     atomic.Pointer[geoip.DB]
	names  sync.Map // AS number → name, learned from lookups (query labels)
	nnames atomic.Int64
	mu     sync.Mutex
	cancel context.CancelFunc
	paths  []string
}

// Lookup implements enrich.GeoSource.
func (g *GeoSwap) Lookup(addr netip.Addr) geoip.Info {
	if db := g.db.Load(); db != nil {
		info := db.Lookup(addr)
		if info.ASN != 0 && info.ASName != "" && g.nnames.Load() < 200000 {
			if _, loaded := g.names.LoadOrStore(info.ASN, info.ASName); !loaded {
				g.nnames.Add(1)
			}
		}
		return info
	}
	return geoip.Info{}
}

// ASName names an AS seen in the GeoIP lookups of this process ("" when
// unknown); the query.ASNamer hook.
func (g *GeoSwap) ASName(asn uint32) string {
	if v, ok := g.names.Load(asn); ok {
		return v.(string)
	}
	return ""
}

// DB returns the current databases (nil when none).
func (g *GeoSwap) DB() *geoip.DB { return g.db.Load() }

// Set opens paths (empty removes the databases) and starts their hot reload
// under ctx. Unchanged paths are kept as they are.
func (g *GeoSwap) Set(ctx context.Context, paths []string, log *slog.Logger) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if slices.Equal(paths, g.paths) && (len(paths) == 0 || g.db.Load() != nil) {
		return nil
	}
	var db *geoip.DB
	if len(paths) > 0 {
		var err error
		if db, err = geoip.Open(geoip.Config{Databases: paths, Logger: log}); err != nil {
			return err
		}
	}
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	g.db.Store(db)
	g.paths = slices.Clone(paths)
	if db != nil {
		rctx, cancel := context.WithCancel(ctx)
		g.cancel = cancel
		go db.Run(rctx)
	}
	return nil
}

// EnricherConfig are the sources of the enricher component.
type EnricherConfig struct {
	Store     *store.Store
	Inventory enrich.InventorySource // nil: no Inventory DB
	IfNames   enrich.IfNameSource    // nil when the collector runs in another process
	PTR       enrich.PTRSource       // reverse DNS (wiring.RDNS); nil: none
	Threats   enrich.ThreatSource    // threat lists (wiring.Threat); nil: none
	Metrics   prometheus.Registerer
	Log       *slog.Logger
	// Routing adds gNMI / SNMP interface names and BMP routes (bmp.go); nil = none.
	Routing *Routing
}

// Enricher is the enrich.Enricher with its reloadable classifiers and GeoIP.
type Enricher struct {
	E   *enrich.Enricher
	Geo *GeoSwap
	in  *Meter

	st  *store.Store
	log *slog.Logger

	mu          sync.Mutex
	classifiers string          // JSON of the rules applied
	base        context.Context // Run's context: GeoIP hot reload lives with it
}

// NewEnricher builds the enricher in front of next (the writer).
func NewEnricher(next flow.Sink, cfg EnricherConfig) (*Enricher, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	g := &GeoSwap{}
	ec := enrich.Config{GeoIP: g, Apps: apps.Default(), Metrics: cfg.Metrics}
	if cfg.Inventory != nil {
		ec.Inventory = cfg.Inventory
	}
	if cfg.IfNames != nil {
		ec.IfNames = cfg.IfNames
	}
	if cfg.PTR != nil {
		ec.PTR = cfg.PTR
	}
	if cfg.Threats != nil {
		ec.Threats = cfg.Threats
	}
	ec.ExporterNames = flowlogs.ExporterName // synthetic exporters of cloud flow logs
	cfg.Routing.configure(&ec)
	e, err := enrich.New(next, ec)
	if err != nil {
		return nil, err
	}
	cfg.Routing.attach(e)
	en := &Enricher{E: e, Geo: g, st: cfg.Store, log: log.With("component", "enricher")}
	en.in = NewMeter(e)
	return en, nil
}

// Sink is what the bus delivers to (counted for the status).
func (e *Enricher) Sink() flow.Sink { return e.in }

// Unknown lists exporters and addresses missing from Inventory DB.
func (e *Enricher) Unknown() any { return e.E.Unknown() }

// Refresh re-reads classifiers and GeoIP settings from PostgreSQL.
func (e *Enricher) Refresh(ctx context.Context) {
	if err := e.reloadClassifiers(ctx); err != nil {
		e.log.Warn("classifiers not loaded", "err", err)
	}
	if err := e.reloadGeoIP(ctx); err != nil {
		e.log.Warn("GeoIP databases not loaded", "err", err)
	}
}

// Run polls the settings every minute (changes made by an API in another
// process) until ctx is done.
func (e *Enricher) Run(ctx context.Context) {
	e.mu.Lock()
	e.base = ctx
	e.mu.Unlock()
	e.Refresh(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Refresh(ctx)
		}
	}
}

func (e *Enricher) reloadClassifiers(ctx context.Context) error {
	if e.st == nil {
		return nil
	}
	m, err := e.st.Classifiers(ctx)
	if err != nil {
		return err
	}
	cfg := classifier.Config{Exporter: m[store.ClassifierExporter], Interface: m[store.ClassifierInterface]}
	key, _ := json.Marshal(cfg)
	e.mu.Lock()
	defer e.mu.Unlock()
	if string(key) == e.classifiers {
		return nil
	}
	if len(cfg.Exporter) == 0 && len(cfg.Interface) == 0 {
		e.E.SetClassifiers(nil)
	} else {
		set, err := classifier.New(cfg)
		if err != nil {
			return err
		}
		e.E.SetClassifiers(set)
	}
	e.classifiers = string(key)
	e.log.Info("classifiers loaded", "exporter", len(cfg.Exporter), "interface", len(cfg.Interface))
	return nil
}

func (e *Enricher) reloadGeoIP(ctx context.Context) error {
	if e.st == nil {
		return nil
	}
	var gs setup.GeoIPSettings
	if _, err := e.st.Setting(ctx, setup.SettingGeoIP, &gs); err != nil {
		return err
	}
	// The databases outlive the request context that may trigger a reload.
	e.mu.Lock()
	base := e.base
	e.mu.Unlock()
	if base == nil {
		base = context.WithoutCancel(ctx)
	}
	return e.Geo.Set(base, gs.Databases, e.log)
}

// Reload implements app.Reloader.
func (e *Enricher) Reload(ctx context.Context, what string) error {
	switch what {
	case app.ReloadClassifiers:
		return e.reloadClassifiers(ctx)
	case app.ReloadGeoIP:
		return e.reloadGeoIP(ctx)
	case app.ReloadInventory:
		e.E.ResetUnknown()
	}
	return nil
}

// Status implements app.StatusReporter.
func (e *Enricher) Status(context.Context) any {
	u := e.E.Unknown()
	out := map[string]any{"received": e.in.snapshot(), "unknown_exporters": len(u.Exporters)}
	if db := e.Geo.DB(); db != nil {
		out["geoip"] = db.Databases()
	}
	return out
}
