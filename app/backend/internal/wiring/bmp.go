package wiring

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/bmp"
	"github.com/sbrw-evc/network/app/backend/internal/enrich"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// BMPListenFromEnv is the BMP listen address: FLOW_BMP_ADDR, default :10179.
func BMPListenFromEnv() string {
	if v := os.Getenv("FLOW_BMP_ADDR"); v != "" {
		return v
	}
	return bmp.DefaultListen
}

// BMP runs the BMP receiver with the settings from PostgreSQL (key "bmp"):
// the TCP listener is opened while BMP is enabled, and the enricher's AS
// provider order is switched to the configured one (routing first by
// default). It runs with the enricher, which reads its RIB.
type BMP struct {
	RIB    *bmp.RIB
	listen string
	st     *store.Store
	log    *slog.Logger
	m      *bmp.Metrics

	enabled atomic.Bool
	mu      sync.Mutex
	base    context.Context
	srv     *bmp.Server
	stop    context.CancelFunc
	applied string
	lastErr string
	enr     *enrich.Enricher

	rds  sync.Map // VRF route distinguisher text → bmp RD
	nrds atomic.Int32
}

// NewBMP builds the component; Run applies the settings.
func NewBMP(st *store.Store, listen string, reg prometheus.Registerer, log *slog.Logger) (*BMP, error) {
	if log == nil {
		log = slog.Default()
	}
	rib := bmp.NewRIB()
	m, err := bmp.NewMetrics(reg, rib)
	if err != nil {
		return nil, err
	}
	if listen == "" {
		listen = bmp.DefaultListen
	}
	return &BMP{RIB: rib, listen: listen, st: st, log: log.With("component", "bmp"), m: m}, nil
}

// LookupRoute implements enrich.RoutingSource.
func (b *BMP) LookupRoute(rd string, a netip.Addr) (enrich.RouteInfo, bool) {
	if !b.enabled.Load() {
		return enrich.RouteInfo{}, false
	}
	r, ok := b.RIB.LookupRD(b.parseRD(rd), a)
	if !ok {
		return enrich.RouteInfo{}, false
	}
	return enrich.RouteInfo{OriginAS: r.OriginAS(), ASPath: r.ASPath, Communities: r.Communities,
		LargeCommunities: r.LargeText, NextHop: r.NextHop}, true
}

// parseRD converts the route distinguisher of an Inventory DB VRF; unset or
// invalid ones select the global table. Results are cached: the enricher
// asks for the same few VRFs for every flow.
func (b *BMP) parseRD(s string) uint64 {
	if s == "" {
		return 0
	}
	if v, ok := b.rds.Load(s); ok {
		return v.(uint64)
	}
	rd, err := bmp.ParseRD(s)
	if err != nil {
		rd = 0
	}
	if b.nrds.Add(1) <= 4096 {
		b.rds.Store(s, rd)
	}
	return rd
}

// attach gives the enricher whose AS provider order follows the settings.
func (b *BMP) attach(e *enrich.Enricher) {
	b.mu.Lock()
	b.enr = e
	b.applied = "" // apply the order on the next refresh
	b.mu.Unlock()
}

// Refresh re-reads the settings and starts / stops / reconfigures the receiver.
func (b *BMP) Refresh(ctx context.Context) error {
	if b.st == nil {
		return nil
	}
	var s bmp.Settings
	if _, err := b.st.Setting(ctx, app.SettingBMP, &s); err != nil {
		return err
	}
	s, err := s.Normalize()
	if err != nil {
		return err
	}
	key, _ := json.Marshal(s)
	b.mu.Lock()
	defer b.mu.Unlock()
	if string(key) == b.applied && (!s.Enabled || b.srv != nil) {
		return nil
	}
	base := b.base
	if base == nil {
		base = context.WithoutCancel(ctx)
	}
	switch {
	case s.Enabled && b.srv == nil:
		srv := bmp.NewServer(bmp.Config{Listen: b.listen, Logger: b.log, Metrics: b.m}, b.RIB)
		if err := srv.Apply(s); err != nil {
			return err
		}
		if err := srv.Listen(); err != nil {
			b.lastErr = err.Error()
			return err
		}
		sctx, cancel := context.WithCancel(base)
		b.srv, b.stop, b.lastErr = srv, cancel, ""
		go func() {
			if err := srv.Run(sctx); err != nil {
				b.log.Warn("BMP receiver stopped", "err", err)
			}
		}()
		b.log.Info("BMP receiver started", "listen", srv.Addr().String(), "policy", s.Policy)
	case !s.Enabled && b.srv != nil:
		b.stop()
		b.srv, b.stop = nil, nil
		b.log.Info("BMP receiver stopped")
	case b.srv != nil:
		if err := b.srv.Apply(s); err != nil {
			return err
		}
	}
	b.enabled.Store(s.Enabled)
	if b.enr != nil {
		order := []string(nil)
		if s.Enabled {
			order = s.ASProviders
		}
		if err := b.enr.SetASProviders(order); err != nil {
			return err
		}
	}
	b.applied = string(key)
	return nil
}

// Run applies the settings and re-reads them every minute until ctx ends.
func (b *BMP) Run(ctx context.Context) {
	b.mu.Lock()
	b.base = ctx
	b.mu.Unlock()
	refresh := func() {
		if err := b.Refresh(ctx); err != nil {
			b.log.Warn("BMP settings not applied", "err", err)
		}
	}
	refresh()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}

// Reload implements app.Reloader.
func (b *BMP) Reload(ctx context.Context, what string) error {
	if what == app.ReloadBMP {
		return b.Refresh(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (b *BMP) Status(context.Context) any {
	b.mu.Lock()
	srv, lastErr := b.srv, b.lastErr
	b.mu.Unlock()
	out := map[string]any{"enabled": b.enabled.Load(), "listen": b.listen, "rib": b.RIB.Stats()}
	if lastErr != "" {
		out["error"] = lastErr
	}
	if srv != nil {
		out["listen"] = srv.Addr().String()
		out["sessions"] = srv.Sessions()
	} else {
		out["sessions"] = []bmp.Session{}
	}
	peers := b.RIB.Peers()
	if len(peers) > 1000 {
		peers = peers[:1000]
	}
	out["peers"] = peers
	return out
}

// Routing groups the SNMP poller and the BMP receiver of the enricher
// process; it implements app.RoutingService.
type Routing struct {
	SNMP *SNMP
	BMP  *BMP
}

// NewRouting builds both components (disabled until their settings enable them).
func NewRouting(st *store.Store, vault *secrets.Client, reg prometheus.Registerer, log *slog.Logger) (*Routing, error) {
	s, err := NewSNMP(st, vault, reg, log)
	if err != nil {
		return nil, err
	}
	b, err := NewBMP(st, BMPListenFromEnv(), reg, log)
	if err != nil {
		return nil, err
	}
	return &Routing{SNMP: s, BMP: b}, nil
}

// configure adds SNMP after the collector's interface names and the BMP
// routes to the enricher configuration.
func (r *Routing) configure(ec *enrich.Config) {
	if r == nil {
		return
	}
	if r.SNMP != nil {
		ec.IfNames = enrich.IfNameChain(ec.IfNames, r.SNMP.P)
	}
	if r.BMP != nil {
		ec.Routing = r.BMP
	}
}

func (r *Routing) attach(e *enrich.Enricher) {
	if r != nil && r.BMP != nil {
		r.BMP.attach(e)
	}
}

// Run runs both components until ctx ends.
func (r *Routing) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { r.SNMP.Run(ctx) })
	wg.Go(func() { r.BMP.Run(ctx) })
	wg.Wait()
}

// Reload implements app.Reloader.
func (r *Routing) Reload(ctx context.Context, what string) error {
	switch what {
	case app.ReloadSNMP:
		return r.SNMP.Refresh(ctx)
	case app.ReloadBMP:
		return r.BMP.Refresh(ctx)
	}
	return nil
}

// SNMPStatus implements app.RoutingService.
func (r *Routing) SNMPStatus() any { return r.SNMP.Status(context.Background()) }

// BMPStatus implements app.RoutingService.
func (r *Routing) BMPStatus() any { return r.BMP.Status(context.Background()) }

// BMPLookup implements app.RoutingService.
func (r *Routing) BMPLookup(rd uint64, a netip.Addr) (any, bool) {
	rt, ok := r.BMP.RIB.LookupRD(rd, a)
	if !ok {
		return nil, false
	}
	large := rt.LargeText
	if large == nil {
		large = []string{}
	}
	comms := make([]string, len(rt.Communities))
	for i, c := range rt.Communities {
		comms[i] = formatCommunity(c)
	}
	path := rt.ASPath
	if path == nil {
		path = []uint32{}
	}
	rdText := ""
	if rt.RD != 0 {
		rdText = bmp.FormatRD(rt.RD)
	}
	return map[string]any{"prefix": rt.Prefix.String(), "rd": rdText, "origin_as": rt.OriginAS(), "as_path": path, "communities": comms,
		"large_communities": large, "next_hop": addrText(rt.NextHop), "peer": map[string]any{"router": rt.Peer.Router,
			"address": rt.Peer.Address, "as": rt.Peer.AS, "post_policy": rt.Peer.Post}}, true
}

func formatCommunity(c uint32) string {
	return strconv.FormatUint(uint64(c>>16), 10) + ":" + strconv.FormatUint(uint64(c&0xffff), 10)
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
