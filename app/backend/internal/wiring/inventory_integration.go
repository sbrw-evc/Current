package wiring

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/inventory"
	"github.com/sbrw-evc/current/app/backend/internal/query"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/setup"
	"github.com/sbrw-evc/current/app/backend/internal/store"
)

// Debounce of early synchronizations requested by Ledger hooks
// (variables for tests).
var (
	HookSyncDelay = 5 * time.Second  // coalesces a burst of notifications
	HookSyncGap   = 30 * time.Second // at most one early sync per gap
)

// InventoryIntegration implements app.InventoryIntegration (docs/integrations.md
// §2): traffic of Ledger objects and of prefixes from ClickHouse,
// resolved against the Ledger snapshot, early syncs on hooks and
// "Create in Ledger".
type InventoryIntegration struct {
	// Q runs the ClickHouse queries; nil answers 503 for the traffic endpoints.
	Q *query.Querier
	// Snapshot returns the current Ledger snapshot (never nil).
	Snapshot func(ctx context.Context) *inventory.Snapshot
	// Store holds the general settings (public URL) and the sync request
	// that the Inventory loops of other processes follow.
	Store *store.Store
	// Wake asks the Inventory loops of this process for a sync now (they
	// sync when the request in Store is newer than their last sync).
	Wake []func()
	// HTTP is the client for Ledger writes (default: 30 s timeout).
	HTTP *http.Client
	Log  *slog.Logger

	mu       sync.Mutex
	pending  bool
	lastFire time.Time
}

// NewInventoryIntegration builds the integration. local is the Inventory loop
// of this process (role all); without one (api role) the snapshot is loaded
// on demand with the stored connection and kept as long as it is current.
func NewInventoryIntegration(q *query.Querier, st *store.Store, vault secrets.Resolver, local *Inventory, log *slog.Logger) *InventoryIntegration {
	if log == nil {
		log = slog.Default()
	}
	ii := &InventoryIntegration{Q: q, Store: st, Log: log.With("component", "inventory-integration")}
	if local != nil {
		ii.Snapshot = func(context.Context) *inventory.Snapshot { return local.Current() }
		ii.Wake = append(ii.Wake, func() { _ = local.Reload(context.Background(), app.ReloadInventory) })
		return ii
	}
	lazy := &lazySnapshot{inv: NewInventory(st, vault, log, nil)}
	ii.Snapshot = lazy.get
	ii.Wake = append(ii.Wake, lazy.invalidate)
	return ii
}

// lazySnapshot loads the Ledger snapshot on first use and refreshes it
// in the background (on its interval, a settings change or a sync request)
// at most once a minute, for processes without an Inventory loop.
type lazySnapshot struct {
	inv     *Inventory
	mu      sync.Mutex
	checked time.Time
	running bool
}

func (l *lazySnapshot) get(ctx context.Context) *inventory.Snapshot {
	s := l.inv.Current()
	l.mu.Lock()
	due := time.Since(l.checked) >= time.Minute && !l.running
	if due {
		l.checked, l.running = time.Now(), true
	}
	l.mu.Unlock()
	if !due {
		return s
	}
	run := func() {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := l.inv.tick(tctx); err != nil {
			l.inv.log.Warn("Ledger snapshot not loaded", "err", err)
		}
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()
	}
	if s.At().IsZero() {
		run() // first use: wait for the data
		return l.inv.Current()
	}
	go run()
	return s
}

func (l *lazySnapshot) invalidate() {
	l.mu.Lock()
	l.checked = time.Time{}
	l.mu.Unlock()
}

// RequestSync implements app.InventoryIntegration: after HookSyncDelay
// (and no sooner than HookSyncGap after the previous one) it records a sync
// request in PostgreSQL — the Inventory loops of the enricher / detector
// processes follow it within a minute — and wakes the loops of this process.
func (ii *InventoryIntegration) RequestSync() {
	ii.mu.Lock()
	defer ii.mu.Unlock()
	if ii.pending {
		return
	}
	ii.pending = true
	delay := HookSyncDelay
	if next := time.Until(ii.lastFire.Add(HookSyncGap)); next > delay {
		delay = next
	}
	time.AfterFunc(delay, ii.fireSync)
}

func (ii *InventoryIntegration) fireSync() {
	ii.mu.Lock()
	ii.pending, ii.lastFire = false, time.Now()
	ii.mu.Unlock()
	if ii.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := ii.Store.PutSetting(ctx, SettingInventorySyncRequest, syncRequest{At: time.Now().UTC()})
		cancel()
		if err != nil {
			ii.log().Warn("Ledger sync request not recorded", "err", err)
		}
	}
	for _, w := range ii.Wake {
		w()
	}
}

func (ii *InventoryIntegration) log() *slog.Logger {
	if ii.Log == nil {
		return slog.Default()
	}
	return ii.Log
}

func (ii *InventoryIntegration) snapshot(ctx context.Context) *inventory.Snapshot {
	if ii.Snapshot == nil {
		return inventory.Empty()
	}
	if s := ii.Snapshot(ctx); s != nil {
		return s
	}
	return inventory.Empty()
}

func (ii *InventoryIntegration) publicURL(ctx context.Context) string {
	var g setup.General
	if ii.Store != nil {
		_, _ = ii.Store.Setting(ctx, setup.SettingGeneral, &g)
	}
	return strings.TrimRight(g.PublicURL, "/")
}

var errNoClickHouse = &httpx.HTTPError{Status: http.StatusServiceUnavailable, Code: "clickhouse_unavailable", Msg: "ClickHouse is not available"}

// objectMeta is what the snapshot says about a requested object.
type objectMeta struct {
	speed  uint64
	commit uint64
	p95    bool
	filter string
	dims   []string
}

// Status implements app.InventoryIntegration.
func (ii *InventoryIntegration) Status(ctx context.Context, typ string, ids []int, window time.Duration, windowText string) (any, error) {
	if ii.Q == nil {
		return nil, errNoClickHouse
	}
	snap := ii.snapshot(ctx)
	hasDevices := len(snap.Devices()) > 0
	var targets []query.ObjectTarget
	meta := map[string]objectMeta{}
	var circuitSpeed map[string]uint64
	if typ == query.ObjectCircuit {
		circuitSpeed = map[string]uint64{}
		for _, d := range snap.Devices() {
			for _, it := range snap.Interfaces(d.ID) {
				if it.Circuit != "" {
					circuitSpeed[it.Circuit] = max(circuitSpeed[it.Circuit], it.Speed)
				}
			}
		}
	}
	for _, id := range ids {
		key := strconv.Itoa(id)
		if _, dup := meta[key]; dup {
			continue
		}
		switch typ {
		case query.ObjectDevice:
			ref := inventory.DeviceRef(id)
			if d, ok := snap.Device(id); ok {
				ref = d.Ref
			} else if hasDevices {
				continue
			}
			targets = append(targets, query.ObjectTarget{ID: key, Ref: ref})
			meta[key] = objectMeta{filter: "ExporterRef = " + filterString(ref), dims: []string{"InIfName"}}
		case query.ObjectInterface:
			it, ok := snap.InterfaceByID(id)
			if !ok {
				continue
			}
			ref := inventory.DeviceRef(it.DeviceID)
			if d, ok := snap.Device(it.DeviceID); ok && d.Ref != "" {
				ref = d.Ref
			}
			m := objectMeta{speed: it.Speed, p95: it.Circuit != "", commit: it.CommitRate, dims: []string{"SrcAS"},
				filter: fmt.Sprintf("ExporterRef = %s AND (InIfName = %s OR OutIfName = %s)", filterString(ref),
					filterString(it.Name), filterString(it.Name))}
			targets = append(targets, query.ObjectTarget{ID: key, Ref: ref, IfName: it.Name, P95: m.p95})
			meta[key] = m
		case query.ObjectCircuit:
			c, ok := snap.Circuit(id)
			if !ok || c.CID == "" {
				continue
			}
			targets = append(targets, query.ObjectTarget{ID: key, Circuit: c.CID, P95: true})
			meta[key] = objectMeta{speed: circuitSpeed[c.CID], commit: c.CommitRate, p95: true, dims: []string{"SrcAS"},
				filter: fmt.Sprintf("InIfCircuit = %s OR OutIfCircuit = %s", filterString(c.CID), filterString(c.CID))}
		default:
			return nil, httpx.BadRequest("invalid_object_type", "object_type must be dcim.device, dcim.interface or circuits.circuit")
		}
	}
	traffic, err := ii.Q.ObjectTraffic(ctx, query.ObjectTrafficRequest{Type: typ, Targets: targets, Window: window})
	if err != nil {
		return nil, MapError(err)
	}
	base := ii.publicURL(ctx)
	results := map[string]any{}
	for _, t := range targets {
		o, m := traffic[t.ID], meta[t.ID]
		if o == nil {
			o = &query.ObjectTraffic{}
		}
		speed := m.speed
		if speed == 0 && typ != query.ObjectDevice {
			speed = o.SpeedBps
		}
		r := map[string]any{
			"in_bps": round(o.InBps), "out_bps": round(o.OutBps),
			"speed_bps": nil, "utilization_in": nil, "utilization_out": nil,
			"sparkline": map[string]any{"t": o.Sparkline.T, "in": roundAll(o.Sparkline.In), "out": roundAll(o.Sparkline.Out)},
			"flow_url":  base + VisualizeLink(windowText, window, m.filter, m.dims),
			"last_seen": o.LastSeen,
		}
		if speed > 0 {
			r["speed_bps"] = speed
			r["utilization_in"] = ratio(o.InBps, speed)
			r["utilization_out"] = ratio(o.OutBps, speed)
		}
		if m.p95 {
			r["p95_month_bps"], r["commit_bps"], r["over_commit"] = nil, nil, nil
			if o.P95MonthBps != nil {
				r["p95_month_bps"] = round(*o.P95MonthBps)
			}
			if m.commit > 0 {
				r["commit_bps"] = m.commit
				if o.P95MonthBps != nil {
					r["over_commit"] = *o.P95MonthBps > float64(m.commit)
				}
			}
		}
		results[t.ID] = r
	}
	return map[string]any{"window": windowText, "results": results}, nil
}

func round(v float64) float64 { return math.Round(v) }

func roundAll(v []float64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = math.Round(x)
	}
	return out
}

func ratio(v float64, speed uint64) float64 {
	return math.Round(v/float64(speed)*10000) / 10000
}

// filterString quotes s as a string of the filter language.
func filterString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// visualizePresets are the time presets of the console (web/src/lib/time.ts).
var visualizePresets = map[string]bool{"15m": true, "1h": true, "6h": true, "24h": true, "7d": true, "30d": true}

// VisualizeLink returns the console link (/visualize?q=…) of a filter over
// the window, in the format of web/src/pages/visualize/state.ts: base64url of
// the compact state {r, g, u, d, l, f}.
func VisualizeLink(windowText string, window time.Duration, filter string, dims []string) string {
	type compact struct {
		R any      `json:"r"`
		G string   `json:"g"`
		U string   `json:"u"`
		D []string `json:"d"`
		L int      `json:"l"`
		F string   `json:"f"`
	}
	c := compact{G: "stacked", U: "l3bps", D: dims, L: 10, F: filter}
	if c.D == nil {
		c.D = []string{}
	}
	if visualizePresets[windowText] {
		c.R = windowText
	} else {
		end := time.Now().UTC().Truncate(time.Minute)
		c.R = []string{end.Add(-window).Format(time.RFC3339), end.Format(time.RFC3339)}
	}
	b, _ := json.Marshal(c)
	return "/visualize?q=" + base64.RawURLEncoding.EncodeToString(b)
}

// PrefixAddresses implements app.InventoryIntegration.
func (ii *InventoryIntegration) PrefixAddresses(ctx context.Context, prefix netip.Prefix, vrf string, window time.Duration) (any, error) {
	if ii.Q == nil {
		return nil, errNoClickHouse
	}
	list, err := ii.Q.PrefixAddresses(ctx, prefix, vrf, window)
	if err != nil {
		return nil, MapError(err)
	}
	snap := ii.snapshot(ctx)
	type result struct {
		Address  string    `json:"address"`
		Bytes    uint64    `json:"bytes"`
		Flows    uint64    `json:"flows"`
		LastSeen time.Time `json:"last_seen"`
		InIPAM   bool      `json:"in_ipam"`
	}
	out := make([]result, 0, len(list))
	for _, p := range list {
		a, ok := snap.Address(p.Address)
		in := ok && (vrf == "" || strings.EqualFold(a.VRF, vrf))
		out = append(out, result{Address: p.Address.String(), Bytes: p.Bytes, Flows: p.Flows, LastSeen: p.LastSeen, InIPAM: in})
	}
	return map[string]any{"prefix": prefix.String(), "results": out}, nil
}

// CreateAddress implements app.InventoryIntegration: POST
// /api/v1/ipam/ip-addresses/ on Ledger with the editor token.
func (ii *InventoryIntegration) CreateAddress(ctx context.Context, baseURL, token string, addr netip.Addr) (any, error) {
	addr = addr.Unmap()
	body, _ := json.Marshal(map[string]any{
		"address":     netip.PrefixFrom(addr, addr.BitLen()).String(),
		"status":      "active",
		"description": "Discovered by Current",
		"tags":        []string{},
	})
	url := strings.TrimRight(baseURL, "/")
	url = strings.TrimSuffix(url, "/api/v1") + "/api/v1/ipam/ip-addresses/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("xc-token", token)
	c := ii.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Ledger: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Message + " " + e.Detail)
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 300 {
				msg = msg[:300]
			}
		}
		status := http.StatusBadGateway
		code := "inventory_error"
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity:
			status, code = http.StatusConflict, "inventory_rejected"
		case http.StatusUnauthorized, http.StatusForbidden:
			code = "inventory_forbidden"
		}
		return nil, &httpx.HTTPError{Status: status, Code: code,
			Msg: fmt.Sprintf("Ledger answered %d: %s", resp.StatusCode, msg), Err: errors.New(msg)}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return map[string]any{}, nil
	}
	out := map[string]any{}
	for _, k := range []string{"id", "address", "display", "url", "display_url"} {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}
