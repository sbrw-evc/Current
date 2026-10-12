package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// ---- saved views

type viewInput struct {
	Name    string          `json:"name"`
	Shared  bool            `json:"shared"`
	Request json.RawMessage `json:"request"`
}

func (in viewInput) check() error {
	if n := strings.TrimSpace(in.Name); n == "" || len([]rune(n)) > 128 {
		return httpx.BadRequest("invalid_name", "the name must have 1-128 characters")
	}
	var obj map[string]any
	if len(in.Request) == 0 || json.Unmarshal(in.Request, &obj) != nil {
		return httpx.BadRequest("invalid_request", "request must be a JSON object")
	}
	return nil
}

func (a *App) listViews(w http.ResponseWriter, r *http.Request, p *Principal) {
	views, err := a.st.SavedViews(r.Context(), p.User.ID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": views})
}

func (a *App) createView(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in viewInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := in.check(); err != nil {
		httpx.Err(w, err)
		return
	}
	v, err := a.st.CreateSavedView(r.Context(), p.User.ID, in.Name, in.Shared, in.Request)
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, v)
}

// ownView loads a view the principal may change: their own, or any with users:edit.
func (a *App) ownView(w http.ResponseWriter, r *http.Request, p *Principal) (store.SavedView, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return store.SavedView{}, false
	}
	v, err := a.st.SavedView(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return v, false
	}
	if v.OwnerID != p.User.ID && !p.Perms.Has(access.UsersEdit) {
		if !v.Shared {
			httpx.Error(w, http.StatusNotFound, "not_found", "not found")
		} else {
			httpx.Error(w, http.StatusForbidden, "forbidden", "only the owner can change a saved view")
		}
		return v, false
	}
	return v, true
}

func (a *App) updateView(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in viewInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := in.check(); err != nil {
		httpx.Err(w, err)
		return
	}
	v, ok := a.ownView(w, r, p)
	if !ok {
		return
	}
	v, err := a.st.UpdateSavedView(r.Context(), v.ID, in.Name, in.Shared, in.Request)
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *App) deleteView(w http.ResponseWriter, r *http.Request, p *Principal) {
	v, ok := a.ownView(w, r, p)
	if !ok {
		return
	}
	if err := a.st.DeleteSavedView(r.Context(), v.ID); err != nil {
		storeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- classifiers

func (a *App) getClassifiers(w http.ResponseWriter, r *http.Request, p *Principal) {
	c, err := a.st.Classifiers(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

func (a *App) putClassifiers(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in map[string][]string
	if !httpx.Decode(w, r, &in) {
		return
	}
	known := map[string]bool{}
	for _, k := range store.ClassifierKinds {
		known[k] = true
	}
	for kind, rules := range in {
		if !known[kind] {
			httpx.Error(w, http.StatusBadRequest, "invalid_kind", "unknown classifier kind "+kind)
			return
		}
		clean := make([]string, 0, len(rules))
		for _, rule := range rules {
			if rule = strings.TrimSpace(rule); rule != "" {
				clean = append(clean, rule)
			}
		}
		if len(clean) > 500 {
			httpx.Error(w, http.StatusBadRequest, "too_many_rules", "at most 500 rules per kind")
			return
		}
		in[kind] = clean
		if a.deps.Classifiers != nil {
			if err := a.deps.Classifiers.Validate(kind, clean); err != nil {
				if status, _ := httpx.StatusOf(err); status == http.StatusInternalServerError {
					err = httpx.BadRequest("invalid_rule", err.Error())
				}
				httpx.Err(w, err)
				return
			}
		}
	}
	ctx := r.Context()
	if err := a.st.SetClassifiers(ctx, in); err != nil {
		httpx.Err(w, err)
		return
	}
	counts := map[string]int{}
	for k, v := range in {
		counts[k] = len(v)
	}
	a.audit(ctx, p, "classifiers.update", "", counts)
	a.reload(ctx, ReloadClassifiers)
	a.getClassifiers(w, r, p)
}

func (a *App) previewClassifiers(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Classifiers == nil {
		notImplemented(w, "classifier preview")
		return
	}
	var in struct {
		Kind   string          `json:"kind"`
		Rules  []string        `json:"rules"`
		Sample json.RawMessage `json:"sample"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	out, err := a.deps.Classifiers.Preview(r.Context(), in.Kind, in.Rules, in.Sample)
	reply(w, out, err)
}

// ---- Inventory DB

// Where the Inventory DB token lives in OpenBao.
const (
	inventorySecretPath = "inventory-db"
	inventorySecretKey  = "token"
)

type inventoryView struct {
	Enabled  bool              `json:"enabled"`
	URL      string            `json:"url"`
	TokenSet bool              `json:"token_set"`
	Interval string            `json:"interval"` // duration: "15m", "1h", "90s"
	LastSync *store.SyncResult `json:"last_sync"`
}

func (a *App) getInventory(w http.ResponseWriter, r *http.Request, p *Principal) {
	c, err := a.st.InventoryDB(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inventoryView{Enabled: c.Enabled, URL: c.URL, TokenSet: c.TokenRef != "",
		Interval: formatInterval(c.Interval), LastSync: c.LastSync})
}

// formatInterval prints a duration the way the console offers it: "15m",
// "1h", else seconds ("90s").
func formatInterval(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	default:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	}
}

// interval accepts seconds (a number) or a Go duration ("15m").
type interval time.Duration

func (d *interval) UnmarshalJSON(b []byte) error {
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*d = interval(time.Duration(n * float64(time.Second)))
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("interval must be seconds or a duration like 15m")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		if secs, err2 := strconv.Atoi(s); err2 == nil {
			v = time.Duration(secs) * time.Second
		} else {
			return fmt.Errorf("interval: %w", err)
		}
	}
	*d = interval(v)
	return nil
}

func checkURL(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", httpx.BadRequest("invalid_url", "the address must look like https://inventory.example")
	}
	return s, nil
}

func (a *App) putInventory(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Enabled  bool      `json:"enabled"`
		URL      string    `json:"url"`
		Token    *string   `json:"token"` // nil = keep, "" = remove
		Interval *interval `json:"interval"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	c, err := a.st.InventoryDB(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	c.Enabled = in.Enabled
	c.URL = strings.TrimSpace(in.URL)
	if c.URL != "" || c.Enabled {
		if c.URL, err = checkURL(c.URL); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	if in.Interval != nil {
		c.Interval = time.Duration(*in.Interval)
		if c.Interval < time.Minute || c.Interval > 7*24*time.Hour {
			httpx.Error(w, http.StatusBadRequest, "invalid_interval", "the interval must be between 1 minute and 7 days")
			return
		}
	}
	if in.Token != nil {
		if tok := strings.TrimSpace(*in.Token); tok != "" {
			if c.TokenRef, err = a.putSecret(ctx, inventorySecretPath, inventorySecretKey, tok); err != nil {
				httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
				return
			}
		} else {
			a.deleteSecret(ctx, inventorySecretPath)
			c.TokenRef = ""
		}
	}
	if c.Enabled && c.TokenRef == "" {
		httpx.Error(w, http.StatusBadRequest, "token_required", "the Inventory DB token is required")
		return
	}
	if err := a.st.SetInventoryDB(ctx, c); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "inventory_db.update", c.URL, map[string]any{"enabled": c.Enabled, "interval": int(c.Interval / time.Second),
		"token_changed": in.Token != nil})
	a.reload(ctx, ReloadInventory)
	a.getInventory(w, r, p)
}

// InventoryConfig returns the stored Inventory DB connection with the token resolved.
func (a *App) InventoryConfig(ctx context.Context) (InventoryConfig, bool, error) {
	c, err := a.st.InventoryDB(ctx)
	if err != nil {
		return InventoryConfig{}, false, err
	}
	out := InventoryConfig{URL: c.URL, Interval: c.Interval}
	if c.TokenRef != "" {
		if out.Token, err = a.secret(c.TokenRef); err != nil {
			return out, c.Enabled, fmt.Errorf("Inventory DB token: %w", err)
		}
	}
	return out, c.Enabled, nil
}

func (a *App) testInventory(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Inventory == nil {
		notImplemented(w, "Inventory DB")
		return
	}
	var in struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if r.ContentLength != 0 && !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	cfg, _, err := a.InventoryConfig(ctx)
	if err != nil && in.Token == "" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if in.URL != "" {
		if cfg.URL, err = checkURL(in.URL); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	if in.Token != "" {
		cfg.Token = in.Token
	}
	if cfg.URL == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid_url", "the Inventory DB address is not set")
		return
	}
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.deps.Inventory.Test(tctx, cfg); err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// SyncInventory runs one synchronization with the stored connection and
// records the result. Only one runs at a time.
func (a *App) SyncInventory(ctx context.Context) (store.SyncResult, error) {
	if a.deps.Inventory == nil {
		return store.SyncResult{}, errors.New("Inventory DB synchronization is not available")
	}
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	cfg, _, err := a.InventoryConfig(ctx)
	res := store.SyncResult{At: time.Now().UTC()}
	if err == nil && cfg.URL == "" {
		err = errors.New("the Inventory DB address is not set")
	}
	if err == nil {
		res.SyncStats, err = a.deps.Inventory.Sync(ctx, cfg)
	}
	res.OK = err == nil
	if err != nil {
		res.Error = err.Error()
	}
	if rerr := a.st.RecordInventorySync(context.WithoutCancel(ctx), res); rerr != nil {
		slog.Warn("inventory sync result not recorded", "err", rerr)
	}
	return res, err
}

func (a *App) syncInventory(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Inventory == nil {
		notImplemented(w, "Inventory DB")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	res, err := a.SyncInventory(ctx)
	a.audit(ctx, p, "inventory_db.sync", "", res)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "stats": res.SyncStats})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "stats": res.SyncStats})
}

func (a *App) runInventorySchedule(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		c, err := a.st.InventoryDB(ctx)
		if err == nil && c.Enabled && (c.LastSync == nil || time.Since(c.LastSync.At) >= c.Interval) {
			if res, err := a.SyncInventory(ctx); err != nil {
				slog.Warn("inventory sync failed", "err", err)
			} else {
				slog.Info("inventory synced", "devices", res.Devices, "interfaces", res.Interfaces, "prefixes", res.Prefixes, "circuits", res.Circuits)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) unknownInventory(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Inventory == nil {
		notImplemented(w, "Inventory DB")
		return
	}
	out, err := a.deps.Inventory.Unknown(r.Context())
	reply(w, out, err)
}

// ---- sampling overrides

func (a *App) getSampling(w http.ResponseWriter, r *http.Request, p *Principal) {
	o, err := a.st.SamplingOverrides(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": o})
}

func (a *App) putSampling(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Results []struct {
			Exporter string `json:"exporter"` // address or CIDR
			IfIndex  uint32 `json:"if_index"`
			Rate     uint64 `json:"rate"`
			Comment  string `json:"comment"`
		} `json:"results"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	out := make([]store.SamplingOverride, 0, len(in.Results))
	for _, o := range in.Results {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(o.Exporter))
		if err != nil {
			addr, err2 := netip.ParseAddr(strings.TrimSpace(o.Exporter))
			if err2 != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_exporter", "not an address or CIDR: "+o.Exporter)
				return
			}
			pfx = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		if o.Rate == 0 || o.Rate > 1<<31 {
			httpx.Error(w, http.StatusBadRequest, "invalid_rate", "the sampling rate must be positive")
			return
		}
		out = append(out, store.SamplingOverride{Exporter: pfx.Masked(), IfIndex: o.IfIndex, Rate: o.Rate, Comment: strings.TrimSpace(o.Comment)})
	}
	ctx := r.Context()
	if err := a.st.SetSamplingOverrides(ctx, out); err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "sampling.update", "", map[string]int{"overrides": len(out)})
	a.reload(ctx, ReloadSampling)
	a.getSampling(w, r, p)
}

// ---- status and audit

type check struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"`
}

func (a *App) status(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out := map[string]any{"version": a.opt.Version, "commit": a.opt.Commit, "built_at": a.opt.BuiltAt, "role": a.opt.Role}
	pg := check{OK: true}
	if err := a.st.Ping(ctx); err != nil {
		pg = check{Error: err.Error()}
	} else if v, err := a.st.Version(ctx); err == nil {
		pg.Version = "schema " + strconv.FormatInt(v, 10)
	}
	out["postgres"] = pg
	if a.deps.ClickHouse != nil {
		ch := check{OK: true}
		if err := a.deps.ClickHouse.Ping(ctx); err != nil {
			ch = check{Error: err.Error()}
		}
		out["clickhouse"] = ch
	} else {
		out["clickhouse"] = nil
	}
	if a.deps.Vault != nil {
		out["openbao"] = a.deps.Vault.Status(ctx)
	} else {
		out["openbao"] = map[string]any{"configured": false}
	}
	comps := map[string]any{}
	for name, c := range a.deps.Components {
		comps[name] = c.Status(ctx)
	}
	out["components"] = comps
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) listAudit(w http.ResponseWriter, r *http.Request, p *Principal) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := a.st.AuditLog(r.Context(), limit, before)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": entries})
}
