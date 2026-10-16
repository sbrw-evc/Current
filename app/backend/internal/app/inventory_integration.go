package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/access"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/setup"
)

// Current's side of the Current ↔ Ledger contract (docs/integrations.md §2):
//
//   - GET  /api/integrations/inventory-db/status            traffic of DCIM objects (token with integrations.inventory:read)
//   - GET  /api/integrations/inventory-db/prefix-addresses  addresses seen inside a prefix
//   - POST /api/integrations/inventory-db/hook              change notifications, HMAC-signed, no session
//   - GET|PUT /api/inventory-db/integration                 hook secret and editor token (write-only, OpenBao)
//   - POST /api/inventory-db/unknown/create                 "Create in Ledger" from the Unknown lists

// InventoryIntegration implements the traffic side of the integration
// (internal/wiring). A nil dependency makes the endpoints answer 501.
type InventoryIntegration interface {
	// Status → {"window", "results": {"<id>": {...}}} for ids of objectType
	// (dcim.device, dcim.interface, circuits.circuit); unknown ids are omitted.
	Status(ctx context.Context, objectType string, ids []int, window time.Duration, windowText string) (any, error)
	// PrefixAddresses → {"prefix", "results": [{address, bytes, flows, last_seen, in_ipam}]}.
	PrefixAddresses(ctx context.Context, prefix netip.Prefix, vrf string, window time.Duration) (any, error)
	// RequestSync schedules an early Ledger synchronization (debounced)
	// in this process and in the enricher / detector processes.
	RequestSync()
	// CreateAddress creates addr as an IPAM address in Ledger with an
	// editor token; the result is Ledger's object (at least id, address).
	CreateAddress(ctx context.Context, url, token string, addr netip.Addr) (any, error)
}

// Where the integration secrets live in OpenBao.
const (
	inventoryHookSecretPath  = "inventory-db-hook"
	inventoryHookSecretKey   = "secret"
	inventoryWriteTokenPath  = "inventory-db-write"
	inventoryWriteTokenKey   = "token"
	inventoryHookMaxAge      = 5 * time.Minute
	inventoryHookMaxBody     = 1 << 20
	inventoryStatusMaxIDs    = 1000
	inventoryStatusMinWindow = 15 * time.Minute
	inventoryStatusMaxWindow = 31 * 24 * time.Hour
)

// Headers of the change-notification hook (as Ledger's Beacon webhook).
const (
	InventoryTimestampHeader = "X-Inventory-Timestamp"
	InventorySignatureHeader = "X-Inventory-Signature"
)

// inventoryIntegrationRoutes registers the integration endpoints.
func (a *App) inventoryIntegrationRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/integrations/inventory-db/status", a.guard(perms(access.IntegrationsInventoryRead), a.inventoryStatus))
	h("GET /api/integrations/inventory-db/prefix-addresses", a.guard(perms(access.IntegrationsInventoryRead), a.inventoryPrefixAddresses))
	h("POST /api/integrations/inventory-db/hook", a.inventoryHook)
	h("GET /api/inventory-db/integration", a.guard(perms(access.InventoryView), a.getInventoryIntegration))
	h("PUT /api/inventory-db/integration", a.guard(perms(access.InventoryEdit), a.putInventoryIntegration))
	h("POST /api/inventory-db/unknown/create", a.guard(perms(access.InventoryEdit), a.createUnknownAddress))
}

// ParseWindow reads a window such as "24h", "90m", "7d" (days are accepted
// on top of Go durations).
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		d, err := strconv.Atoi(n)
		if err != nil || d <= 0 {
			return 0, errors.New("invalid window")
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("invalid window")
	}
	return d, nil
}

func windowParam(r *http.Request) (time.Duration, string, error) {
	text := r.URL.Query().Get("window")
	if text == "" {
		text = "24h"
	}
	d, err := ParseWindow(text)
	if err != nil || d < inventoryStatusMinWindow || d > inventoryStatusMaxWindow {
		return 0, "", httpx.BadRequest("invalid_window", "window must be a duration from 15m to 31d, like 24h or 7d")
	}
	return d, text, nil
}

func (a *App) inventoryStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.InventoryIntegration == nil {
		notImplemented(w, "Ledger integration")
		return
	}
	q := r.URL.Query()
	typ := q.Get("object_type")
	switch typ {
	case "dcim.device", "dcim.interface", "circuits.circuit":
	default:
		httpx.Error(w, http.StatusBadRequest, "invalid_object_type", "object_type must be dcim.device, dcim.interface or circuits.circuit")
		return
	}
	var ids []int
	for _, part := range strings.Split(q.Get("ids"), ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil || id <= 0 {
			httpx.Error(w, http.StatusBadRequest, "invalid_ids", "ids must be a comma-separated list of positive integers")
			return
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(ids) > inventoryStatusMaxIDs {
		httpx.Error(w, http.StatusBadRequest, "invalid_ids", "ids must list 1 to 1000 objects")
		return
	}
	window, text, err := windowParam(r)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out, err := a.deps.InventoryIntegration.Status(r.Context(), typ, ids, window, text)
	reply(w, out, err)
}

func (a *App) inventoryPrefixAddresses(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.InventoryIntegration == nil {
		notImplemented(w, "Ledger integration")
		return
	}
	q := r.URL.Query()
	raw := strings.TrimSpace(q.Get("prefix"))
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		addr, err2 := netip.ParseAddr(raw)
		if err2 != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_prefix", "prefix must be a CIDR such as 10.0.0.0/24")
			return
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}
	if pfx.Addr().Is4In6() {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), max(pfx.Bits()-96, 0))
	}
	window, _, err := windowParam(r)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out, err := a.deps.InventoryIntegration.PrefixAddresses(r.Context(), pfx.Masked(), strings.TrimSpace(q.Get("vrf")), window)
	reply(w, out, err)
}

// VerifyInventorySignature checks x-inventory-timestamp / x-inventory-signature
// of a hook request: "v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>",
// several comma-separated signatures during a secret rotation (any may
// match), and a timestamp at most 5 minutes away from now.
func VerifyInventorySignature(secret, timestamp, signature string, body []byte, now time.Time) error {
	if secret == "" {
		return errors.New("no hook secret is configured")
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return errors.New("missing or invalid timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > inventoryHookMaxAge || d < -inventoryHookMaxAge {
		return errors.New("timestamp too old or in the future")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.TrimSpace(timestamp)))
	mac.Write([]byte("."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, part := range strings.Split(signature, ",") {
		v, ok := strings.CutPrefix(strings.TrimSpace(part), "v1=")
		if !ok {
			continue
		}
		got, err := hex.DecodeString(v)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

// inventoryHook receives Ledger change notifications (§2.2): 401 on
// any verification failure, else 202 and an early (debounced) sync.
func (a *App) inventoryHook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	unauthorized := func(reason string) {
		slog.Warn("Ledger hook rejected", "reason", reason, "remote", httpx.ClientIP(r, a.opt.TrustedProxies))
		httpx.Error(w, http.StatusUnauthorized, "unauthorized", "invalid or missing hook signature")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, inventoryHookMaxBody+1))
	if err != nil || len(body) > inventoryHookMaxBody {
		unauthorized("body unreadable or too large")
		return
	}
	c, err := a.st.InventoryIntegration(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if c.HookSecretRef == "" {
		unauthorized("no hook secret configured")
		return
	}
	secret, err := a.secret(c.HookSecretRef)
	if err != nil {
		slog.Error("Ledger hook secret not readable", "err", err)
		unauthorized("hook secret not readable")
		return
	}
	if err := VerifyInventorySignature(secret, r.Header.Get(InventoryTimestampHeader), r.Header.Get(InventorySignatureHeader), body, time.Now()); err != nil {
		unauthorized(err.Error())
		return
	}
	var in struct {
		IntegrationID string            `json:"integration_id"`
		Events        []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "the body must be a JSON object")
		return
	}
	if a.deps.InventoryIntegration != nil {
		a.deps.InventoryIntegration.RequestSync()
	} else {
		a.reload(ctx, ReloadInventory)
	}
	slog.Debug("Ledger hook accepted", "integration", in.IntegrationID, "events", len(in.Events))
	httpx.JSON(w, http.StatusAccepted, map[string]any{"accepted": len(in.Events)})
}

type inventoryIntegrationView struct {
	HookSecretSet bool   `json:"hook_secret_set"`
	WriteTokenSet bool   `json:"write_token_set"`
	HookURL       string `json:"hook_url"`      // to enter in Ledger's flow integration
	InventoryURL  string `json:"inventory_url"` // Ledger address (links to its UI)
}

func (a *App) getInventoryIntegration(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	c, err := a.st.InventoryIntegration(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	conn, err := a.st.InventoryDB(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	var general setup.General
	_, _ = a.st.Setting(ctx, setup.SettingGeneral, &general)
	httpx.JSON(w, http.StatusOK, inventoryIntegrationView{HookSecretSet: c.HookSecretRef != "", WriteTokenSet: c.WriteTokenRef != "",
		HookURL: strings.TrimRight(general.PublicURL, "/") + "/api/integrations/inventory-db/hook", InventoryURL: conn.URL})
}

func (a *App) putInventoryIntegration(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		HookSecret *string `json:"hook_secret"` // nil = keep, "" = remove
		WriteToken *string `json:"write_token"` // nil = keep, "" = remove
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	c, err := a.st.InventoryIntegration(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	set := func(v *string, path, key string, ref *string) bool {
		if v == nil {
			return true
		}
		if s := strings.TrimSpace(*v); s != "" {
			if *ref, err = a.putSecret(ctx, path, key, s); err != nil {
				httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
				return false
			}
			return true
		}
		a.deleteSecret(ctx, path)
		*ref = ""
		return true
	}
	if !set(in.HookSecret, inventoryHookSecretPath, inventoryHookSecretKey, &c.HookSecretRef) ||
		!set(in.WriteToken, inventoryWriteTokenPath, inventoryWriteTokenKey, &c.WriteTokenRef) {
		return
	}
	if err := a.st.SetInventoryIntegration(ctx, c); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "inventory_db.integration.update", "", map[string]any{"hook_secret_changed": in.HookSecret != nil,
		"write_token_changed": in.WriteToken != nil, "hook_secret_set": c.HookSecretRef != "", "write_token_set": c.WriteTokenRef != ""})
	a.getInventoryIntegration(w, r, p)
}

func (a *App) createUnknownAddress(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.InventoryIntegration == nil {
		notImplemented(w, "Ledger integration")
		return
	}
	var in struct {
		Address string `json:"address"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(in.Address))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_address", "address must be an IP address")
		return
	}
	addr = addr.Unmap()
	ctx := r.Context()
	c, err := a.st.InventoryIntegration(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if c.WriteTokenRef == "" {
		httpx.Error(w, http.StatusConflict, "write_token_required", "no Ledger editor token is configured")
		return
	}
	conn, err := a.st.InventoryDB(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if conn.URL == "" {
		httpx.Error(w, http.StatusConflict, "inventory_not_configured", "the Ledger address is not set")
		return
	}
	token, err := a.secret(c.WriteTokenRef)
	if err != nil {
		httpx.Error(w, http.StatusBadGateway, "openbao_read_failed", err.Error())
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	obj, err := a.deps.InventoryIntegration.CreateAddress(cctx, conn.URL, token, addr)
	if err != nil {
		if status, _ := httpx.StatusOf(err); status == http.StatusInternalServerError {
			err = &httpx.HTTPError{Status: http.StatusBadGateway, Code: "inventory_error", Msg: err.Error(), Err: err}
		}
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "inventory_db.address.create", addr.String(), nil)
	a.deps.InventoryIntegration.RequestSync()
	httpx.JSON(w, http.StatusCreated, map[string]any{"ok": true, "address": addr.String(), "object": obj})
}
