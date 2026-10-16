package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/access"
	"github.com/sbrw-evc/current/app/backend/internal/auth"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/store"
)

// API tokens (docs/integrations.md §1): service accounts with a role and
// bearer tokens "flow_…" that carry it. Tokens need no CSRF header. A token
// belongs to the person who created it and stops working while Keystone keeps
// that person disabled.

// SourceService is the source of the principal of a token request.
const SourceService = "service"

// touchTokenEvery limits last_used_at writes per token.
const touchTokenEvery = time.Minute

// tokenGuard authenticates a request with "Authorization: Bearer flow_…" and
// requires one of anyOf, as guard does for sessions.
func (a *App) tokenGuard(w http.ResponseWriter, r *http.Request, token string, anyOf []string, next handler) {
	ctx := r.Context()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	if !auth.WellFormedToken(token) {
		httpx.Error(w, http.StatusUnauthorized, "invalid_token", "the API token is invalid, expired or revoked")
		return
	}
	hash, err := auth.NewKeys(a.deps.Vault).TokenHash(ctx, token)
	if err != nil {
		slog.Error("token key not available", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "openbao_unavailable", "the token key store (OpenBao) is not available")
		return
	}
	tp, err := a.st.TokenByHash(ctx, hash)
	now := time.Now()
	if errors.Is(err, store.ErrNotFound) || (err == nil && (!tp.Token.Active(now) || tp.Account.Disabled || tp.OwnerDisabled)) {
		httpx.Error(w, http.StatusUnauthorized, "invalid_token", "the API token is invalid, expired or revoked")
		return
	}
	if err != nil {
		slog.Error("token lookup failed", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "storage_unavailable", "the configuration database is not available")
		return
	}
	t := tp.Token
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > touchTokenEvery || t.LastUsedFrom != remote {
		newAddr, err := a.st.TouchAPIToken(ctx, t.ID, remote, now.UTC())
		if err != nil {
			slog.Warn("token use not recorded", "err", err)
		} else if newAddr {
			_ = a.st.Audit(ctx, serviceName(tp.Account.Name), "token.use_new_address", tokenTarget(t), remote,
				map[string]any{"token_id": t.ID, "previous": t.LastUsedFrom})
		}
	}
	list, err := a.st.RolePermissions(ctx, tp.Account.RoleID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	p := &Principal{
		User: store.User{Username: serviceName(tp.Account.Name), Name: tp.Account.Name, Source: SourceService,
			RoleID: tp.Account.RoleID, Role: tp.Account.Role, CreatedAt: tp.Account.CreatedAt, UpdatedAt: tp.Account.UpdatedAt},
		Perms:   access.NewSet(list),
		Session: &auth.Session{}, // no cookie session: handlers that read it get empty values
		Remote:  remote,
	}
	if len(anyOf) > 0 && !p.Perms.Any(anyOf...) {
		httpx.Error(w, http.StatusForbidden, "forbidden", "you do not have the permission "+anyOf[0])
		return
	}
	next(w, r, p)
}

// serviceName is how a service account appears as an actor (audit, Principal).
func serviceName(name string) string { return "service:" + name }

func tokenTarget(t store.APIToken) string { return t.ServiceAccount + "/" + t.Name }

// ---- service accounts

func (a *App) listServiceAccounts(w http.ResponseWriter, r *http.Request, p *Principal) {
	list, err := a.st.ServiceAccounts(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": list})
}

// grantable checks that a role gives nothing the principal does not have:
// tokens:edit must not become a way to raise one's own rights.
func (a *App) grantable(ctx context.Context, p *Principal, roleID int64) error {
	perms, err := a.st.RolePermissions(ctx, roleID)
	if err != nil {
		return err
	}
	for _, perm := range perms {
		if perm != access.ScopeUmbrella && !p.Perms.Has(perm) {
			return &httpx.HTTPError{Status: http.StatusForbidden, Code: "role_not_grantable",
				Msg: "the role gives the permission " + perm + " that you do not have"}
		}
	}
	return nil
}

func (a *App) createServiceAccount(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		RoleID      int64  `json:"role_id"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 64 || strings.ContainsAny(in.Name, " \t\r\n/") {
		httpx.Error(w, http.StatusBadRequest, "invalid_name", "the name must have 1-64 characters without spaces or slashes")
		return
	}
	if len([]rune(in.Description)) > 512 {
		httpx.Error(w, http.StatusBadRequest, "invalid_description", "the description must have at most 512 characters")
		return
	}
	ctx := r.Context()
	if _, err := a.st.RoleByID(ctx, in.RoleID); errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such role")
		return
	} else if err != nil {
		httpx.Err(w, err)
		return
	}
	if err := a.grantable(ctx, p, in.RoleID); err != nil {
		httpx.Err(w, err)
		return
	}
	sa, err := a.st.CreateServiceAccount(ctx, in.Name, in.Description, in.RoleID, p.User.Username)
	if err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "service_account.create", sa.Name, map[string]any{"id": sa.ID, "role": sa.Role})
	httpx.JSON(w, http.StatusCreated, sa)
}

func (a *App) deleteServiceAccount(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	sa, err := a.st.ServiceAccount(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.st.DeleteServiceAccount(ctx, id); err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "service_account.delete", sa.Name, map[string]any{"id": sa.ID, "tokens": sa.Tokens})
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- tokens

type tokenView struct {
	store.APIToken
	Active bool `json:"active"`
}

func viewToken(t store.APIToken) tokenView {
	return tokenView{APIToken: t, Active: t.Active(time.Now())}
}

func (a *App) listTokens(w http.ResponseWriter, r *http.Request, p *Principal) {
	var account int64
	if v := r.URL.Query().Get("service_account_id"); v != "" {
		var err error
		if account, err = strconv.ParseInt(v, 10, 64); err != nil || account <= 0 {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid service_account_id")
			return
		}
	}
	list, err := a.st.APITokens(r.Context(), account)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := make([]tokenView, 0, len(list))
	for _, t := range list {
		out = append(out, viewToken(t))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": out})
}

// parseExpiry accepts RFC 3339 or a date (end of that day, UTC).
func parseExpiry(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		d, err2 := time.Parse(time.DateOnly, s)
		if err2 != nil {
			return nil, httpx.BadRequest("invalid_expiry", "expires_at must be a date (2026-12-31) or an RFC 3339 time")
		}
		t = d.Add(24*time.Hour - time.Second)
	}
	if !t.After(time.Now()) {
		return nil, httpx.BadRequest("invalid_expiry", "expires_at must be in the future")
	}
	if t.After(time.Now().AddDate(5, 0, 0)) {
		return nil, httpx.BadRequest("invalid_expiry", "expires_at must be within 5 years")
	}
	t = t.UTC()
	return &t, nil
}

func (a *App) createToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		ServiceAccountID int64  `json:"service_account_id"`
		Name             string `json:"name"`
		ExpiresAt        string `json:"expires_at"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 128 {
		httpx.Error(w, http.StatusBadRequest, "invalid_name", "the name must have 1-128 characters")
		return
	}
	exp, err := parseExpiry(in.ExpiresAt)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	ctx := r.Context()
	sa, err := a.st.ServiceAccount(ctx, in.ServiceAccountID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusBadRequest, "invalid_service_account", "no such service account")
		return
	} else if err != nil {
		httpx.Err(w, err)
		return
	}
	if err := a.grantable(ctx, p, sa.RoleID); err != nil {
		httpx.Err(w, err)
		return
	}
	token := auth.NewAPIToken()
	hash, err := auth.NewKeys(a.deps.Vault).TokenHash(ctx, token)
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "openbao_unavailable", err.Error())
		return
	}
	t, err := a.st.CreateAPIToken(ctx, store.NewAPIToken{ServiceAccountID: sa.ID, Name: in.Name, Hash: hash,
		Display: auth.TokenDisplay(token), ExpiresAt: exp, CreatedBy: p.User.Username, CreatedByID: p.User.ID})
	if err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "token.create", tokenTarget(t), map[string]any{"token_id": t.ID, "expires_at": t.ExpiresAt})
	httpx.JSON(w, http.StatusCreated, struct {
		tokenView
		Token string `json:"token"` // shown once
	}{viewToken(t), token})
}

func (a *App) revokeToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	t, err := a.st.RevokeAPIToken(ctx, id, p.User.Username)
	if err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "token.revoke", tokenTarget(t), map[string]any{"token_id": t.ID})
	httpx.JSON(w, http.StatusOK, viewToken(t))
}

func (a *App) tokenRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/service-accounts", a.guard(perms(access.TokensView), a.listServiceAccounts))
	h("POST /api/service-accounts", a.guard(perms(access.TokensEdit), a.createServiceAccount))
	h("DELETE /api/service-accounts/{id}", a.guard(perms(access.TokensEdit), a.deleteServiceAccount))
	h("GET /api/tokens", a.guard(perms(access.TokensView), a.listTokens))
	h("POST /api/tokens", a.guard(perms(access.TokensEdit), a.createToken))
	h("DELETE /api/tokens/{id}", a.guard(perms(access.TokensEdit), a.revokeToken))
}
