package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/entra"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Microsoft Entra ID sign-in (OpenID Connect, authorization code + PKCE), as
// in Umbrella Monitoring. Settings key "entra"; the client secret lives in
// OpenBao at entra#client_secret. Users are created on their first sign-in
// with the role of the first matching group mapping, else the default role.

const (
	settingEntra    = "entra"
	entraCookie     = "flow_entra"
	entraPendingTTL = 10 * time.Minute
	entraPendingMax = 10000
)

func (a *App) entraRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/entra", a.guard(perms(access.UsersView), a.getEntra))
	h("PUT /api/settings/entra", a.guard(perms(access.UsersEdit), a.putEntra))
	h("POST /api/settings/entra/test", a.guard(perms(access.UsersEdit), a.testEntra))
	h("GET /api/auth/entra", a.entraInfo)
	h("GET /api/auth/entra/start", a.entraStart)
	h("GET "+entra.CallbackPath, a.entraCallback)
}

// entraGroupRole maps an Entra group (object ID) to a role.
type entraGroupRole struct {
	GroupID string `json:"group_id"`
	RoleID  int64  `json:"role_id"`
	Role    string `json:"role,omitempty"`
}

type entraSettings struct {
	entra.Config
	DefaultRoleID int64            `json:"default_role_id"`
	GroupRoles    []entraGroupRole `json:"group_roles"`
}

func (a *App) entraSettings(ctx context.Context) (entraSettings, error) {
	var es entraSettings
	_, err := a.st.Setting(ctx, settingEntra, &es)
	if es.GroupRoles == nil {
		es.GroupRoles = []entraGroupRole{}
	}
	return es, err
}

type entraView struct {
	entraSettings
	ClientSecretSet bool `json:"client_secret_set"`
	Users           int  `json:"users"` // users signed in through Entra ID
}

func (a *App) getEntra(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	es, err := a.entraSettings(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	n := 0
	for _, u := range users {
		if u.Source == store.SourceEntra {
			n++
		}
	}
	for i, g := range es.GroupRoles {
		if role, err := a.st.RoleByID(ctx, g.RoleID); err == nil {
			es.GroupRoles[i].Role = role.Name
		}
	}
	set := es.ClientSecretRef != ""
	es.ClientSecretRef = ""
	if es.Cloud == "" {
		es.Cloud = entra.CloudGlobal
	}
	httpx.JSON(w, http.StatusOK, entraView{entraSettings: es, ClientSecretSet: set, Users: n})
}

type entraInput struct {
	Enabled       bool             `json:"enabled"`
	Cloud         string           `json:"cloud"`
	TenantID      string           `json:"tenant_id"`
	ClientID      string           `json:"client_id"`
	RedirectURL   string           `json:"redirect_url"`
	ClientSecret  *string          `json:"client_secret"` // nil or "" = keep
	DefaultRoleID int64            `json:"default_role_id"`
	GroupRoles    []entraGroupRole `json:"group_roles"`
}

// entraFromInput checks the input and returns the settings with the client
// secret to use (the given one, else the stored one for the same app).
func (a *App) entraFromInput(ctx context.Context, in entraInput) (entraSettings, string, error) {
	old, err := a.entraSettings(ctx)
	if err != nil {
		return entraSettings{}, "", err
	}
	cfg, err := entra.Config{Enabled: in.Enabled, Cloud: in.Cloud, TenantID: in.TenantID, ClientID: in.ClientID, RedirectURL: in.RedirectURL}.Normalize()
	if err != nil {
		return entraSettings{}, "", httpx.BadRequest("entra_invalid", err.Error())
	}
	es := entraSettings{Config: cfg, DefaultRoleID: in.DefaultRoleID, GroupRoles: []entraGroupRole{}}
	if es.DefaultRoleID != 0 {
		if _, err := a.st.RoleByID(ctx, es.DefaultRoleID); err != nil {
			return entraSettings{}, "", httpx.BadRequest("invalid_role", "the default role does not exist")
		}
	}
	seen := map[string]bool{}
	for _, g := range in.GroupRoles {
		id := strings.ToLower(strings.TrimSpace(g.GroupID))
		if !entra.ValidGroupID(id) {
			return entraSettings{}, "", httpx.BadRequest("entra_invalid", "a group must be given by its object ID (GUID): "+g.GroupID)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if _, err := a.st.RoleByID(ctx, g.RoleID); err != nil {
			return entraSettings{}, "", httpx.BadRequest("invalid_role", "the role of group "+id+" does not exist")
		}
		es.GroupRoles = append(es.GroupRoles, entraGroupRole{GroupID: id, RoleID: g.RoleID})
	}
	if len(es.GroupRoles) > 200 {
		return entraSettings{}, "", httpx.BadRequest("entra_invalid", "at most 200 group mappings")
	}
	es.ClientSecretRef = old.ClientSecretRef
	if in.ClientSecret != nil && strings.TrimSpace(*in.ClientSecret) != "" {
		return es, strings.TrimSpace(*in.ClientSecret), nil
	}
	if old.ClientSecretRef == "" {
		return es, "", nil
	}
	if !strings.EqualFold(old.TenantID, cfg.TenantID) || !strings.EqualFold(old.ClientID, cfg.ClientID) || old.Cloud != cfg.Cloud {
		// A stored secret is never sent to another tenant or application.
		return es, "", nil
	}
	secret, err := a.secret(old.ClientSecretRef)
	if err != nil {
		return es, "", &httpx.HTTPError{Status: http.StatusServiceUnavailable, Code: "openbao_unavailable", Msg: "client secret: " + err.Error()}
	}
	return es, secret, nil
}

func (a *App) testEntra(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in entraInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	es, secret, err := a.entraFromInput(ctx, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if secret == "" {
		httpx.Error(w, http.StatusBadRequest, "entra_secret_required", "enter the client secret")
		return
	}
	httpx.JSON(w, http.StatusOK, entra.Report(entra.Test(ctx, es.Config, secret)))
}

func (a *App) putEntra(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in entraInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	old, err := a.entraSettings(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	var es entraSettings
	if !in.Enabled && strings.TrimSpace(in.TenantID) == "" {
		es = old // switching off an incomplete form keeps the rest
		es.Enabled = false
	} else {
		var secret string
		if es, secret, err = a.entraFromInput(ctx, in); err != nil {
			httpx.Err(w, err)
			return
		}
		if es.Enabled {
			if secret == "" {
				httpx.Error(w, http.StatusBadRequest, "entra_secret_required", "enter the client secret")
				return
			}
			if es.DefaultRoleID == 0 && len(es.GroupRoles) == 0 {
				httpx.Error(w, http.StatusBadRequest, "invalid_role", "choose the default role or map at least one group")
				return
			}
			if _, err := entra.Test(ctx, es.Config, secret); err != nil {
				httpx.Error(w, http.StatusBadRequest, "entra_unavailable", err.Error())
				return
			}
		}
		if in.ClientSecret != nil && strings.TrimSpace(*in.ClientSecret) != "" {
			if es.ClientSecretRef, err = a.putSecret(ctx, entra.SecretPath, entra.SecretKey, secret); err != nil {
				httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
				return
			}
		}
	}
	if err := a.st.PutSetting(ctx, settingEntra, es); err != nil {
		httpx.Err(w, err)
		return
	}
	if old.Enabled && !es.Enabled {
		a.signOutEntraUsers(ctx)
	}
	a.audit(ctx, p, "settings.entra", es.TenantID, map[string]any{"enabled": es.Enabled, "client_id": es.ClientID,
		"groups": len(es.GroupRoles), "secret_changed": in.ClientSecret != nil && strings.TrimSpace(*in.ClientSecret) != ""})
	a.getEntra(w, r, p)
}

// signOutEntraUsers ends the sessions of Entra users once Entra is off.
func (a *App) signOutEntraUsers(ctx context.Context) {
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		slog.Warn("entra users not signed out", "err", err)
		return
	}
	for _, u := range users {
		if u.Source == store.SourceEntra {
			if err := a.sessions.DeleteUser(ctx, u.ID, ""); err != nil {
				slog.Warn("entra user not signed out", "user", u.Username, "err", err)
			}
		}
	}
}

// entraInfo tells the sign-in page whether to show the Microsoft button.
func (a *App) entraInfo(w http.ResponseWriter, r *http.Request) {
	es, err := a.entraSettings(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]bool{"enabled": err == nil && es.Enabled})
}

// ---- the sign-in flow

type entraPending struct {
	req    entra.Request
	expiry time.Time
}

// entraFlow keeps started sign-ins until their callback and limits starts per address.
type entraFlow struct {
	mu      sync.Mutex
	pending map[string]entraPending
	starts  *auth.Limiter
}

func newEntraFlow() *entraFlow {
	l := auth.NewLimiter()
	l.MaxFailures, l.Window, l.LockFor = 60, time.Minute, time.Minute
	return &entraFlow{pending: map[string]entraPending{}, starts: l}
}

var entraFlows sync.Map // *App → *entraFlow

func (a *App) entraFlow() *entraFlow {
	f, _ := entraFlows.LoadOrStore(a, newEntraFlow())
	return f.(*entraFlow)
}

// remember keeps a started sign-in; expired ones are dropped and, when the
// table is full, the oldest gives way.
func (f *entraFlow) remember(req entra.Request, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, p := range f.pending {
		if now.After(p.expiry) {
			delete(f.pending, k)
		}
	}
	for len(f.pending) >= entraPendingMax {
		var oldest string
		var at time.Time
		for k, p := range f.pending {
			if oldest == "" || p.expiry.Before(at) {
				oldest, at = k, p.expiry
			}
		}
		delete(f.pending, oldest)
	}
	f.pending[req.State] = entraPending{req: req, expiry: now.Add(entraPendingTTL)}
}

func (f *entraFlow) take(state string) (entra.Request, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pending[state]
	delete(f.pending, state)
	if !ok || time.Now().After(p.expiry) {
		return entra.Request{}, false
	}
	return p.req, true
}

// entraStart sends the browser to the Microsoft sign-in page. The state also
// goes into a cookie, so only the browser that started can finish.
func (a *App) entraStart(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, a.opt.TrustedProxies)
	f := a.entraFlow()
	if locked, _ := f.starts.Locked(ip); locked {
		a.entraFailed(w, r, "too_many_attempts")
		return
	}
	f.starts.Fail(ip)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	es, err := a.entraSettings(ctx)
	if err != nil || !es.Enabled {
		a.entraFailed(w, r, "entra_off")
		return
	}
	m, err := entra.Discover(ctx, es.Config)
	if err != nil {
		slog.Error("entra: sign-in cannot start", "err", err)
		a.entraFailed(w, r, "entra_unavailable")
		return
	}
	req := entra.NewRequest()
	f.remember(req, time.Now())
	a.setEntraCookie(w, req.State, int(entraPendingTTL/time.Second))
	http.Redirect(w, r, entra.AuthURL(es.Config, m, req), http.StatusFound)
}

var (
	errEntraState  = errors.New("the sign-in request has expired or was started in another browser")
	errEntraNoRole = &signInError{status: http.StatusForbidden, code: "entra_no_role",
		msg: "your Entra ID groups give no role in Flow; ask an administrator"}
)

func (a *App) entraCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		slog.Warn("entra: sign-in refused by Microsoft", "error", e, "description", q.Get("error_description"))
		a.entraFailed(w, r, "entra_denied")
		return
	}
	state := q.Get("state")
	c, err := r.Cookie(entraCookie)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		a.entraFailed(w, r, "entra_state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	u, err := a.entraComplete(ctx, state, q.Get("code"))
	var se *signInError
	switch {
	case errors.Is(err, errEntraState):
		a.entraFailed(w, r, "entra_state")
		return
	case errors.As(err, &se):
		_ = a.st.Audit(ctx, u.Username, "auth.login_failed", "", remote, map[string]string{"reason": se.code, "source": store.SourceEntra})
		a.entraFailed(w, r, se.code)
		return
	case err != nil:
		slog.Error("entra: sign-in failed", "err", err)
		a.entraFailed(w, r, "entra_unavailable")
		return
	}
	a.setEntraCookie(w, "", -1)
	if _, err := a.sessions.Create(ctx, w, u.ID, remote); err != nil {
		slog.Error("entra: session not created", "err", err)
		a.entraFailed(w, r, "entra_unavailable")
		return
	}
	_ = a.st.TouchLogin(ctx, u.ID)
	_ = a.st.Audit(ctx, u.Username, "auth.login", "", remote, map[string]string{"source": store.SourceEntra})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// entraComplete redeems the code and returns the Flow user (created on the
// first sign-in). On a refusal the returned user carries the user name.
func (a *App) entraComplete(ctx context.Context, state, code string) (store.User, error) {
	req, ok := a.entraFlow().take(state)
	if !ok {
		return store.User{}, errEntraState
	}
	es, err := a.entraSettings(ctx)
	if err != nil {
		return store.User{}, err
	}
	if !es.Enabled {
		return store.User{}, &signInError{status: http.StatusForbidden, code: "entra_off", msg: "Entra ID sign-in is off"}
	}
	secret, err := a.secret(es.ClientSecretRef)
	if err != nil {
		return store.User{}, fmt.Errorf("client secret: %w", err)
	}
	cfg := es.Config
	cfg.ReadGroups = len(es.GroupRoles) > 0
	acc, err := entra.SignIn(ctx, cfg, secret, code, req, time.Now())
	if errors.Is(err, entra.ErrInvalidUser) {
		return store.User{}, &signInError{status: http.StatusForbidden, code: "entra_account", msg: err.Error()}
	}
	if err != nil {
		return store.User{}, err
	}
	who := store.User{Username: acc.Username}
	roleID := es.DefaultRoleID
	for _, g := range es.GroupRoles {
		if slices.Contains(acc.Groups, g.GroupID) {
			roleID = g.RoleID
			break
		}
	}
	if roleID == 0 {
		return who, errEntraNoRole
	}
	u, created, err := a.st.UpsertEntraUser(ctx, acc.Username, acc.Name, acc.Email, roleID)
	if errors.Is(err, store.ErrConflict) {
		return who, &signInError{status: http.StatusConflict, code: "entra_conflict", msg: "a local or LDAP user with this name exists"}
	}
	if err != nil {
		return who, err
	}
	if created {
		_ = a.st.Audit(ctx, u.Username, "user.create", u.Username, "", map[string]any{"source": store.SourceEntra, "role": u.Role, "object_id": acc.ObjectID})
	}
	if u.Disabled {
		return u, &signInError{status: http.StatusForbidden, code: "user_disabled", msg: "the account is disabled"}
	}
	return u, nil
}

func (a *App) entraFailed(w http.ResponseWriter, r *http.Request, code string) {
	a.setEntraCookie(w, "", -1)
	http.Redirect(w, r, "/login?signin_error="+code, http.StatusSeeOther)
}

func (a *App) setEntraCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: entraCookie, Value: value, Path: "/api/auth/entra/", HttpOnly: true, Secure: a.opt.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
