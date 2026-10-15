package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/spa"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// SPA, the Single Point of Authorization (docs/identity-federation.md and
// SPA's docs/protocol.md): people sign in there (OpenID Connect with PKCE),
// Flow reads the people who may use it and their roles every five minutes
// and publishes its roles as the catalogue SPA administrators assign.
//
// The connection key comes from SPA_CONNECTION_KEY, the file named by
// SPA_CONNECTION_KEY_FILE or OpenBao (spa#connection_key, written by the
// setup wizard). The state of the connection (what SPA said last, the last
// synchronization) is the settings key "spa".

const (
	settingSPA = "spa"
	// spaCookie keeps the PKCE verifier and the nonce of a sign-in, bound to
	// the signed state.
	spaCookie     = "flow_spa"
	spaCookiePath = "/api/auth/spa/"
	spaFlowTTL    = 10 * time.Minute
	// spaDefaultRole is suggested to SPA administrators for new rules.
	spaDefaultRole = store.IdentViewer
)

var errSPANotConnected = errors.New("Flow is not connected to SPA: set " + spa.Env + " (or " + spa.EnvFile + ") to the connection key SPA shows in Applications → Connect an application")

// spaStatus is what SPA said last and how the last synchronization went.
type spaStatus struct {
	Issuer      string       `json:"issuer"`
	ClientID    string       `json:"client_id"`
	Application spaApp       `json:"application"`
	AccountURL  string       `json:"account_url"`
	SignOutURL  string       `json:"sign_out_url"`
	Methods     []spa.Method `json:"methods"`
	LastSync    *time.Time   `json:"last_sync,omitempty"`
	OK          bool         `json:"ok"`
	Error       string       `json:"error,omitempty"`
	Users       int          `json:"users"`
	Created     int          `json:"created"`
	Updated     int          `json:"updated"`
	Bound       int          `json:"bound"`
	Disabled    int          `json:"disabled"`
	Conflicts   []string     `json:"conflicts"`
	NoRole      []string     `json:"no_role"`
	ConfigETag  string       `json:"config_etag,omitempty"`
	UsersETag   string       `json:"users_etag,omitempty"`
	Catalogue   spaPublished `json:"catalogue"`
}

type spaApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type spaPublished struct {
	Hash  string     `json:"hash,omitempty"`
	At    *time.Time `json:"at,omitempty"`
	Roles int        `json:"roles"`
	Error string     `json:"error,omitempty"`
}

// spaState is the in-process part: one synchronization at a time and the
// states already used.
type spaState struct {
	mu   sync.Mutex // status read-modify-write, synchronization, publishing
	used sync.Map   // state id → expiry (single use)
}

func (a *App) spaStatus(ctx context.Context) (spaStatus, error) {
	var s spaStatus
	_, err := a.st.Setting(ctx, settingSPA, &s)
	if s.Methods == nil {
		s.Methods = []spa.Method{}
	}
	if s.Conflicts == nil {
		s.Conflicts = []string{}
	}
	if s.NoRole == nil {
		s.NoRole = []string{}
	}
	return s, err
}

// spaKey returns the connection key and where it came from (env, file,
// openbao); errSPANotConnected when there is none.
func (a *App) spaKey() (spa.Key, string, error) {
	parse := func(raw, source string) (spa.Key, string, error) {
		k, err := spa.ParseKey(raw)
		if err != nil {
			return spa.Key{}, source, fmt.Errorf("%s: %w", source, err)
		}
		return k, source, nil
	}
	if strings.TrimSpace(a.opt.SPAKey) != "" {
		return parse(a.opt.SPAKey, "env")
	}
	if a.opt.SPAKeyFile != "" {
		b, err := os.ReadFile(a.opt.SPAKeyFile)
		if err != nil {
			return spa.Key{}, "file", fmt.Errorf("%s: %w", spa.EnvFile, err)
		}
		return parse(string(b), "file")
	}
	raw, err := a.deps.Vault.Resolve(a.deps.Vault.Ref(spa.SecretPath, spa.SecretKey))
	switch {
	case errors.Is(err, secrets.ErrNotFound) || (err == nil && strings.TrimSpace(raw) == ""):
		return spa.Key{}, "", errSPANotConnected
	case err != nil:
		return spa.Key{}, "openbao", fmt.Errorf("the connection key in OpenBao: %w", err)
	}
	return parse(raw, "openbao")
}

// baseURL is the address of Flow for the redirect addresses: SPA_PUBLIC_URL,
// else the address of the request (X-Forwarded-Proto / -Host from
// FLOW_TRUSTED_PROXIES).
func (a *App) baseURL(r *http.Request) string {
	if u := strings.TrimRight(strings.TrimSpace(a.opt.SPAPublicURL), "/"); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || a.opt.SecureCookies {
		scheme = "https"
	} else if p := r.Header.Get("X-Forwarded-Proto"); (p == "https" || p == "http") && a.fromTrustedProxy(r) {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" && a.fromTrustedProxy(r) {
		host = h
	}
	return scheme + "://" + host
}

// fromTrustedProxy: the request comes from one of FLOW_TRUSTED_PROXIES.
func (a *App) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(a.opt.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(addr.Unmap()) })
}

func (a *App) spaRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/auth/spa", a.spaInfo)
	h("GET "+spa.StartPath, a.spaStart)
	h("GET "+spa.CallbackPath, a.spaCallback)
	h("GET /api/settings/spa", a.guard(perms(access.UsersView), a.getSPA))
	h("POST /api/settings/spa/sync", a.guard(perms(access.UsersEdit), a.syncSPANow))
}

// spaInfo tells the sign-in page whether Flow is connected to SPA.
func (a *App) spaInfo(w http.ResponseWriter, r *http.Request) {
	k, _, err := a.spaKey()
	if err != nil {
		out := map[string]any{"connected": false}
		if !errors.Is(err, errSPANotConnected) {
			out["error"] = "invalid_key"
		}
		httpx.JSON(w, http.StatusOK, out)
		return
	}
	st, _ := a.spaStatus(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]any{"connected": true, "issuer": k.Issuer, "application": st.Application.Name, "methods": st.Methods})
}

// ---- sign-in

// spaFlow is what the cookie keeps between start and callback.
type spaFlow struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
}

// statePayload is signed into the state: its id (single use), the page to
// return to and the expiry.
type statePayload struct {
	ID     string `json:"i"`
	Return string `json:"r"`
	Exp    int64  `json:"e"`
}

func (a *App) signState(ctx context.Context, p statePayload) (string, error) {
	b, _ := json.Marshal(p)
	body := base64.RawURLEncoding.EncodeToString(b)
	m, err := auth.NewKeys(a.deps.Vault).StateMAC(ctx, body)
	if err != nil {
		return "", err
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(m), nil
}

func (a *App) openState(ctx context.Context, state string, now time.Time) (statePayload, bool) {
	body, sig, ok := strings.Cut(state, ".")
	if !ok {
		return statePayload{}, false
	}
	got, err1 := base64.RawURLEncoding.DecodeString(sig)
	want, err2 := auth.NewKeys(a.deps.Vault).StateMAC(ctx, body)
	if err1 != nil || err2 != nil || !hmac.Equal(got, want) {
		return statePayload{}, false
	}
	var p statePayload
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(b, &p) != nil || p.ID == "" || now.Unix() > p.Exp {
		return statePayload{}, false
	}
	// Single use.
	if _, seen := a.spa.used.LoadOrStore(p.ID, p.Exp); seen {
		return statePayload{}, false
	}
	a.spa.used.Range(func(k, v any) bool {
		if v.(int64) < now.Unix() {
			a.spa.used.Delete(k)
		}
		return true
	})
	return p, true
}

// safeReturn keeps a return path inside Flow.
func safeReturn(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.HasPrefix(p, "/api/") {
		return "/"
	}
	if u, err := url.Parse(p); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return p
}

func (a *App) setSPACookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	secure := a.opt.SecureCookies || r.TLS != nil || strings.HasPrefix(a.baseURL(r), "https://")
	http.SetCookie(w, &http.Cookie{Name: spaCookie, Value: value, Path: spaCookiePath, HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// spaFailed returns to the sign-in page with the error.
func (a *App) spaFailed(w http.ResponseWriter, r *http.Request, code, description string) {
	a.setSPACookie(w, r, "", -1)
	q := url.Values{"sso_error": {code}}
	if description != "" {
		if len(description) > 300 {
			description = description[:300]
		}
		q.Set("sso_error_description", description)
	}
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusSeeOther)
}

var idpHints = map[string]bool{"password": true, "passkey": true, "ldap": true, "entra": true, "google": true, "apple": true, "oidc": true}

// spaStart: GET /api/auth/spa/start?return=<path>[&login_hint=…][&idp_hint=…][&prompt=login].
func (a *App) spaStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	k, _, err := a.spaKey()
	if err != nil {
		if !errors.Is(err, errSPANotConnected) {
			slog.Error("spa: connection key", "err", err)
		}
		a.spaFailed(w, r, "not_connected", "")
		return
	}
	q := r.URL.Query()
	req := oidcx.NewRequest()
	state, err := a.signState(ctx, statePayload{ID: oidcx.Random(), Return: safeReturn(q.Get("return")), Exp: time.Now().Add(spaFlowTTL).Unix()})
	if err != nil {
		slog.Error("spa: state not signed", "err", err)
		a.spaFailed(w, r, "spa_unavailable", "")
		return
	}
	req.State = state
	o := spa.AuthOptions{LoginHint: strings.TrimSpace(q.Get("login_hint"))}
	if h := q.Get("idp_hint"); idpHints[h] {
		o.IDPHint = h
	}
	if q.Get("prompt") == "login" {
		o.Prompt = "login"
	}
	target, err := k.AuthURL(ctx, a.baseURL(r)+spa.CallbackPath, o, req)
	if err != nil {
		slog.Error("spa: sign-in cannot start", "err", err)
		a.spaFailed(w, r, "spa_unavailable", "")
		return
	}
	b, _ := json.Marshal(spaFlow{State: state, Verifier: req.Verifier, Nonce: req.Nonce})
	a.setSPACookie(w, r, base64.RawURLEncoding.EncodeToString(b), int(spaFlowTTL/time.Second))
	http.Redirect(w, r, target, http.StatusFound)
}

var errorCodeRe = regexp.MustCompile(`^[a-z_]{1,40}$`)

func (a *App) spaCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	if e := q.Get("error"); e != "" {
		if !errorCodeRe.MatchString(e) {
			e = "spa_error"
		}
		_ = a.st.Audit(r.Context(), "", "auth.login_failed", "", remote, map[string]string{"reason": e, "description": q.Get("error_description")})
		a.spaFailed(w, r, e, q.Get("error_description"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	state := q.Get("state")
	var flow spaFlow
	c, err := r.Cookie(spaCookie)
	if err == nil {
		if b, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			_ = json.Unmarshal(b, &flow)
		}
	}
	if state == "" || flow.State == "" || subtle.ConstantTimeCompare([]byte(flow.State), []byte(state)) != 1 {
		a.spaFailed(w, r, "state", "")
		return
	}
	payload, ok := a.openState(ctx, state, time.Now())
	if !ok {
		a.spaFailed(w, r, "state", "")
		return
	}
	k, _, err := a.spaKey()
	if err != nil {
		a.spaFailed(w, r, "not_connected", "")
		return
	}
	id, err := k.Finish(ctx, a.baseURL(r)+spa.CallbackPath, q.Get("code"), oidcx.Request{State: state, Nonce: flow.Nonce, Verifier: flow.Verifier})
	if err != nil {
		code := "spa_unavailable"
		if errors.Is(err, oidcx.ErrInvalidToken) {
			code = "invalid_token"
		}
		slog.Warn("spa: sign-in failed", "err", err)
		_ = a.st.Audit(ctx, "", "auth.login_failed", "", remote, map[string]string{"reason": code, "error": err.Error()})
		a.spaFailed(w, r, code, "")
		return
	}
	roles, err := a.st.ListRoles(ctx)
	if err != nil {
		a.spaFailed(w, r, "spa_unavailable", "")
		return
	}
	role := pickRole(roles, id.Roles)
	if role == 0 {
		_ = a.st.Audit(ctx, id.Username, "auth.login_failed", "", remote, map[string]any{"reason": "no_role", "roles": id.Roles})
		a.spaFailed(w, r, "no_role", "")
		return
	}
	u, _, err := a.st.UpsertSPAUser(ctx, store.SPAUser{ExternalID: id.Subject, Username: id.Username, Name: id.Name, Email: id.Email, RoleID: role})
	if err != nil {
		code := "spa_unavailable"
		if errors.Is(err, store.ErrUsernameTaken) {
			code = "account_conflict"
		}
		slog.Warn("spa: account refused", "user", id.Username, "err", err)
		_ = a.st.Audit(ctx, id.Username, "auth.login_failed", "", remote, map[string]string{"reason": code})
		a.spaFailed(w, r, code, "")
		return
	}
	if _, err := a.sessions.Create(ctx, w, u.ID, remote); err != nil {
		slog.Error("session not created", "err", err)
		a.spaFailed(w, r, "spa_unavailable", "")
		return
	}
	a.setSPACookie(w, r, "", -1)
	a.refreshSPAConfig(ctx, k)
	_ = a.st.TouchLogin(ctx, u.ID)
	_ = a.st.Audit(ctx, u.Username, "auth.login", "", remote, map[string]any{"source": store.SourceSPA, "amr": id.Methods, "role": u.RoleIdent})
	http.Redirect(w, r, payload.Return, http.StatusSeeOther)
}

// refreshSPAConfig reads SPA's configuration (account and sign-out
// addresses) when it was never read for this key, so the first person signed
// in before any synchronization gets "Account and security".
func (a *App) refreshSPAConfig(ctx context.Context, k spa.Key) {
	if st, err := a.spaStatus(ctx); err != nil || (st.Issuer == k.Issuer && st.ClientID == k.ClientID && st.AccountURL != "") {
		return
	}
	cfg, _, _, err := k.Config(ctx, "")
	if err != nil {
		slog.Warn("spa: configuration not read", "err", err)
		return
	}
	a.spa.mu.Lock()
	defer a.spa.mu.Unlock()
	st, err := a.spaStatus(ctx)
	if err != nil {
		return
	}
	if st.Issuer != k.Issuer || st.ClientID != k.ClientID {
		st = spaStatus{Issuer: k.Issuer, ClientID: k.ClientID, Conflicts: []string{}, NoRole: []string{}}
	}
	st.Application = spaApp{ID: cfg.Application.ID, Name: cfg.Application.Name, Type: cfg.Application.Type}
	st.AccountURL, st.SignOutURL, st.Methods = cfg.AccountURL, cfg.SignOutURL, cfg.Methods
	if st.Methods == nil {
		st.Methods = []spa.Method{}
	}
	_ = a.st.PutSetting(ctx, settingSPA, st)
}

// pickRole maps SPA role IDs to the Flow role: of the roles named, the one
// with the most permissions (Flow gives one role per person); 0 = none known.
func pickRole(roles []store.Role, idents []string) int64 {
	var best *store.Role
	for i := range roles {
		r := &roles[i]
		for _, id := range idents {
			if r.Ident == id && (best == nil || len(r.Permissions) > len(best.Permissions)) {
				best = r
			}
		}
	}
	if best == nil {
		return 0
	}
	return best.ID
}

// spaSignOut is SPA's sign-out address (back to Flow's address), "" when
// not connected.
func (a *App) spaSignOut(r *http.Request) string {
	k, _, err := a.spaKey()
	if err != nil {
		return ""
	}
	st, _ := a.spaStatus(r.Context())
	out := st.SignOutURL
	if out == "" || st.Issuer != k.Issuer {
		out = k.Issuer + "/oauth2/logout"
	}
	return spa.SignOutURL(out, k.ClientID, a.baseURL(r)+"/")
}

// ---- settings page

type spaView struct {
	Connected   bool   `json:"connected"`
	KeySource   string `json:"key_source,omitempty"`
	KeyError    string `json:"key_error,omitempty"`
	RedirectURI string `json:"redirect_uri"`
	SignOutURI  string `json:"post_logout_redirect_uri"`
	spaStatus
	Counts   store.SPAUserCounts `json:"counts"`
	Roles    []spa.Role          `json:"roles"`
	Interval string              `json:"interval"`
}

func (a *App) getSPA(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	st, err := a.spaStatus(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	v := spaView{spaStatus: st, RedirectURI: a.baseURL(r) + spa.CallbackPath, SignOutURI: a.baseURL(r) + "/", Interval: spa.SyncEvery.String()}
	v.ConfigETag, v.UsersETag, v.Catalogue.Hash = "", "", ""
	k, source, err := a.spaKey()
	v.KeySource = source
	switch {
	case err == nil:
		v.Connected = true
		v.Issuer, v.ClientID = k.Issuer, k.ClientID
	case !errors.Is(err, errSPANotConnected):
		v.KeyError = err.Error()
	}
	if v.Counts, err = a.st.CountSPAUsers(ctx); err != nil {
		httpx.Err(w, err)
		return
	}
	cat, err := a.catalogue(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	v.Roles = cat.Roles
	httpx.JSON(w, http.StatusOK, v)
}

func (a *App) syncSPANow(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := a.syncSPA(ctx, p.User.Username, false); err != nil {
		var he *httpx.HTTPError
		switch {
		case errors.Is(err, errSPANotConnected):
			httpx.Error(w, http.StatusConflict, "spa_not_connected", err.Error())
			return
		case errors.As(err, &he):
			httpx.Err(w, err)
			return
		}
		// The error is in the status the page shows.
	}
	a.getSPA(w, r, p)
}

// ---- role catalogue

// catalogue is Flow's roles as SPA gets them.
func (a *App) catalogue(ctx context.Context) (spa.Catalogue, error) {
	roles, err := a.st.ListRoles(ctx)
	if err != nil {
		return spa.Catalogue{}, err
	}
	c := spa.Catalogue{Roles: make([]spa.Role, 0, len(roles)), Default: spaDefaultRole}
	for _, r := range roles {
		c.Roles = append(c.Roles, spa.Role{ID: r.Ident, Name: r.Name, Description: r.Description})
	}
	return c, nil
}

// publishCatalogue sends the role catalogue to SPA when it changed since the
// last successful publication (or always with force). The result is kept in
// the status; it is called with a.spa.mu held.
func (a *App) publishCatalogue(ctx context.Context, k spa.Key, st *spaStatus, force bool) {
	c, err := a.catalogue(ctx)
	if err != nil {
		st.Catalogue.Error = err.Error()
		return
	}
	b, _ := json.Marshal(struct {
		Issuer, Client string
		C              spa.Catalogue
	}{k.Issuer, k.ClientID, c})
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	if !force && st.Catalogue.Hash == hash && st.Catalogue.Error == "" {
		return
	}
	if err := k.PublishRoles(ctx, c); err != nil {
		st.Catalogue.Error = err.Error()
		slog.Warn("spa: role catalogue not published", "err", err)
		return
	}
	now := time.Now().UTC()
	st.Catalogue = spaPublished{Hash: hash, At: &now, Roles: len(c.Roles)}
}

// rolesChanged publishes the catalogue after a role was created, changed or
// deleted (errors are kept in the status and retried by the schedule).
func (a *App) rolesChanged(ctx context.Context) {
	k, _, err := a.spaKey()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	a.spa.mu.Lock()
	defer a.spa.mu.Unlock()
	st, err := a.spaStatus(ctx)
	if err != nil {
		return
	}
	a.publishCatalogue(ctx, k, &st, false)
	if err := a.st.PutSetting(ctx, settingSPA, st); err != nil {
		slog.Warn("spa: status not saved", "err", err)
	}
}

// ---- synchronization

// syncSPA reads the configuration and the people of SPA and applies them
// (docs/protocol.md §4). One replica runs it at a time (an advisory lock);
// schedule tells a run of the schedule, which skips quietly when another
// replica holds the lock.
func (a *App) syncSPA(ctx context.Context, actor string, schedule bool) error {
	k, _, err := a.spaKey()
	if err != nil {
		return err
	}
	release, ok, err := a.st.TryLock(ctx, store.LockKey("spa-sync"))
	if err != nil {
		return err
	}
	if !ok {
		if schedule {
			return nil
		}
		return &httpx.HTTPError{Status: http.StatusConflict, Code: "sync_running", Msg: "a synchronization with SPA is running, try again in a minute"}
	}
	defer release()
	a.spa.mu.Lock()
	defer a.spa.mu.Unlock()
	st, err := a.spaStatus(ctx)
	if err != nil {
		return err
	}
	if st.Issuer != k.Issuer || st.ClientID != k.ClientID {
		// Another SPA or a new key: read everything again.
		st = spaStatus{Issuer: k.Issuer, ClientID: k.ClientID, Methods: []spa.Method{}, Conflicts: []string{}, NoRole: []string{}}
	}
	err = a.applySPA(ctx, k, &st)
	now := time.Now().UTC()
	st.LastSync, st.OK, st.Error = &now, err == nil, ""
	if err != nil {
		st.Error = err.Error()
		slog.Warn("spa: synchronization failed", "err", err)
	}
	if perr := a.st.PutSetting(ctx, settingSPA, st); perr != nil {
		return perr
	}
	if err != nil || st.Created+st.Bound+st.Disabled > 0 || !schedule {
		_ = a.st.Audit(ctx, actor, "spa.sync", k.Issuer, "", map[string]any{"ok": err == nil, "users": st.Users, "created": st.Created,
			"bound": st.Bound, "updated": st.Updated, "disabled": st.Disabled, "conflicts": st.Conflicts, "no_role": st.NoRole, "error": st.Error})
	}
	return err
}

func (a *App) applySPA(ctx context.Context, k spa.Key, st *spaStatus) error {
	cfg, tag, same, err := k.Config(ctx, st.ConfigETag)
	if err != nil {
		return err
	}
	if !same {
		st.ConfigETag = tag
		st.Application = spaApp{ID: cfg.Application.ID, Name: cfg.Application.Name, Type: cfg.Application.Type}
		st.AccountURL, st.SignOutURL = cfg.AccountURL, cfg.SignOutURL
		st.Methods = cfg.Methods
		if st.Methods == nil {
			st.Methods = []spa.Method{}
		}
	}
	a.publishCatalogue(ctx, k, st, false)
	users, tag, same, err := k.Users(ctx, st.UsersETag)
	if err != nil {
		return err
	}
	st.Created, st.Updated, st.Bound, st.Disabled = 0, 0, 0, 0
	if same {
		return nil
	}
	roles, err := a.st.ListRoles(ctx)
	if err != nil {
		return err
	}
	st.Users, st.Conflicts, st.NoRole = 0, []string{}, []string{}
	keep := []string{}
	var revoke []int64
	for _, su := range users {
		if su.ID == "" || su.Username == "" {
			continue
		}
		role := pickRole(roles, su.Roles)
		if su.Disabled || role == 0 {
			if role == 0 && !su.Disabled {
				st.NoRole = append(st.NoRole, su.Username)
			}
			id, err := a.st.DisableSPAUser(ctx, su.ID)
			if err != nil {
				return err
			}
			if id != 0 {
				revoke = append(revoke, id)
				st.Disabled++
			}
			continue
		}
		_, how, err := a.st.UpsertSPAUser(ctx, store.SPAUser{ExternalID: su.ID, Username: su.Username, Name: su.Name, Email: su.Email, RoleID: role})
		if errors.Is(err, store.ErrUsernameTaken) {
			st.Conflicts = append(st.Conflicts, su.Username)
			continue
		}
		if err != nil {
			return err
		}
		keep = append(keep, su.ID)
		st.Users++
		switch how {
		case store.SPACreated:
			st.Created++
		case store.SPABound:
			st.Bound++
		default:
			st.Updated++
		}
	}
	gone, err := a.st.DisableAbsent(ctx, keep)
	if err != nil {
		return err
	}
	st.Disabled += len(gone)
	for _, id := range append(revoke, gone...) {
		if err := a.sessions.DeleteUser(ctx, id, ""); err != nil {
			slog.Warn("spa: sessions of a disabled user not ended", "user_id", id, "err", err)
		}
	}
	st.UsersETag = tag
	return nil
}

// runSPASchedule publishes the catalogue and synchronizes at start and every
// five minutes.
func (a *App) runSPASchedule(ctx context.Context) {
	a.removeIdentitySecrets(ctx)
	t := time.NewTicker(spa.SyncEvery)
	defer t.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if err := a.syncSPA(sctx, "schedule", true); err != nil && !errors.Is(err, errSPANotConnected) && ctx.Err() == nil {
			slog.Warn("spa: scheduled synchronization failed", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// removeIdentitySecrets deletes, once, the secrets of the sign-in Flow had
// before SPA: password hashes and their history, the LDAP service account,
// the Entra ID, provider and Umbrella Identity client secrets.
func (a *App) removeIdentitySecrets(ctx context.Context) {
	const setting = "identity_secrets_removed"
	var done bool
	if found, err := a.st.Setting(ctx, setting, &done); err != nil || (found && done) {
		return
	}
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		return
	}
	paths := []string{"ldap", "entra", "identity/umbrella", "identity/umbrella/token"}
	for _, kind := range []string{"google", "apple", "oidc"} {
		paths = append(paths, "identity/providers/"+kind+"/client-secret", "identity/providers/"+kind+"/private-key")
	}
	for _, u := range users {
		id := fmt.Sprint(u.ID)
		paths = append(paths, "users/"+id, "users/"+id+"/history")
	}
	for _, p := range paths {
		if err := a.deps.Vault.Delete(ctx, p); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			slog.Warn("old identity secret not deleted", "path", p, "err", err)
			return // OpenBao is away: try again at the next start
		}
	}
	_ = a.st.PutSetting(ctx, setting, true)
}
