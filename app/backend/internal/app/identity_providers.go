package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Sign-in with Google (Workspace), Apple and any OpenID Connect provider, as
// in Umbrella Monitoring. Settings key "providers"; secrets in OpenBao at
// identity/providers/<kind>. A person is bound to the provider's subject; an
// account with the same verified e-mail of an allowed domain is signed in
// (and the link written to the audit log); otherwise an account is created
// with the provider's role unless only existing accounts may sign in.

const (
	settingProviders = "providers"
	ssoCookie        = "flow_sso"
	ssoPendingTTL    = 10 * time.Minute
)

var providerKinds = []string{store.SourceGoogle, store.SourceApple, store.SourceOIDC}

type provider struct {
	Enabled         bool     `json:"enabled"`
	Title           string   `json:"title"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecretRef string   `json:"client_secret_ref,omitempty"`
	TeamID          string   `json:"team_id,omitempty"`
	KeyID           string   `json:"key_id,omitempty"`
	PrivateKeyRef   string   `json:"private_key_ref,omitempty"`
	AllowedDomains  []string `json:"allowed_domains"`
	ExistingOnly    bool     `json:"existing_only"`
	Scopes          string   `json:"scopes,omitempty"`
	GroupsClaim     string   `json:"groups_claim,omitempty"`
	AdminGroup      string   `json:"admin_group,omitempty"`
	// RoleID is the role of accounts the provider creates; AdminRoleID the
	// role of members of AdminGroup.
	RoleID      int64 `json:"role_id"`
	AdminRoleID int64 `json:"admin_role_id"`
}

func (p provider) emailAllowed(email string) bool {
	if len(p.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	return at >= 0 && slices.Contains(p.AllowedDomains, strings.ToLower(email[at+1:]))
}

func providerTitle(kind string, p provider) string {
	switch kind {
	case store.SourceGoogle:
		return "Google"
	case store.SourceApple:
		return "Apple"
	}
	if p.Title != "" {
		return p.Title
	}
	return "OpenID Connect"
}

func (a *App) providers(ctx context.Context) (map[string]provider, error) {
	out := map[string]provider{}
	_, err := a.st.Setting(ctx, settingProviders, &out)
	return out, err
}

func (a *App) publicURL(ctx context.Context) string {
	g, err := a.loadGeneral(ctx)
	if err != nil {
		return ""
	}
	return strings.TrimRight(g.PublicURL, "/")
}

func providerRedirect(public, kind string) string {
	return public + "/api/auth/sso/" + kind + "/callback"
}

func (a *App) providerRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/providers", a.guard(perms(access.UsersView), a.getProviders))
	h("PUT /api/settings/providers/{kind}", a.guard(perms(access.UsersEdit), a.putProvider))
	h("GET /api/auth/sso/{kind}/start", a.providerStart)
	h("GET /api/auth/sso/{kind}/callback", a.providerCallback)
	h("POST /api/auth/sso/{kind}/callback", a.providerCallback)
}

type providerView struct {
	Kind            string   `json:"kind"`
	Config          provider `json:"config"`
	ClientSecretSet bool     `json:"client_secret_set"`
	PrivateKeySet   bool     `json:"private_key_set"`
	RedirectURI     string   `json:"redirect_uri"`
	Users           int      `json:"users"`
}

func (a *App) getProviders(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	all, err := a.providers(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	public := a.publicURL(ctx)
	out := []providerView{}
	for _, kind := range providerKinds {
		c := all[kind]
		v := providerView{Kind: kind, Config: c, ClientSecretSet: c.ClientSecretRef != "", PrivateKeySet: c.PrivateKeyRef != ""}
		v.Config.ClientSecretRef, v.Config.PrivateKeyRef = "", ""
		if v.Config.AllowedDomains == nil {
			v.Config.AllowedDomains = []string{}
		}
		if public != "" {
			v.RedirectURI = providerRedirect(public, kind)
		}
		for _, u := range users {
			if u.Source == kind {
				v.Users++
			}
		}
		out = append(out, v)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"public_url": public, "providers": out})
}

func normalizeProvider(kind string, p provider) (provider, error) {
	p.Title, p.ClientID = strings.TrimSpace(p.Title), strings.TrimSpace(p.ClientID)
	p.TeamID, p.KeyID = strings.TrimSpace(p.TeamID), strings.TrimSpace(p.KeyID)
	var domains []string
	for _, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d == "" {
			continue
		}
		if !strings.Contains(d, ".") || strings.ContainsAny(d, " /:@") {
			return p, httpx.BadRequest("provider_domain", d+" is not a domain name")
		}
		if !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	p.AllowedDomains = domains
	switch kind {
	case store.SourceGoogle:
		p.Issuer, p.Title = oidcx.GoogleIssuer, ""
	case store.SourceApple:
		p.Issuer, p.Title = oidcx.AppleIssuer, ""
		if p.Enabled && (p.TeamID == "" || p.KeyID == "") {
			return p, httpx.BadRequest("provider_apple", "enter the Team ID and the Key ID")
		}
	default:
		u, err := url.Parse(strings.TrimRight(strings.TrimSpace(p.Issuer), "/"))
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return p, httpx.BadRequest("provider_issuer", "the issuer must be an https:// address")
		}
		p.Issuer = u.String()
	}
	if p.Enabled && p.ClientID == "" {
		return p, httpx.BadRequest("provider_client", "enter the client ID")
	}
	if p.Enabled && kind != store.SourceOIDC && len(p.AllowedDomains) == 0 && !p.ExistingOnly {
		return p, httpx.BadRequest("provider_domains", "enter the allowed e-mail domains or allow only existing accounts")
	}
	return p, nil
}

func (a *App) putProvider(w http.ResponseWriter, r *http.Request, p *Principal) {
	kind := r.PathValue("kind")
	if !slices.Contains(providerKinds, kind) {
		httpx.Error(w, http.StatusNotFound, "not_found", "unknown provider")
		return
	}
	var in struct {
		Config       provider `json:"config"`
		ClientSecret string   `json:"client_secret"`
		PrivateKey   string   `json:"private_key"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	cfg, err := normalizeProvider(kind, in.Config)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	all, err := a.providers(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	old := all[kind]
	cfg.ClientSecretRef, cfg.PrivateKeyRef = old.ClientSecretRef, old.PrivateKeyRef
	if cfg.Enabled {
		if a.publicURL(ctx) == "" {
			httpx.Error(w, http.StatusBadRequest, "public_url_required", "set the public address of Flow first (general settings)")
			return
		}
		for _, id := range []int64{cfg.RoleID, cfg.AdminRoleID} {
			if id != 0 {
				if _, err := a.st.RoleByID(ctx, id); err != nil {
					httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such role")
					return
				}
			}
		}
		if cfg.RoleID == 0 && !cfg.ExistingOnly {
			httpx.Error(w, http.StatusBadRequest, "invalid_role", "choose the role of new accounts or allow only existing accounts")
			return
		}
		if _, err := oidcx.Discover(ctx, cfg.Issuer); err != nil {
			httpx.Error(w, http.StatusBadRequest, "provider_unavailable", err.Error())
			return
		}
		if kind == store.SourceApple {
			if in.PrivateKey == "" && cfg.PrivateKeyRef == "" {
				httpx.Error(w, http.StatusBadRequest, "provider_key", "upload the private key (.p8)")
				return
			}
			if in.PrivateKey != "" {
				if _, err := oidcx.AppleSecret(cfg.TeamID, cfg.KeyID, cfg.ClientID, in.PrivateKey, time.Now()); err != nil {
					httpx.Error(w, http.StatusBadRequest, "provider_key", err.Error())
					return
				}
			}
		} else if in.ClientSecret == "" && cfg.ClientSecretRef == "" {
			httpx.Error(w, http.StatusBadRequest, "provider_secret", "enter the client secret")
			return
		}
	}
	if in.ClientSecret != "" {
		if cfg.ClientSecretRef, err = a.putSecret(ctx, "identity/providers/"+kind+"/client-secret", "client_secret", in.ClientSecret); err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
	}
	if in.PrivateKey != "" {
		if cfg.PrivateKeyRef, err = a.putSecret(ctx, "identity/providers/"+kind+"/private-key", "private_key", in.PrivateKey); err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
	}
	all[kind] = cfg
	if err := a.st.PutSetting(ctx, settingProviders, all); err != nil {
		httpx.Err(w, err)
		return
	}
	if old.Enabled && !cfg.Enabled {
		a.signOutSource(ctx, kind)
	}
	a.audit(ctx, p, "settings.provider."+kind, cfg.ClientID, map[string]any{"enabled": cfg.Enabled, "domains": cfg.AllowedDomains,
		"existing_only": cfg.ExistingOnly, "secret_changed": in.ClientSecret != "" || in.PrivateKey != ""})
	a.getProviders(w, r, p)
}

// signOutSource ends the sessions of the accounts of a source.
func (a *App) signOutSource(ctx context.Context, source string) {
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		return
	}
	for _, u := range users {
		if u.Source == source {
			_ = a.sessions.DeleteUser(ctx, u.ID, "")
		}
	}
}

// ---- the sign-in flow (shared with Umbrella single sign-in)

type ssoPending struct {
	kind   string
	hint   string
	req    oidcx.Request
	expiry time.Time
}

type ssoFlow struct {
	mu      sync.Mutex
	pending map[string]ssoPending
}

var ssoFlows sync.Map // *App → *ssoFlow

func (a *App) ssoFlow() *ssoFlow {
	f, _ := ssoFlows.LoadOrStore(a, &ssoFlow{pending: map[string]ssoPending{}})
	return f.(*ssoFlow)
}

func (f *ssoFlow) remember(p ssoPending) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for k, x := range f.pending {
		if now.After(x.expiry) {
			delete(f.pending, k)
		}
	}
	if len(f.pending) >= entraPendingMax {
		for k := range f.pending {
			delete(f.pending, k)
			break
		}
	}
	p.expiry = now.Add(ssoPendingTTL)
	f.pending[p.req.State] = p
}

func (f *ssoFlow) take(state, kind string) (ssoPending, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pending[state]
	delete(f.pending, state)
	return p, ok && p.kind == kind && time.Now().Before(p.expiry)
}

// setSSOCookie binds a sign-in to the browser. Apple answers with a
// cross-site POST, which carries only SameSite=None cookies.
func (a *App) setSSOCookie(w http.ResponseWriter, kind, value string, maxAge int) {
	same, secure := http.SameSiteLaxMode, a.opt.SecureCookies
	if kind == store.SourceApple {
		same, secure = http.SameSiteNoneMode, true
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: value, Path: "/api/auth/", HttpOnly: true, Secure: secure, SameSite: same, MaxAge: maxAge})
}

func (a *App) ssoFailed(w http.ResponseWriter, r *http.Request, kind, code string) {
	a.setSSOCookie(w, kind, "", -1)
	http.Redirect(w, r, "/login?signin_error="+url.QueryEscape(code), http.StatusSeeOther)
}

func (a *App) ssoStartAllowed(w http.ResponseWriter, r *http.Request, kind string) bool {
	ip := httpx.ClientIP(r, a.opt.TrustedProxies)
	f := a.entraFlow()
	if locked, _ := f.starts.Locked("sso:" + ip); locked {
		a.ssoFailed(w, r, kind, "too_many_attempts")
		return false
	}
	f.starts.Fail("sso:" + ip)
	return true
}

func (a *App) providerClient(ctx context.Context, kind string, p provider) (oidcx.Client, error) {
	c := oidcx.Client{Issuer: p.Issuer, ClientID: p.ClientID, RedirectURI: providerRedirect(a.publicURL(ctx), kind),
		Scopes: []string{"openid", "email", "profile"}, Extra: url.Values{}}
	switch kind {
	case store.SourceGoogle:
		if len(p.AllowedDomains) == 1 {
			c.Extra.Set("hd", p.AllowedDomains[0])
		}
		c.Extra.Set("prompt", "select_account")
	case store.SourceApple:
		c.Scopes = []string{"openid", "email", "name"}
		c.Extra.Set("response_mode", "form_post")
	default:
		c.Scopes = append(c.Scopes, strings.Fields(p.Scopes)...)
	}
	return c, nil
}

func (a *App) providerStart(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if !a.ssoStartAllowed(w, r, kind) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	all, _ := a.providers(ctx)
	p, ok := all[kind]
	if !ok || !p.Enabled || a.publicURL(ctx) == "" {
		a.ssoFailed(w, r, kind, "provider_off")
		return
	}
	m, err := oidcx.Discover(ctx, p.Issuer)
	if err != nil {
		slog.Error("sso: provider unavailable", "provider", kind, "err", err)
		a.ssoFailed(w, r, kind, "provider_unavailable")
		return
	}
	c, _ := a.providerClient(ctx, kind, p)
	req := oidcx.NewRequest()
	a.ssoFlow().remember(ssoPending{kind: kind, req: req})
	a.setSSOCookie(w, kind, req.State, int(ssoPendingTTL/time.Second))
	http.Redirect(w, r, oidcx.AuthURL(c, m, req), http.StatusFound)
}

var errNotAllowed = errors.New("the account is not allowed to sign in to Flow")

func (a *App) providerCallback(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if err := r.ParseForm(); err != nil {
		a.ssoFailed(w, r, kind, "provider_state")
		return
	}
	if e := r.Form.Get("error"); e != "" {
		slog.Warn("sso: refused by the provider", "provider", kind, "error", e)
		a.ssoFailed(w, r, kind, "provider_denied")
		return
	}
	state := r.Form.Get("state")
	c, err := r.Cookie(ssoCookie)
	pend, ok := a.ssoFlow().take(state, kind)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 || !ok {
		a.ssoFailed(w, r, kind, "provider_state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	u, err := a.completeProvider(ctx, kind, r.Form.Get("code"), r.Form.Get("user"), pend.req)
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	switch {
	case errors.Is(err, errNotAllowed):
		slog.Warn("sso: account refused", "provider", kind, "err", err)
		_ = a.st.Audit(ctx, "", "auth.login_failed", "", remote, map[string]string{"reason": err.Error(), "method": kind})
		a.ssoFailed(w, r, kind, "provider_not_allowed")
		return
	case err != nil:
		slog.Error("sso: sign-in failed", "provider", kind, "err", err)
		a.ssoFailed(w, r, kind, "provider_unavailable")
		return
	}
	a.setSSOCookie(w, kind, "", -1)
	a.redirectSignedIn(w, r, u, kind)
}

// redirectSignedIn starts the session of a person coming back from a
// provider and opens the console.
func (a *App) redirectSignedIn(w http.ResponseWriter, r *http.Request, u store.User, method string) {
	ctx := r.Context()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	if u.Disabled {
		a.ssoFailed(w, r, method, "user_disabled")
		return
	}
	if _, err := a.sessions.Create(ctx, w, u.ID, remote); err != nil {
		a.ssoFailed(w, r, method, "sign_in_unavailable")
		return
	}
	_ = a.st.TouchLogin(ctx, u.ID)
	_ = a.st.Audit(ctx, u.Username, "auth.login", "", remote, map[string]string{"source": u.Source, "method": method})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) completeProvider(ctx context.Context, kind, code, userJSON string, req oidcx.Request) (store.User, error) {
	all, err := a.providers(ctx)
	if err != nil {
		return store.User{}, err
	}
	p := all[kind]
	if !p.Enabled {
		return store.User{}, fmt.Errorf("%w: the provider is off", errNotAllowed)
	}
	m, err := oidcx.Discover(ctx, p.Issuer)
	if err != nil {
		return store.User{}, err
	}
	c, _ := a.providerClient(ctx, kind, p)
	if kind == store.SourceApple {
		key, err := a.secret(p.PrivateKeyRef)
		if err != nil {
			return store.User{}, err
		}
		if c.Secret, err = oidcx.AppleSecret(p.TeamID, p.KeyID, p.ClientID, key, time.Now()); err != nil {
			return store.User{}, err
		}
	} else if c.Secret, err = a.secret(p.ClientSecretRef); err != nil {
		return store.User{}, err
	}
	t, err := oidcx.Exchange(ctx, c, m, code, req)
	if err != nil {
		return store.User{}, err
	}
	cl, err := oidcx.Verify(ctx, m, p.ClientID, t.IDToken, req.Nonce, time.Now())
	if err != nil {
		return store.User{}, fmt.Errorf("%w: %v", errNotAllowed, err)
	}
	email := strings.ToLower(strings.TrimSpace(cl.String("email")))
	verified := cl.Bool("email_verified") || (kind == store.SourceOIDC && cl["email_verified"] == nil && email != "")
	if cl.String("sub") == "" || email == "" || !verified {
		return store.User{}, fmt.Errorf("%w: no verified e-mail address", errNotAllowed)
	}
	if !p.emailAllowed(email) {
		return store.User{}, fmt.Errorf("%w: the domain of %s is not allowed", errNotAllowed, email)
	}
	if kind == store.SourceGoogle && len(p.AllowedDomains) > 0 && !slices.Contains(p.AllowedDomains, strings.ToLower(cl.String("hd"))) {
		return store.User{}, fmt.Errorf("%w: %s is not a Workspace account of an allowed domain", errNotAllowed, email)
	}
	sub := cl.String("sub")
	if u, err := a.st.UserByExternal(ctx, kind, sub); err == nil {
		return u, nil
	}
	if u, err := a.st.UserByEmail(ctx, email); err == nil {
		_ = a.st.Audit(ctx, u.Username, "auth.provider_link", "", "", map[string]string{"provider": kind, "email": email})
		return u, nil
	}
	if p.ExistingOnly {
		return store.User{}, fmt.Errorf("%w: %s has no Flow account", errNotAllowed, email)
	}
	name := cl.String("name")
	if kind == store.SourceApple && userJSON != "" {
		var au struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if json.Unmarshal([]byte(userJSON), &au) == nil {
			name = strings.TrimSpace(au.Name.FirstName + " " + au.Name.LastName)
		}
	}
	username := email
	if pu := strings.ToLower(strings.TrimSpace(cl.String("preferred_username"))); kind == store.SourceOIDC && pu != "" && !strings.ContainsAny(pu, " /\\") {
		username = pu
	}
	role := p.RoleID
	if p.GroupsClaim != "" && p.AdminGroup != "" && p.AdminRoleID != 0 &&
		slices.ContainsFunc(cl.Strings(p.GroupsClaim), func(g string) bool { return strings.EqualFold(g, p.AdminGroup) }) {
		role = p.AdminRoleID
	}
	u, _, err := a.st.UpsertExternalUser(ctx, store.ExternalUser{Source: kind, ExternalID: sub, Username: username, Name: name, Email: email, RoleID: role})
	if errors.Is(err, store.ErrUsernameTaken) {
		return store.User{}, fmt.Errorf("%w: the user name %s belongs to another account", errNotAllowed, username)
	}
	return u, err
}
