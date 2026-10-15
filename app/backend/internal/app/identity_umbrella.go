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
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/directory"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
	"github.com/sbrw-evc/network/app/backend/internal/passkey"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/umbrellaid"
)

// Umbrella Identity, the member side (docs/identity-federation.md): Flow
// connects to Umbrella Monitoring with a connection key, signs people in
// through it and synchronizes users, roles, the password policy and passkeys
// every five minutes. Settings key "umbrella_identity"; the client secret and
// the synchronization token live in OpenBao at identity/umbrella.

const (
	settingIdentity   = "umbrella_identity"
	identitySecret    = "identity/umbrella"
	identitySyncEvery = 5 * time.Minute
	methodUmbrella    = "umbrella"
)

// roleMapping maps a hub role or directory group to a Flow role.
type roleMapping struct {
	Match  string `json:"match"`
	RoleID int64  `json:"role_id"`
	Role   string `json:"role,omitempty"`
}

type identitySettings struct {
	Enabled   bool   `json:"enabled"`
	Hub       string `json:"hub"`
	ClientID  string `json:"client_id"`
	SecretRef string `json:"secret_ref,omitempty"`
	TokenRef  string `json:"token_ref,omitempty"`
	AppName   string `json:"application"`
	// Roles: the first matching row wins; hub administrators get AdminRoleID
	// unless a row says otherwise; others DefaultRoleID (0 = no access).
	RoleMap       []roleMapping `json:"role_map"`
	DefaultRoleID int64         `json:"default_role_id"`
	AdminRoleID   int64         `json:"admin_role_id"`
	LinkLocal     bool          `json:"link_local"`
	SSO           bool          `json:"sso"`
	SyncUsers     bool          `json:"sync_users"`
	SyncPolicy    bool          `json:"sync_policy"`
	SyncPasskeys  bool          `json:"sync_passkeys"`
	// What the hub said last.
	Methods     []umbrellaid.Method `json:"methods"`
	HubPasskeys passkeySettings     `json:"hub_passkeys"`
	Status      identityStatus      `json:"status"`
}

type identityStatus struct {
	LastSync   *time.Time `json:"last_sync,omitempty"`
	OK         bool       `json:"ok"`
	Error      string     `json:"error,omitempty"`
	Created    int        `json:"created"`
	Updated    int        `json:"updated"`
	Disabled   int        `json:"disabled"`
	Conflicts  []string   `json:"conflicts"`
	Users      int        `json:"users"`
	ConfigETag string     `json:"config_etag,omitempty"`
	UsersETag  string     `json:"users_etag,omitempty"`
}

func (a *App) identitySettings(ctx context.Context) (identitySettings, error) {
	var is identitySettings
	_, err := a.st.Setting(ctx, settingIdentity, &is)
	if is.RoleMap == nil {
		is.RoleMap = []roleMapping{}
	}
	if is.Methods == nil {
		is.Methods = []umbrellaid.Method{}
	}
	if is.Status.Conflicts == nil {
		is.Status.Conflicts = []string{}
	}
	return is, err
}

func (a *App) identityKey(is identitySettings) (umbrellaid.Key, error) {
	secret, err := a.secret(is.SecretRef)
	if err != nil {
		return umbrellaid.Key{}, err
	}
	token, err := a.secret(is.TokenRef)
	if err != nil {
		return umbrellaid.Key{}, err
	}
	return umbrellaid.Key{Hub: is.Hub, ClientID: is.ClientID, ClientSecret: secret, Token: token}, nil
}

func (a *App) identityRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/identity", a.guard(perms(access.UsersView), a.getIdentity))
	h("POST /api/settings/identity/check", a.guard(perms(access.UsersEdit), a.checkIdentity))
	h("PUT /api/settings/identity", a.guard(perms(access.UsersEdit), a.putIdentity))
	h("POST /api/settings/identity/sync", a.guard(perms(access.UsersEdit), a.syncIdentityNow))
	h("DELETE /api/settings/identity", a.guard(perms(access.UsersEdit), a.disconnectIdentity))
	h("GET /api/auth/methods", a.signInMethods)
	h("GET /api/auth/umbrella/start", a.umbrellaStart)
	h("GET "+umbrellaid.CallbackPath, a.umbrellaCallback)
}

type identityView struct {
	identitySettings
	Connected   bool   `json:"connected"`
	RedirectURI string `json:"redirect_uri"`
	PublicURL   string `json:"public_url"`
}

func (a *App) identityView(ctx context.Context) (identityView, error) {
	is, err := a.identitySettings(ctx)
	if err != nil {
		return identityView{}, err
	}
	for i, m := range is.RoleMap {
		if role, err := a.st.RoleByID(ctx, m.RoleID); err == nil {
			is.RoleMap[i].Role = role.Name
		}
	}
	v := identityView{identitySettings: is, Connected: is.SecretRef != "" && is.TokenRef != "", PublicURL: a.publicURL(ctx)}
	v.SecretRef, v.TokenRef = "", ""
	if v.PublicURL != "" {
		v.RedirectURI = v.PublicURL + umbrellaid.CallbackPath
	}
	return v, nil
}

func (a *App) getIdentity(w http.ResponseWriter, r *http.Request, p *Principal) {
	v, err := a.identityView(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// identityCheck is step 1 of the connection: what the hub says about the key.
type identityCheck struct {
	Hub          string              `json:"hub"`
	Application  string              `json:"application"`
	Methods      []umbrellaid.Method `json:"methods"`
	Passkeys     passkeySettings     `json:"passkeys"`
	PasskeysHere bool                `json:"passkeys_here"`
	Users        int                 `json:"users"`
	Roles        []string            `json:"roles"`
	Groups       []string            `json:"groups"`
	Conflicts    []string            `json:"conflicts"`
}

func (a *App) checkKey(ctx context.Context, k umbrellaid.Key) (identityCheck, error) {
	public := a.publicURL(ctx)
	if public == "" {
		return identityCheck{}, httpx.BadRequest("public_url_required", "set the public address of Flow first (general settings)")
	}
	cfg, _, _, err := k.Config(ctx, "")
	if err != nil {
		return identityCheck{}, httpx.BadRequest("identity_unavailable", err.Error())
	}
	if err := k.CheckSecret(ctx, public+umbrellaid.CallbackPath); err != nil {
		return identityCheck{}, httpx.BadRequest("identity_unavailable", err.Error())
	}
	users, _, _, err := k.Users(ctx, "")
	if err != nil {
		return identityCheck{}, httpx.BadRequest("identity_unavailable", err.Error())
	}
	out := identityCheck{Hub: k.Hub, Application: cfg.Application.Name, Methods: cfg.Methods, Roles: []string{}, Groups: []string{}, Conflicts: []string{},
		Passkeys: passkeySettings{Enabled: cfg.Passkeys.Enabled, RPID: cfg.Passkeys.RPID}}
	if u, err := url.Parse(public); err == nil {
		out.PasskeysHere = cfg.Passkeys.Enabled && cfg.Passkeys.RPID != "" && passkey.HostWithin(u.Hostname(), cfg.Passkeys.RPID)
	}
	for _, u := range users {
		if u.Disabled {
			continue
		}
		out.Users++
		if n := u.RoleName(); n != "" && !slices.Contains(out.Roles, n) {
			out.Roles = append(out.Roles, n)
		}
		for _, g := range u.Groups {
			if !slices.Contains(out.Groups, g) && len(out.Groups) < 500 {
				out.Groups = append(out.Groups, g)
			}
		}
		if local, err := a.st.UserByUsername(ctx, u.Username); err == nil && local.Source != store.SourceUmbrella {
			out.Conflicts = append(out.Conflicts, local.Username)
		}
	}
	slices.Sort(out.Roles)
	slices.Sort(out.Groups)
	return out, nil
}

func (a *App) checkIdentity(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Key string `json:"key"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	k, err := a.keyFromInput(ctx, in.Key)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out, err := a.checkKey(ctx, k)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}

// keyFromInput parses a pasted key; an empty one means the stored key.
func (a *App) keyFromInput(ctx context.Context, raw string) (umbrellaid.Key, error) {
	if strings.TrimSpace(raw) != "" {
		k, err := umbrellaid.ParseKey(raw)
		if err != nil {
			return umbrellaid.Key{}, httpx.BadRequest("identity_key", err.Error())
		}
		return k, nil
	}
	is, err := a.identitySettings(ctx)
	if err != nil {
		return umbrellaid.Key{}, err
	}
	if is.SecretRef == "" {
		return umbrellaid.Key{}, httpx.BadRequest("identity_key", "paste the connection key")
	}
	return a.identityKey(is)
}

type identityInput struct {
	Key           string        `json:"key"`
	Enabled       bool          `json:"enabled"`
	RoleMap       []roleMapping `json:"role_map"`
	DefaultRoleID int64         `json:"default_role_id"`
	AdminRoleID   int64         `json:"admin_role_id"`
	LinkLocal     bool          `json:"link_local"`
	SSO           bool          `json:"sso"`
	SyncUsers     bool          `json:"sync_users"`
	SyncPolicy    bool          `json:"sync_policy"`
	SyncPasskeys  bool          `json:"sync_passkeys"`
}

func (a *App) putIdentity(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in identityInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	old, err := a.identitySettings(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	k, err := a.keyFromInput(ctx, in.Key)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	check, err := a.checkKey(ctx, k)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	is := old
	is.Enabled, is.Hub, is.ClientID, is.AppName = in.Enabled, k.Hub, k.ClientID, check.Application
	is.DefaultRoleID, is.AdminRoleID, is.LinkLocal = in.DefaultRoleID, in.AdminRoleID, in.LinkLocal
	is.SSO, is.SyncUsers, is.SyncPolicy, is.SyncPasskeys = in.SSO, in.SyncUsers, in.SyncPolicy, in.SyncPasskeys
	is.Methods, is.HubPasskeys = check.Methods, check.Passkeys
	is.RoleMap = []roleMapping{}
	for _, m := range in.RoleMap {
		m.Match = strings.TrimSpace(m.Match)
		if m.Match == "" {
			continue
		}
		if _, err := a.st.RoleByID(ctx, m.RoleID); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_role", "the role for "+m.Match+" does not exist")
			return
		}
		is.RoleMap = append(is.RoleMap, roleMapping{Match: m.Match, RoleID: m.RoleID})
	}
	for _, id := range []int64{is.DefaultRoleID, is.AdminRoleID} {
		if id != 0 {
			if _, err := a.st.RoleByID(ctx, id); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such role")
				return
			}
		}
	}
	if strings.TrimSpace(in.Key) != "" {
		if is.SecretRef, err = a.putSecret(ctx, identitySecret, "client_secret", k.ClientSecret); err == nil {
			is.TokenRef, err = a.putSecret(ctx, identitySecret+"/token", "token", k.Token)
		}
		if err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
		is.Status.ConfigETag, is.Status.UsersETag = "", ""
	}
	if err := a.st.PutSetting(ctx, settingIdentity, is); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.identity", is.Hub, map[string]any{"enabled": is.Enabled, "application": is.AppName, "sso": is.SSO,
		"sync_users": is.SyncUsers, "sync_policy": is.SyncPolicy, "sync_passkeys": is.SyncPasskeys, "key_changed": strings.TrimSpace(in.Key) != ""})
	if is.Enabled {
		if err := a.syncIdentity(ctx, "settings"); err != nil {
			slog.Warn("identity: first synchronization failed", "err", err)
		}
	} else if old.Enabled {
		a.signOutSource(ctx, store.SourceUmbrella)
	}
	a.getIdentity(w, r, p)
}

func (a *App) syncIdentityNow(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	err := a.syncIdentity(ctx, p.User.Username)
	if err != nil && !errors.Is(err, errIdentityOff) {
		a.audit(ctx, p, "identity.sync", "", map[string]string{"error": err.Error()})
	}
	a.getIdentity(w, r, p)
}

func (a *App) disconnectIdentity(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	is, err := a.identitySettings(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	is.Enabled, is.SecretRef, is.TokenRef = false, "", ""
	if err := a.st.PutSetting(ctx, settingIdentity, is); err != nil {
		httpx.Err(w, err)
		return
	}
	a.deleteSecret(ctx, identitySecret)
	a.deleteSecret(ctx, identitySecret+"/token")
	users, _ := a.st.ListUsers(ctx)
	disabled := true
	for _, u := range users {
		if u.Source == store.SourceUmbrella && !u.Disabled {
			_, _ = a.st.UpdateUser(ctx, u.ID, store.UserUpdate{Disabled: &disabled})
			_ = a.sessions.DeleteUser(ctx, u.ID, "")
		}
	}
	a.audit(ctx, p, "settings.identity", is.Hub, map[string]bool{"disconnected": true})
	a.getIdentity(w, r, p)
}

// ---- synchronization

var errIdentityOff = errors.New("Umbrella Identity is not connected")

var identitySyncMu sync.Map // *App → *sync.Mutex

// syncIdentity reads the configuration and the users of the hub and applies them.
func (a *App) syncIdentity(ctx context.Context, actor string) error {
	mu, _ := identitySyncMu.LoadOrStore(a, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	is, err := a.identitySettings(ctx)
	if err != nil {
		return err
	}
	if !is.Enabled || is.SecretRef == "" {
		return errIdentityOff
	}
	k, err := a.identityKey(is)
	if err == nil {
		err = a.applyIdentity(ctx, k, &is)
	}
	now := time.Now().UTC()
	is.Status.LastSync, is.Status.OK = &now, err == nil
	is.Status.Error = ""
	if err != nil {
		is.Status.Error = err.Error()
	}
	if perr := a.st.PutSetting(ctx, settingIdentity, is); perr != nil {
		return perr
	}
	if err != nil || is.Status.Created+is.Status.Disabled > 0 || actor != "schedule" {
		_ = a.st.Audit(ctx, actor, "identity.sync", is.Hub, "", map[string]any{"ok": err == nil, "created": is.Status.Created,
			"updated": is.Status.Updated, "disabled": is.Status.Disabled, "conflicts": is.Status.Conflicts, "error": is.Status.Error})
	}
	return err
}

func (a *App) applyIdentity(ctx context.Context, k umbrellaid.Key, is *identitySettings) error {
	cfg, tag, same, err := k.Config(ctx, is.Status.ConfigETag)
	if err != nil {
		return err
	}
	if !same {
		is.Status.ConfigETag = tag
		is.Methods, is.HubPasskeys, is.AppName = cfg.Methods, passkeySettings{Enabled: cfg.Passkeys.Enabled, RPID: cfg.Passkeys.RPID}, cfg.Application.Name
		if is.SyncPolicy && len(cfg.Policy) > 0 {
			var pol auth.PasswordPolicy
			if err := json.Unmarshal(cfg.Policy, &pol); err != nil {
				return fmt.Errorf("password policy of Umbrella: %w", err)
			}
			if err := a.st.PutSetting(ctx, setup.SettingPasswordPolicy, pol.Normalize()); err != nil {
				return err
			}
		}
	}
	if !is.SyncUsers {
		return nil
	}
	users, tag, same, err := k.Users(ctx, is.Status.UsersETag)
	if err != nil {
		return err
	}
	if same {
		is.Status.Created, is.Status.Disabled = 0, 0
		return nil
	}
	_, hubKeys := a.passkeyConfig(ctx)
	st := identityStatus{ConfigETag: is.Status.ConfigETag, Conflicts: []string{}}
	keep := []string{}
	for _, hu := range users {
		role := a.identityRole(*is, hu.RoleName(), hu.Groups, hu.Admin)
		if hu.Disabled || role == 0 {
			continue
		}
		keep = append(keep, hu.ID)
		in := store.ExternalUser{Source: store.SourceUmbrella, ExternalID: hu.ID, Username: hu.Username, Name: hu.Name, Email: hu.Email, RoleID: role}
		link := []string{}
		if is.LinkLocal {
			if local, err := a.st.UserByUsername(ctx, hu.Username); err == nil && local.Source != store.SourceUmbrella {
				if admin, _ := a.isAdmin(ctx, local.RoleID); !admin || local.Source != store.SourceLocal {
					link = append(link, local.Source)
				}
			}
		}
		u, created, err := a.st.UpsertExternalUser(ctx, in, link...)
		if errors.Is(err, store.ErrUsernameTaken) {
			st.Conflicts = append(st.Conflicts, hu.Username)
			continue
		}
		if err != nil {
			return err
		}
		st.Users++
		if created {
			st.Created++
		} else {
			st.Updated++
		}
		if is.SyncPasskeys && hubKeys {
			keys := make([]store.Passkey, 0, len(hu.Passkeys))
			for _, pk := range hu.Passkeys {
				cred, err1 := passkey.Decode(pk.CredentialID)
				pub, err2 := passkey.Decode(pk.PublicKey)
				handle, err3 := passkey.Decode(pk.UserHandle)
				if err1 != nil || err2 != nil || err3 != nil {
					continue
				}
				keys = append(keys, store.Passkey{Name: pk.Name, CredentialID: cred, PublicKey: pub, UserHandle: handle, SignCount: pk.SignCount,
					AAGUID: passkey.ParseAAGUID(pk.AAGUID), Transports: pk.Transports, BackupEligible: pk.BackupEligible, HubID: pk.ID, CreatedAt: pk.CreatedAt})
			}
			if err := a.st.ReplaceHubPasskeys(ctx, u.ID, keys); err != nil {
				return err
			}
		}
	}
	disabled, err := a.st.DisableMissing(ctx, store.SourceUmbrella, keep)
	if err != nil {
		return err
	}
	for _, id := range disabled {
		_ = a.sessions.DeleteUser(ctx, id, "")
	}
	st.Disabled = len(disabled)
	st.UsersETag = tag
	is.Status = st
	return nil
}

// identityRole maps a hub person to a Flow role (0 = no access).
func (a *App) identityRole(is identitySettings, role string, groups []string, admin bool) int64 {
	for _, m := range is.RoleMap {
		if strings.EqualFold(m.Match, role) {
			return m.RoleID
		}
		for _, g := range groups {
			if strings.EqualFold(m.Match, g) || directory.NormalizeDN(m.Match) == directory.NormalizeDN(g) {
				return m.RoleID
			}
		}
	}
	if admin && is.AdminRoleID != 0 {
		return is.AdminRoleID
	}
	return is.DefaultRoleID
}

// runIdentitySchedule synchronizes every five minutes.
func (a *App) runIdentitySchedule(ctx context.Context) {
	t := time.NewTicker(identitySyncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := a.syncIdentity(sctx, "schedule"); err != nil && !errors.Is(err, errIdentityOff) {
				slog.Warn("identity: synchronization failed", "err", err)
			}
			cancel()
		}
	}
}

// ---- sign-in

// signInMethods tells the sign-in page which buttons to show.
func (a *App) signInMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{"passkeys": false, "entra": false, "providers": []map[string]string{}, "umbrella": nil}
	if ps, _ := a.passkeyConfig(ctx); ps.Enabled {
		out["passkeys"] = true
	}
	if es, err := a.entraSettings(ctx); err == nil && es.Enabled {
		out["entra"] = true
	}
	if all, err := a.providers(ctx); err == nil {
		list := []map[string]string{}
		for _, kind := range providerKinds {
			if p := all[kind]; p.Enabled {
				list = append(list, map[string]string{"id": kind, "title": providerTitle(kind, p)})
			}
		}
		out["providers"] = list
	}
	if is, err := a.identitySettings(ctx); err == nil && is.Enabled && is.SSO {
		out["umbrella"] = map[string]any{"hub": is.Hub, "methods": is.Methods}
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) umbrellaStart(w http.ResponseWriter, r *http.Request) {
	if !a.ssoStartAllowed(w, r, methodUmbrella) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	is, err := a.identitySettings(ctx)
	public := a.publicURL(ctx)
	if err != nil || !is.Enabled || !is.SSO || public == "" {
		a.ssoFailed(w, r, methodUmbrella, "umbrella_off")
		return
	}
	k, err := a.identityKey(is)
	if err != nil {
		a.ssoFailed(w, r, methodUmbrella, "umbrella_unavailable")
		return
	}
	hint := r.URL.Query().Get("method")
	if hint == methodUmbrella {
		hint = ""
	}
	req := oidcx.NewRequest()
	target, err := k.AuthURL(ctx, public+umbrellaid.CallbackPath, hint, req)
	if err != nil {
		slog.Error("identity: sign-in cannot start", "err", err)
		a.ssoFailed(w, r, methodUmbrella, "umbrella_unavailable")
		return
	}
	a.ssoFlow().remember(ssoPending{kind: methodUmbrella, hint: hint, req: req})
	a.setSSOCookie(w, methodUmbrella, req.State, int(ssoPendingTTL/time.Second))
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *App) umbrellaCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		code := "umbrella_denied"
		if e == "access_denied" {
			code = "umbrella_no_access"
		}
		a.ssoFailed(w, r, methodUmbrella, code)
		return
	}
	state := q.Get("state")
	c, err := r.Cookie(ssoCookie)
	pend, ok := a.ssoFlow().take(state, methodUmbrella)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 || !ok {
		a.ssoFailed(w, r, methodUmbrella, "provider_state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	is, err := a.identitySettings(ctx)
	if err != nil || !is.Enabled {
		a.ssoFailed(w, r, methodUmbrella, "umbrella_off")
		return
	}
	k, err := a.identityKey(is)
	if err != nil {
		a.ssoFailed(w, r, methodUmbrella, "umbrella_unavailable")
		return
	}
	id, err := k.Finish(ctx, a.publicURL(ctx)+umbrellaid.CallbackPath, q.Get("code"), pend.req)
	if err != nil {
		slog.Error("identity: sign-in failed", "err", err)
		a.ssoFailed(w, r, methodUmbrella, "umbrella_unavailable")
		return
	}
	u, err := a.st.UserByExternal(ctx, store.SourceUmbrella, id.Subject)
	if errors.Is(err, store.ErrNotFound) {
		// Not synchronized yet (a new person, or synchronization is off).
		role := a.identityRole(is, id.Role, id.Groups, id.Admin)
		if role == 0 {
			a.ssoFailed(w, r, methodUmbrella, "umbrella_no_access")
			return
		}
		u, _, err = a.st.UpsertExternalUser(ctx, store.ExternalUser{Source: store.SourceUmbrella, ExternalID: id.Subject,
			Username: id.Username, Name: id.Name, Email: id.Email, RoleID: role})
	}
	if err != nil {
		slog.Warn("identity: account refused", "user", id.Username, "err", err)
		a.ssoFailed(w, r, methodUmbrella, "umbrella_account")
		return
	}
	a.setSSOCookie(w, methodUmbrella, "", -1)
	a.redirectSignedIn(w, r, u, methodUmbrella+":"+strings.Join(id.Methods, "+"))
}
