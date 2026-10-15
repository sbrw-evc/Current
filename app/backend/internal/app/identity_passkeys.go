package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/passkey"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Passkeys (WebAuthn with user verification): Windows Hello (face,
// fingerprint, iris, PIN), Touch ID / Face ID, Android biometrics, security
// keys. Settings key "passkeys". When Flow is connected to Umbrella Identity
// and its address is inside the hub's passkey domain, the hub's domain is used
// and the hub's passkeys are synchronized, so one passkey works everywhere.

const (
	settingPasskeys = "passkeys"
	maxPasskeys     = 20
)

type passkeySettings struct {
	Enabled bool   `json:"enabled"`
	RPID    string `json:"rp_id"`
}

var (
	ceremoniesMu sync.Mutex
	ceremonies   = map[*App]*passkey.Ceremonies{}
)

func (a *App) ceremonies() *passkey.Ceremonies {
	ceremoniesMu.Lock()
	defer ceremoniesMu.Unlock()
	c := ceremonies[a]
	if c == nil {
		c = passkey.NewCeremonies()
		ceremonies[a] = c
	}
	return c
}

// passkeyConfig is the passkey setting in effect: the hub's when Flow uses
// the hub's passkeys, else the local one.
func (a *App) passkeyConfig(ctx context.Context) (passkeySettings, bool) {
	var ps passkeySettings
	_, _ = a.st.Setting(ctx, settingPasskeys, &ps)
	if is, err := a.identitySettings(ctx); err == nil && is.Enabled && is.SyncPasskeys && is.HubPasskeys.Enabled && is.HubPasskeys.RPID != "" {
		host := ""
		if g, err := a.loadGeneral(ctx); err == nil {
			if u, err := url.Parse(g.PublicURL); err == nil {
				host = u.Hostname()
			}
		}
		if host == "" || passkey.HostWithin(host, is.HubPasskeys.RPID) {
			return passkeySettings{Enabled: true, RPID: is.HubPasskeys.RPID}, true
		}
	}
	return ps, false
}

func (a *App) passkeyParty(r *http.Request) (passkey.Party, error) {
	ps, _ := a.passkeyConfig(r.Context())
	if !ps.Enabled {
		return passkey.Party{}, &httpx.HTTPError{Status: http.StatusConflict, Code: "passkeys_off", Msg: "passkeys are turned off"}
	}
	p, err := passkey.NewParty(ps.RPID, "Umbrella Flow", r.Header.Get("Origin"))
	if err != nil {
		return passkey.Party{}, &httpx.HTTPError{Status: http.StatusBadRequest, Code: "passkey_origin", Msg: "this address is outside the passkey domain"}
	}
	return p, nil
}

func keyOf(k store.Passkey) passkey.Key {
	return passkey.Key{ID: strconv.FormatInt(k.ID, 10), Name: k.Name, CredentialID: k.CredentialID, PublicKey: k.PublicKey,
		UserHandle: k.UserHandle, SignCount: k.SignCount, AAGUID: k.AAGUID, Transports: k.Transports,
		BackupEligible: k.BackupEligible, BackupState: k.BackupState, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
}

// userHandle is the user ID stored in the authenticators of local passkeys.
func userHandle(id int64) []byte { return []byte("flow:" + strconv.FormatInt(id, 10)) }

func (a *App) passkeyAccount(ctx context.Context, u store.User) (passkey.Account, error) {
	keys, err := a.st.Passkeys(ctx, u.ID)
	if err != nil {
		return passkey.Account{}, err
	}
	acc := passkey.Account{Handle: userHandle(u.ID), Name: u.Username, Display: u.Name}
	for _, k := range keys {
		if bytes.Equal(k.UserHandle, acc.Handle) {
			acc.Keys = append(acc.Keys, keyOf(k))
		}
	}
	return acc, nil
}

func (a *App) passkeyRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("POST /api/auth/passkey/begin", a.passkeyBegin)
	h("POST /api/auth/passkey/finish", a.passkeyFinish)
	h("GET /api/auth/me/passkeys", a.guard(nil, a.myPasskeys))
	h("POST /api/auth/me/passkeys/begin", a.guard(nil, a.passkeyRegisterBegin))
	h("POST /api/auth/me/passkeys/finish", a.guard(nil, a.passkeyRegisterFinish))
	h("PATCH /api/auth/me/passkeys/{id}", a.guard(nil, a.renamePasskey))
	h("DELETE /api/auth/me/passkeys/{id}", a.guard(nil, a.deleteMyPasskey))
	h("GET /api/users/{id}/passkeys", a.guard(perms(access.UsersView), a.userPasskeys))
	h("DELETE /api/users/{id}/passkeys", a.guard(perms(access.UsersEdit), a.deleteUserPasskeys))
	h("GET /api/settings/passkeys", a.guard(perms(access.UsersView), a.getPasskeySettings))
	h("PUT /api/settings/passkeys", a.guard(perms(access.UsersEdit), a.putPasskeySettings))
}

func (a *App) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, a.opt.TrustedProxies)
	f := a.entraFlow()
	if locked, _ := f.starts.Locked("passkey:" + ip); locked {
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "too many sign-in attempts")
		return
	}
	f.starts.Fail("passkey:" + ip)
	p, err := a.passkeyParty(r)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	started, err := a.ceremonies().BeginLogin(p)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, started)
}

type passkeyAnswer struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (a *App) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	var in passkeyAnswer
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	var stored store.Passkey
	acc, key, err := a.ceremonies().FinishLogin(in.Ceremony, in.Credential, func(credID, handle []byte) (passkey.Account, error) {
		k, err := a.st.PasskeyByCredential(ctx, credID)
		if err != nil {
			return passkey.Account{}, passkey.ErrUnknown
		}
		stored = k
		u, err := a.st.UserByID(ctx, k.UserID)
		if err != nil || u.Disabled {
			return passkey.Account{}, passkey.ErrUnknown
		}
		keys, err := a.st.Passkeys(ctx, u.ID)
		if err != nil {
			return passkey.Account{}, err
		}
		list := make([]passkey.Key, 0, len(keys))
		for _, x := range keys {
			list = append(list, keyOf(x))
		}
		acc, ok := passkey.AccountFor(u.Username, u.Name, list, credID, handle)
		if !ok {
			return passkey.Account{}, passkey.ErrUnknown
		}
		return acc, nil
	}, time.Now())
	if err != nil {
		code := "passkey_failed"
		if errors.Is(err, passkey.ErrCeremony) {
			code = "passkey_expired"
		}
		_ = a.st.Audit(ctx, "", "auth.login_failed", "", remote, map[string]string{"reason": code, "method": "passkey"})
		httpx.Error(w, http.StatusUnauthorized, code, err.Error())
		return
	}
	_ = acc
	if err := a.st.TouchPasskey(ctx, stored.ID, key.SignCount, key.BackupState); err != nil {
		slog.Warn("passkey use not recorded", "err", err)
	}
	u, err := a.st.UserByID(ctx, stored.UserID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.signedIn(w, r, u, "passkey", stored.Name)
}

// signedIn starts the session of a person signed in without a password and
// answers with the user (JSON).
func (a *App) signedIn(w http.ResponseWriter, r *http.Request, u store.User, method, detail string) {
	ctx := r.Context()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	ss, err := a.sessions.Create(ctx, w, u.ID, remote)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	_ = a.st.TouchLogin(ctx, u.ID)
	list, err := a.st.Permissions(ctx, u.ID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	_ = a.st.Audit(ctx, u.Username, "auth.login", "", remote, map[string]string{"source": u.Source, "method": method, "detail": detail})
	httpx.JSON(w, http.StatusOK, map[string]any{"user": a.viewOf(ctx, u, access.NewSet(list)), "csrf": ss.CSRF})
}

func (a *App) myPasskeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	keys, err := a.st.Passkeys(r.Context(), p.User.ID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, keys)
}

func (a *App) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	party, err := a.passkeyParty(r)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if _, hub := a.passkeyConfig(ctx); hub && p.User.Source == store.SourceUmbrella {
		httpx.Error(w, http.StatusConflict, "passkeys_hub", "passkeys come from Umbrella Monitoring: add them in your Umbrella profile")
		return
	}
	if n, err := a.st.CountPasskeys(ctx, p.User.ID); err != nil || n >= maxPasskeys {
		httpx.Error(w, http.StatusConflict, "passkey_limit", "too many passkeys")
		return
	}
	acc, err := a.passkeyAccount(ctx, p.User)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	started, err := a.ceremonies().BeginRegistration(party, strconv.FormatInt(p.User.ID, 10), acc)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, started)
}

func passkeyName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 64 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 }) {
		return "", httpx.BadRequest("passkey_name", "the name is too long")
	}
	return s, nil
}

func (a *App) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in passkeyAnswer
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	name, err := passkeyName(in.Name)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	acc, err := a.passkeyAccount(ctx, p.User)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	k, err := a.ceremonies().FinishRegistration(in.Ceremony, strconv.FormatInt(p.User.ID, 10), acc, in.Credential, time.Now())
	if err != nil {
		code := "passkey_failed"
		if errors.Is(err, passkey.ErrCeremony) {
			code = "passkey_expired"
		}
		httpx.Error(w, http.StatusBadRequest, code, err.Error())
		return
	}
	if name != "" {
		k.Name = name
	}
	saved, err := a.st.AddPasskey(ctx, store.Passkey{UserID: p.User.ID, Name: k.Name, CredentialID: k.CredentialID, PublicKey: k.PublicKey,
		UserHandle: k.UserHandle, SignCount: k.SignCount, AAGUID: k.AAGUID, Transports: k.Transports, BackupEligible: k.BackupEligible,
		BackupState: k.BackupState})
	if err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "passkey.add", p.User.Username, map[string]string{"name": saved.Name})
	httpx.JSON(w, http.StatusCreated, saved)
}

func (a *App) renamePasskey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Name string `json:"name"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	name, err := passkeyName(in.Name)
	if err != nil || name == "" {
		httpx.Error(w, http.StatusBadRequest, "passkey_name", "enter a name")
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	k, err := a.st.RenamePasskey(r.Context(), p.User.ID, id, name)
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, k)
}

func (a *App) deleteMyPasskey(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.Error(w, http.StatusNotFound, "not_found", "no such passkey")
		return
	}
	if _, err := a.st.DeletePasskey(r.Context(), p.User.ID, id); err != nil {
		storeErr(w, err)
		return
	}
	a.audit(r.Context(), p, "passkey.remove", p.User.Username, map[string]int64{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) userPasskeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	keys, err := a.st.Passkeys(r.Context(), id)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, keys)
}

func (a *App) deleteUserPasskeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := a.st.UserByID(r.Context(), id)
	if err != nil {
		storeErr(w, err)
		return
	}
	n, err := a.st.DeletePasskey(r.Context(), id, 0)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "passkey.remove", u.Username, map[string]int64{"removed": n})
	w.WriteHeader(http.StatusNoContent)
}

type passkeySettingsView struct {
	passkeySettings
	FromHub   bool   `json:"from_hub"`
	Effective string `json:"effective_rp_id"`
}

func (a *App) passkeySettingsView(ctx context.Context) passkeySettingsView {
	var local passkeySettings
	_, _ = a.st.Setting(ctx, settingPasskeys, &local)
	eff, hub := a.passkeyConfig(ctx)
	v := passkeySettingsView{passkeySettings: local, FromHub: hub, Effective: eff.RPID}
	if v.Effective == "" {
		if g, err := a.loadGeneral(ctx); err == nil {
			if u, err := url.Parse(g.PublicURL); err == nil {
				v.Effective = u.Hostname()
			}
		}
	}
	if hub {
		v.Enabled = true
	}
	return v
}

func (a *App) getPasskeySettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	httpx.JSON(w, http.StatusOK, a.passkeySettingsView(r.Context()))
}

func (a *App) putPasskeySettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in passkeySettings
	if !httpx.Decode(w, r, &in) {
		return
	}
	in.RPID = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.RPID), "."))
	if in.RPID != "" && (strings.ContainsAny(in.RPID, "/:@ ") || !strings.Contains(in.RPID, ".") && in.RPID != "localhost") {
		httpx.Error(w, http.StatusBadRequest, "passkey_domain", "enter a domain name such as example.com")
		return
	}
	if err := a.st.PutSetting(r.Context(), settingPasskeys, in); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "settings.passkeys", in.RPID, map[string]bool{"enabled": in.Enabled})
	httpx.JSON(w, http.StatusOK, a.passkeySettingsView(r.Context()))
}

// policyManaged: the password policy comes from Umbrella Identity.
func (a *App) policyManaged(ctx context.Context) bool {
	is, err := a.identitySettings(ctx)
	return err == nil && is.Enabled && is.SyncPolicy
}

// passwordPolicyRoutes: GET / PUT /api/settings/password-policy.
func (a *App) passwordPolicyRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/password-policy", a.guard(nil, func(w http.ResponseWriter, r *http.Request, p *Principal) {
		httpx.JSON(w, http.StatusOK, map[string]any{"policy": a.policy(r.Context()), "managed_by_hub": a.policyManaged(r.Context())})
	}))
	h("PUT /api/settings/password-policy", a.guard(perms(access.UsersEdit), func(w http.ResponseWriter, r *http.Request, p *Principal) {
		var in auth.PasswordPolicy
		if !httpx.Decode(w, r, &in) {
			return
		}
		ctx := r.Context()
		if a.policyManaged(ctx) {
			httpx.Error(w, http.StatusConflict, "policy_managed", "the password policy comes from Umbrella Monitoring")
			return
		}
		if err := in.Check(); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		if err := a.st.PutSetting(ctx, setup.SettingPasswordPolicy, in.Normalize()); err != nil {
			httpx.Err(w, err)
			return
		}
		a.audit(ctx, p, "settings.password_policy", "", in)
		httpx.JSON(w, http.StatusOK, map[string]any{"policy": a.policy(ctx), "managed_by_hub": false})
	}))
}
