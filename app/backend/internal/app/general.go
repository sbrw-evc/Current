package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/config"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/setup"
)

// ---- general settings (language, theme, time zone, address, GeoIP)

type generalView struct {
	setup.General
	GeoIP setup.GeoIPSettings `json:"geoip"`
}

func (a *App) loadGeneral(ctx context.Context) (generalView, error) {
	v := generalView{General: setup.General{Language: "ru", Theme: "system", Timezone: "UTC"}, GeoIP: setup.GeoIPSettings{Databases: []string{}}}
	if _, err := a.st.Setting(ctx, setup.SettingGeneral, &v.General); err != nil {
		return v, err
	}
	if _, err := a.st.Setting(ctx, setup.SettingGeoIP, &v.GeoIP); err != nil {
		return v, err
	}
	return v, nil
}

func (a *App) getGeneral(w http.ResponseWriter, r *http.Request, p *Principal) {
	v, err := a.loadGeneral(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *App) putGeneral(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in generalView
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	in.PublicURL = strings.TrimRight(strings.TrimSpace(in.PublicURL), "/")
	g := in.General
	if g.Language != "ru" && g.Language != "en" {
		httpx.Error(w, http.StatusBadRequest, "invalid_language", "language must be ru or en")
		return
	}
	if g.Theme != "light" && g.Theme != "dark" && g.Theme != "system" {
		httpx.Error(w, http.StatusBadRequest, "invalid_theme", "theme must be light, dark or system")
		return
	}
	if _, err := time.LoadLocation(g.Timezone); err != nil || g.Timezone == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid_timezone", "unknown time zone")
		return
	}
	if g.PublicURL != "" {
		if _, err := checkURL(g.PublicURL); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	geo := in.GeoIP
	if geo.Databases == nil {
		geo.Databases = []string{}
	}
	if len(geo.Databases) > 0 {
		if c := setup.CheckGeoIP(geo.Databases); !c.OK {
			httpx.Error(w, http.StatusBadRequest, "geoip_unavailable", c.Error)
			return
		}
	}
	for _, step := range []func() error{
		func() error { return a.st.PutSetting(ctx, setup.SettingGeneral, g) },
		func() error { return a.st.PutSetting(ctx, setup.SettingGeoIP, geo) },
	} {
		if err := step(); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	a.audit(ctx, p, "settings.general", "", map[string]any{"language": g.Language, "theme": g.Theme, "timezone": g.Timezone,
		"public_url": g.PublicURL, "geoip": len(geo.Databases)})
	a.reload(ctx, ReloadGeoIP)
	a.reload(ctx, ReloadGeneral)
	a.getGeneral(w, r, p)
}

func (a *App) testGeoIP(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in setup.GeoIPSettings
	if !httpx.Decode(w, r, &in) {
		return
	}
	httpx.JSON(w, http.StatusOK, setup.CheckGeoIP(in.Databases))
}

// ---- Beacon connection (events of the detector go there)

func (a *App) loadUmbrella(ctx context.Context) (setup.UmbrellaSettings, error) {
	var u setup.UmbrellaSettings
	_, err := a.st.Setting(ctx, setup.SettingUmbrella, &u)
	return u, err
}

func (a *App) getUmbrella(w http.ResponseWriter, r *http.Request, p *Principal) {
	u, err := a.loadUmbrella(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"enabled": u.Enabled, "ingest_url": u.IngestURL, "token_set": u.TokenRef != ""})
}

type umbrellaInput struct {
	Enabled   bool    `json:"enabled"`
	IngestURL string  `json:"ingest_url"`
	Token     *string `json:"token"` // nil = keep
}

// umbrellaTarget merges the input with the stored settings and resolves the token.
func (a *App) umbrellaTarget(ctx context.Context, in umbrellaInput) (setup.UmbrellaSettings, string, error) {
	u, err := a.loadUmbrella(ctx)
	if err != nil {
		return u, "", err
	}
	u.Enabled, u.IngestURL = in.Enabled, strings.TrimSpace(in.IngestURL)
	if in.Token != nil {
		return u, strings.TrimSpace(*in.Token), nil
	}
	tok, err := a.secret(u.TokenRef)
	return u, tok, err
}

func (a *App) putUmbrella(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in umbrellaInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	u, tok, err := a.umbrellaTarget(ctx, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if u.Enabled && (u.IngestURL == "" || tok == "") {
		httpx.Error(w, http.StatusBadRequest, "umbrella_invalid", "the ingest address and the token are required")
		return
	}
	if in.Token != nil {
		if tok == "" {
			a.deleteSecret(ctx, setup.SecretUmbrella)
			u.TokenRef = ""
		} else if u.TokenRef, err = a.putSecret(ctx, setup.SecretUmbrella, "token", tok); err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
	}
	if err := a.st.PutSetting(ctx, setup.SettingUmbrella, u); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.umbrella", u.IngestURL, map[string]any{"enabled": u.Enabled, "token_changed": in.Token != nil})
	a.reload(ctx, ReloadUmbrella)
	a.getUmbrella(w, r, p)
}

func (a *App) testUmbrella(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in umbrellaInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	u, tok, err := a.umbrellaTarget(r.Context(), in)
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	if a.deps.Detector == nil || u.IngestURL == "" || tok == "" {
		httpx.JSON(w, http.StatusOK, setup.CheckUmbrella(r.Context(), u.IngestURL, tok))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ev, err := a.deps.Detector.SendTest(ctx, u.IngestURL, tok)
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, setup.CheckResult{OK: true, Details: map[string]any{"event": ev}})
}

// ---- OpenBao

func (a *App) getOpenBao(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	st := a.deps.Vault.Status(ctx)
	ob := a.config().OpenBao
	out := map[string]any{
		"addr": st.Addr, "mount": st.Mount, "auth": st.Auth,
		// status.ok: reachable, unsealed, the token works and the mount is readable.
		"status": struct {
			OK bool `json:"ok"`
			secrets.Status
		}{st.Reachable && !st.Sealed && st.TokenOK && st.MountOK && st.Error == "", st},
	}
	if ob.RoleID != "" && ob.Auth == config.AuthAppRole {
		out["role_id"] = ob.RoleID // the role id is an identifier, the secret id is never shown
	}
	httpx.JSON(w, http.StatusOK, out)
}

// testOpenBao checks the current connection (empty body) or another server.
func (a *App) testOpenBao(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	raw, ok := httpx.Raw(w, r)
	if !ok {
		return
	}
	var in setup.OpenBaoInput
	if err := json.Unmarshal(raw, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	// An empty body ({} from the console) checks the current connection.
	if strings.TrimSpace(in.Addr) == "" {
		rep := a.deps.Vault.Verify(ctx)
		httpx.JSON(w, http.StatusOK, setup.CheckResult{OK: rep.OK, Error: rep.Error, Details: rep.Status})
		return
	}
	_, res := setup.CheckOpenBao(ctx, config.OpenBao{Addr: in.Addr, Mount: in.Mount, Namespace: in.Namespace, Auth: in.Auth,
		Token: in.Token, RoleID: in.RoleID, SecretID: in.SecretID, CACert: in.CACert, SkipVerify: in.SkipVerify})
	httpx.JSON(w, http.StatusOK, res)
}
