package app

import (
	"context"
	"net/http"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/umbrella"
)

// Settings → Umbrella, API part: Umbrella's address and a service-account
// token (Umbrella permissions integrations.flow:read and cmdb:propose) for
// visibility scopes and dependency proposals. The ingest URL and token of the
// detector's events stay under /api/settings/umbrella.

const (
	settingUmbrellaAPI = "umbrella_api" // {url, token_ref}
	secretUmbrellaAPI  = "umbrella-api" // #token
)

type umbrellaAPISettings struct {
	URL      string `json:"url"`
	TokenRef string `json:"token_ref,omitempty"`
}

func (a *App) loadUmbrellaAPI(ctx context.Context) (umbrellaAPISettings, error) {
	var s umbrellaAPISettings
	_, err := a.st.Setting(ctx, settingUmbrellaAPI, &s)
	return s, err
}

// umbrellaClient returns a client for the stored connection.
func (a *App) umbrellaClient(ctx context.Context) (*umbrella.Client, error) {
	s, err := a.loadUmbrellaAPI(ctx)
	if err != nil {
		return nil, err
	}
	if s.URL == "" || s.TokenRef == "" {
		return nil, umbrella.ErrNotConfigured
	}
	tok, err := a.secret(s.TokenRef)
	if err != nil {
		return nil, err
	}
	return &umbrella.Client{BaseURL: s.URL, Token: tok, HTTP: a.umb.HTTP}, nil
}

type umbrellaAPIView struct {
	URL      string `json:"url"`
	TokenSet bool   `json:"token_set"`
}

func (a *App) getUmbrellaAPI(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadUmbrellaAPI(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, umbrellaAPIView{URL: s.URL, TokenSet: s.TokenRef != ""})
}

type umbrellaAPIInput struct {
	URL   *string `json:"url"`
	Token *string `json:"token"` // nil = keep, "" = remove
}

// umbrellaAPIDraft merges the input with the stored settings and resolves
// the token.
func (a *App) umbrellaAPIDraft(ctx context.Context, in umbrellaAPIInput) (umbrellaAPISettings, string, error) {
	s, err := a.loadUmbrellaAPI(ctx)
	if err != nil {
		return s, "", err
	}
	if in.URL != nil {
		s.URL = strings.TrimRight(strings.TrimSpace(*in.URL), "/")
		s.URL = strings.TrimSuffix(s.URL, "/api")
	}
	if s.URL != "" {
		if s.URL, err = checkURL(s.URL); err != nil {
			return s, "", httpx.BadRequest("invalid_url", "the Umbrella address must look like https://umbrella.example")
		}
	}
	tok := ""
	switch {
	case in.Token != nil:
		tok = strings.TrimSpace(*in.Token)
	case s.TokenRef != "":
		if tok, err = a.secret(s.TokenRef); err != nil {
			return s, "", err
		}
	}
	return s, tok, nil
}

func (a *App) putUmbrellaAPI(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in umbrellaAPIInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	s, _, err := a.umbrellaAPIDraft(ctx, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if in.Token != nil {
		if tok := strings.TrimSpace(*in.Token); tok == "" {
			if s.TokenRef != "" {
				a.deleteSecret(ctx, secretUmbrellaAPI)
			}
			s.TokenRef = ""
		} else if s.TokenRef, err = a.putSecret(ctx, secretUmbrellaAPI, "token", tok); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	if s.TokenRef != "" && s.URL == "" {
		httpx.Error(w, http.StatusBadRequest, "umbrella_invalid", "the Umbrella address is required with a token")
		return
	}
	if err := a.st.PutSetting(ctx, settingUmbrellaAPI, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.scopeCache().Invalidate()
	a.audit(ctx, p, "settings.umbrella.api", s.URL, map[string]any{"token_changed": in.Token != nil})
	httpx.JSON(w, http.StatusOK, umbrellaAPIView{URL: s.URL, TokenSet: s.TokenRef != ""})
}

// testUmbrellaAPI asks Umbrella for the scope of the signed-in user with the
// draft (or stored) address and token.
func (a *App) testUmbrellaAPI(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in umbrellaAPIInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	s, tok, err := a.umbrellaAPIDraft(ctx, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	type result struct {
		OK      bool       `json:"ok"`
		Error   string     `json:"error,omitempty"`
		Details *scopeView `json:"details,omitempty"`
	}
	if s.URL == "" || tok == "" {
		httpx.JSON(w, http.StatusOK, result{Error: "the Umbrella address and the service-account token are required"})
		return
	}
	c := &umbrella.Client{BaseURL: s.URL, Token: tok, HTTP: a.umb.HTTP}
	reply, err := c.Scope(ctx, p.User.Username)
	if err != nil {
		httpx.JSON(w, http.StatusOK, result{Error: err.Error()})
		return
	}
	v := &scopeView{Restricted: scopeRestricted(p), OK: true, Configured: true}
	fillScopeView(v, reply)
	httpx.JSON(w, http.StatusOK, result{OK: true, Details: v})
}
