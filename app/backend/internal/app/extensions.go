package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/flowlogs"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/rdns"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/threat"
)

// extensionRoutes registers reverse DNS, threat intelligence and cloud flow
// log endpoints (docs/api.md, "Enrichment extensions").
func (a *App) extensionRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/rdns", a.guard(perms(access.RDNSView), a.getRDNS))
	h("PUT /api/settings/rdns", a.guard(perms(access.RDNSEdit), a.putRDNS))
	h("GET /api/settings/threat", a.guard(perms(access.ThreatView), a.getThreat))
	h("PUT /api/settings/threat", a.guard(perms(access.ThreatEdit), a.putThreat))
	h("POST /api/settings/threat/refresh", a.guard(perms(access.ThreatEdit), a.refreshThreat))
	h("GET /api/settings/flowlogs", a.guard(perms(access.FlowLogsView), a.getFlowLogs))
	h("PUT /api/settings/flowlogs", a.guard(perms(access.FlowLogsEdit), a.putFlowLogs))
	// Token authentication of its own (no session, no CSRF): called by
	// AWS Firehose, Azure forwarders and GCP Pub/Sub push subscriptions.
	h("POST /api/ingest/flowlogs/{provider}", func(w http.ResponseWriter, r *http.Request) {
		if a.deps.FlowLogs == nil {
			notImplemented(w, "cloud flow log ingestion (no bus in this process)")
			return
		}
		a.deps.FlowLogs.ServeHTTP(w, r)
	})
}

// ---- reverse DNS

func (a *App) loadRDNS(ctx context.Context) (rdns.Settings, error) {
	var s rdns.Settings
	_, err := a.st.Setting(ctx, rdns.SettingKey, &s)
	return s.WithDefaults(), err
}

func (a *App) getRDNS(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadRDNS(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := map[string]any{"settings": s}
	if c, ok := a.deps.Components["rdns"]; ok {
		out["stats"] = c.Status(r.Context())
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) putRDNS(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in rdns.Settings
	if !httpx.Decode(w, r, &in) {
		return
	}
	for i, s := range in.Servers {
		in.Servers[i] = strings.TrimSpace(s)
	}
	in = in.WithDefaults()
	if err := in.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, "rdns_invalid", err.Error())
		return
	}
	ctx := r.Context()
	if err := a.st.PutSetting(ctx, rdns.SettingKey, in); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.rdns", "", map[string]any{"enabled": in.Enabled, "servers": in.Servers, "scope": in.Scope})
	a.reload(ctx, rdns.SettingKey)
	a.getRDNS(w, r, p)
}

// ---- threat intelligence

func (a *App) loadThreat(ctx context.Context) (threat.Settings, error) {
	s := threat.Default()
	var stored threat.Settings
	found, err := a.st.Setting(ctx, threat.SettingKey, &stored)
	if found {
		s = stored
	}
	return s.WithDefaults(), err
}

func (a *App) getThreat(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	s, err := a.loadThreat(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	status := threat.Status{Lists: []threat.ListStatus{}}
	if _, err := a.st.Setting(ctx, threat.StatusKey, &status); err != nil {
		httpx.Err(w, err)
		return
	}
	if status.Lists == nil {
		status.Lists = []threat.ListStatus{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"settings": s, "status": status, "default_lists": threat.DefaultLists()})
}

func (a *App) putThreat(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in threat.Settings
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	cur, err := a.loadThreat(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	for i := range in.Lists {
		in.Lists[i].Name, in.Lists[i].URL = strings.TrimSpace(in.Lists[i].Name), strings.TrimSpace(in.Lists[i].URL)
	}
	in.RefreshRequestedAt = cur.RefreshRequestedAt
	in = in.WithDefaults()
	if err := in.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, "threat_invalid", err.Error())
		return
	}
	if err := a.st.PutSetting(ctx, threat.SettingKey, in); err != nil {
		httpx.Err(w, err)
		return
	}
	names := make([]string, 0, len(in.Lists))
	for _, l := range in.Lists {
		if l.Enabled {
			names = append(names, l.Name)
		}
	}
	a.audit(ctx, p, "settings.threat", "", map[string]any{"enabled": in.Enabled, "lists": names, "refresh_minutes": in.RefreshMinutes})
	a.reload(ctx, threat.SettingKey)
	a.getThreat(w, r, p)
}

// refreshThreat asks the downloading process for a refresh: in this process
// at once (Reload), in an enricher process within a minute.
func (a *App) refreshThreat(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	s, err := a.loadThreat(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	now := time.Now().UTC()
	s.RefreshRequestedAt = &now
	if err := a.st.PutSetting(ctx, threat.SettingKey, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.threat.refresh", "", nil)
	a.reload(ctx, threat.SettingKey)
	httpx.JSON(w, http.StatusAccepted, map[string]any{"requested_at": now})
}

// ---- cloud flow logs

func (a *App) loadFlowLogs(ctx context.Context) (flowlogs.Settings, error) {
	var s flowlogs.Settings
	_, err := a.st.Setting(ctx, flowlogs.SettingKey, &s)
	return s, err
}

func (a *App) getFlowLogs(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadFlowLogs(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	var general setup.General
	_, _ = a.st.Setting(r.Context(), setup.SettingGeneral, &general)
	base := strings.TrimRight(general.PublicURL, "/")
	out := map[string]any{"available": a.deps.FlowLogs != nil, "public_url": base}
	for _, name := range flowlogs.Providers {
		ps := s.Provider(name)
		// url: the absolute ingest URL for the cloud side ("" without a public URL in the general settings).
		u := ""
		if base != "" {
			u = base + "/api/ingest/flowlogs/" + name
		}
		out[name] = map[string]any{"enabled": ps.Enabled, "token_set": ps.TokenRef != "",
			"endpoint": "/api/ingest/flowlogs/" + name, "url": u}
	}
	httpx.JSON(w, http.StatusOK, out)
}

type flowLogsProviderInput struct {
	Enabled bool    `json:"enabled"`
	Token   *string `json:"token"` // nil = keep, "" = remove
}

type flowLogsInput struct {
	AWS   *flowLogsProviderInput `json:"aws"`
	Azure *flowLogsProviderInput `json:"azure"`
	GCP   *flowLogsProviderInput `json:"gcp"`
}

func (a *App) putFlowLogs(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in flowLogsInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	s, err := a.loadFlowLogs(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	detail := map[string]any{}
	inputs := map[string]*flowLogsProviderInput{flowlogs.AWS: in.AWS, flowlogs.Azure: in.Azure, flowlogs.GCP: in.GCP}
	for _, name := range flowlogs.Providers {
		pin := inputs[name]
		if pin == nil {
			continue
		}
		ps := s.Provider(name)
		if pin.Token != nil {
			tok := strings.TrimSpace(*pin.Token)
			if tok != "" && len(tok) < 16 {
				httpx.Error(w, http.StatusBadRequest, "flowlogs_invalid", name+": the token must have at least 16 characters")
				return
			}
			if tok == "" {
				if ps.TokenRef != "" {
					if err := a.deps.Vault.Put(ctx, flowlogs.SecretPath, map[string]string{name: ""}); err != nil {
						httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
						return
					}
				}
				ps.TokenRef = ""
			} else if ps.TokenRef, err = a.putSecret(ctx, flowlogs.SecretPath, name, tok); err != nil {
				httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
				return
			}
		}
		if pin.Enabled && ps.TokenRef == "" {
			httpx.Error(w, http.StatusBadRequest, "flowlogs_invalid", name+": a token is required to enable ingestion")
			return
		}
		ps.Enabled = pin.Enabled
		detail[name] = map[string]any{"enabled": ps.Enabled, "token_changed": pin.Token != nil}
	}
	if err := a.st.PutSetting(ctx, flowlogs.SettingKey, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.flowlogs", "", detail)
	a.reload(ctx, flowlogs.SettingKey)
	a.getFlowLogs(w, r, p)
}
