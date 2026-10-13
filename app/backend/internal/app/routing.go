package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/bmp"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/snmp"
)

// Settings keys and reload topics of the gNMI and SNMP pollers and the BMP
// receiver.
const (
	SettingGNMI = "gnmi"
	SettingSNMP = "snmp"
	SettingBMP  = "bmp"
	ReloadGNMI  = "gnmi"
	ReloadSNMP  = "snmp"
	ReloadBMP   = "bmp"
)

// RoutingService is the gNMI and SNMP pollers and the BMP receiver of this
// process (wiring.Routing). Each method returns nil / false when the
// component does not run here (it runs with the enricher).
type RoutingService interface {
	GNMIStatus() any
	SNMPStatus() any
	BMPStatus() any
	// BMPLookup finds the route of addr in the VPN table of rd (0: global).
	BMPLookup(rd uint64, addr netip.Addr) (any, bool)
}

func (a *App) routingRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("GET /api/settings/gnmi", a.guard(perms(access.GNMIView), a.getGNMI))
	h("PUT /api/settings/gnmi", a.guard(perms(access.GNMIEdit), a.putGNMI))
	h("POST /api/settings/gnmi/test", a.guard(perms(access.GNMIEdit), a.testGNMI))
	h("GET /api/settings/snmp", a.guard(perms(access.SNMPView), a.getSNMP))
	h("PUT /api/settings/snmp", a.guard(perms(access.SNMPEdit), a.putSNMP))
	h("POST /api/settings/snmp/test", a.guard(perms(access.SNMPEdit), a.testSNMP))
	h("GET /api/settings/bmp", a.guard(perms(access.BMPView), a.getBMP))
	h("PUT /api/settings/bmp", a.guard(perms(access.BMPEdit), a.putBMP))
	h("GET /api/bmp/lookup", a.guard(perms(access.BMPView), a.bmpLookup))
}

// ---- SNMP

func (a *App) loadSNMP(ctx context.Context) (snmp.Settings, error) {
	var s snmp.Settings
	found, err := a.st.Setting(ctx, SettingSNMP, &s)
	if err != nil {
		return s, err
	}
	if !found {
		s.PollExporters = true
	}
	n, err := s.Normalize()
	if err != nil {
		return s, nil // shown as stored; PUT validates
	}
	return n, nil
}

// snmpProfileView is a profile without secret references.
type snmpProfileView struct {
	snmp.Profile
	CommunitySet bool `json:"community_set"`
	AuthSet      bool `json:"auth_password_set"`
	PrivSet      bool `json:"priv_password_set"`
}

func snmpView(s snmp.Settings) map[string]any {
	profiles := make([]snmpProfileView, 0, len(s.Profiles))
	for _, p := range s.Profiles {
		v := snmpProfileView{Profile: p, CommunitySet: p.CommunityRef != "", AuthSet: p.AuthRef != "", PrivSet: p.PrivRef != ""}
		v.CommunityRef, v.AuthRef, v.PrivRef = "", "", ""
		profiles = append(profiles, v)
	}
	return map[string]any{"enabled": s.Enabled, "poll_exporters": s.PollExporters, "devices": s.Devices,
		"interval_minutes": s.IntervalMinutes, "ttl_minutes": s.TTLMinutes, "timeout_seconds": s.TimeoutSeconds,
		"retries": s.Retries, "concurrency": s.Concurrency, "profiles": profiles,
		"auth_protocols": snmp.AuthProtocols, "priv_protocols": snmp.PrivProtocols}
}

func (a *App) getSNMP(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadSNMP(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := snmpView(s)
	if a.deps.Routing != nil {
		out["status"] = a.deps.Routing.SNMPStatus()
	}
	httpx.JSON(w, http.StatusOK, out)
}

// snmpProfileInput: secrets are write-only (nil = keep, "" = remove).
type snmpProfileInput struct {
	snmp.Profile
	Community    *string `json:"community"`
	AuthPassword *string `json:"auth_password"`
	PrivPassword *string `json:"priv_password"`
}

type snmpInput struct {
	Enabled         bool               `json:"enabled"`
	PollExporters   bool               `json:"poll_exporters"`
	Devices         []string           `json:"devices"`
	IntervalMinutes int                `json:"interval_minutes"`
	TTLMinutes      int                `json:"ttl_minutes"`
	TimeoutSeconds  int                `json:"timeout_seconds"`
	Retries         int                `json:"retries"`
	Concurrency     int                `json:"concurrency"`
	Profiles        []snmpProfileInput `json:"profiles"`
}

func newProfileID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "p" + hex.EncodeToString(b)
}

type secretChange struct {
	path, value string
	ref         *string
}

// mergeProfile keeps the stored references of a profile and lists the secret
// changes; it fails when a needed secret would be missing.
func mergeProfile(in snmpProfileInput, stored map[string]snmp.Profile) (snmp.Profile, []secretChange, error) {
	p := in.Profile
	old, existed := stored[p.ID]
	if !existed {
		p.ID = newProfileID()
	}
	p.CommunityRef, p.AuthRef, p.PrivRef = old.CommunityRef, old.AuthRef, old.PrivRef
	var ch []secretChange
	set := func(v *string, what string, ref *string) bool {
		if v == nil {
			return *ref != ""
		}
		ch = append(ch, secretChange{path: snmp.SecretPath(p.ID, what), value: strings.TrimSpace(*v), ref: ref})
		return strings.TrimSpace(*v) != ""
	}
	name := strings.TrimSpace(p.Name)
	switch p.Version {
	case snmp.Version2c:
		if !set(in.Community, "community", &p.CommunityRef) {
			return p, nil, fmt.Errorf("profile %q: the community is required", name)
		}
		p.Username, p.SecurityLevel, p.AuthProtocol, p.PrivProtocol, p.ContextName = "", "", "", "", ""
		for _, w := range []string{"auth", "priv"} {
			ch = append(ch, secretChange{path: snmp.SecretPath(p.ID, w)})
		}
		p.AuthRef, p.PrivRef = "", ""
	case snmp.Version3:
		level := p.SecurityLevel
		if level == "" {
			level = snmp.AuthPriv
		}
		if level != snmp.NoAuthNoPriv && !set(in.AuthPassword, "auth", &p.AuthRef) {
			return p, nil, fmt.Errorf("profile %q: the authentication password is required", name)
		}
		if level == snmp.AuthPriv && !set(in.PrivPassword, "priv", &p.PrivRef) {
			return p, nil, fmt.Errorf("profile %q: the privacy password is required", name)
		}
		ch = append(ch, secretChange{path: snmp.SecretPath(p.ID, "community")})
		p.CommunityRef = ""
		if level != snmp.AuthPriv {
			ch = append(ch, secretChange{path: snmp.SecretPath(p.ID, "priv")})
			p.PrivRef = ""
		}
		if level == snmp.NoAuthNoPriv {
			ch = append(ch, secretChange{path: snmp.SecretPath(p.ID, "auth")})
			p.AuthRef = ""
		}
	}
	return p, ch, nil
}

func (a *App) putSNMP(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var in snmpInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	cur, err := a.loadSNMP(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	stored := map[string]snmp.Profile{}
	for _, p := range cur.Profiles {
		stored[p.ID] = p
	}
	s := snmp.Settings{Enabled: in.Enabled, PollExporters: in.PollExporters, Devices: in.Devices, IntervalMinutes: in.IntervalMinutes,
		TTLMinutes: in.TTLMinutes, TimeoutSeconds: in.TimeoutSeconds, Retries: in.Retries, Concurrency: in.Concurrency}
	var changes []secretChange
	kept := map[string]bool{}
	for _, pi := range in.Profiles {
		p, ch, err := mergeProfile(pi, stored)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "snmp_invalid", err.Error())
			return
		}
		kept[p.ID] = true
		s.Profiles = append(s.Profiles, p)
		changes = append(changes, ch...)
	}
	if s, err = s.Normalize(); err != nil {
		httpx.Error(w, http.StatusBadRequest, "snmp_invalid", err.Error())
		return
	}
	// Index of each profile, to update its references after writing secrets.
	idx := map[string]int{}
	for i, p := range s.Profiles {
		idx[p.ID] = i
	}
	for _, c := range changes {
		id := strings.Split(c.path, "/")[1]
		what := c.path[strings.LastIndex(c.path, "/")+1:]
		p := &s.Profiles[idx[id]]
		ref := map[string]*string{"community": &p.CommunityRef, "auth": &p.AuthRef, "priv": &p.PrivRef}[what]
		if c.value == "" {
			if c.ref != nil || *ref == "" { // removed, or not used by this version
				a.deleteSecret(ctx, c.path)
				*ref = ""
			}
			continue
		}
		if *ref, err = a.putSecret(ctx, c.path, "value", c.value); err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
	}
	for id := range stored {
		if !kept[id] {
			for _, what := range []string{"community", "auth", "priv"} {
				a.deleteSecret(ctx, snmp.SecretPath(id, what))
			}
		}
	}
	if err := a.st.PutSetting(ctx, SettingSNMP, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, pr, "settings.snmp", "", map[string]any{"enabled": s.Enabled, "profiles": len(s.Profiles), "devices": len(s.Devices)})
	a.reload(ctx, ReloadSNMP)
	a.getSNMP(w, r, pr)
}

type snmpTestInput struct {
	Address string           `json:"address"`
	Profile snmpProfileInput `json:"profile"`
}

func (a *App) testSNMP(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in snmpTestInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(in.Address))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_address", "address must be an IP address")
		return
	}
	ctx := r.Context()
	cur, err := a.loadSNMP(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	var stored snmp.Profile
	for _, sp := range cur.Profiles {
		if sp.ID == in.Profile.ID {
			stored = sp
		}
	}
	prof := in.Profile.Profile
	if prof.ID == "" {
		prof.ID = "test"
	}
	tmp := snmp.Settings{Profiles: []snmp.Profile{prof}}
	if prof.Version == snmp.Version3 && prof.SecurityLevel == "" {
		tmp.Profiles[0].SecurityLevel = snmp.AuthPriv
	}
	if tmp.Profiles[0].Name == "" {
		tmp.Profiles[0].Name = "test"
	}
	tmp, err = tmp.Normalize()
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	cred := snmp.Credentials{}
	pick := func(v *string, ref string) (string, error) {
		if v != nil {
			return strings.TrimSpace(*v), nil
		}
		return a.secret(ref)
	}
	if cred.Community, err = pick(in.Profile.Community, stored.CommunityRef); err == nil {
		if cred.Auth, err = pick(in.Profile.AuthPassword, stored.AuthRef); err == nil {
			cred.Priv, err = pick(in.Profile.PrivPassword, stored.PrivRef)
		}
	}
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	cur.TimeoutSeconds, cur.Retries = max(cur.TimeoutSeconds, 1), min(cur.Retries, 1)
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ifs, err := snmp.Walk(tctx, addr, tmp.Profiles[0], cred, cur)
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	type row struct {
		Index uint32 `json:"index"`
		snmp.Interface
	}
	rows := make([]row, 0, len(ifs))
	for i, it := range ifs {
		rows = append(rows, row{i, it})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Index < rows[j].Index })
	if len(rows) > 50 {
		rows = rows[:50]
	}
	httpx.JSON(w, http.StatusOK, setup.CheckResult{OK: true, Details: map[string]any{"interfaces": len(ifs), "sample": rows}})
}

// ---- BMP

func (a *App) loadBMP(ctx context.Context) (bmp.Settings, error) {
	var s bmp.Settings
	if _, err := a.st.Setting(ctx, SettingBMP, &s); err != nil {
		return s, err
	}
	if n, err := s.Normalize(); err == nil {
		s = n
	}
	return s, nil
}

func (a *App) getBMP(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadBMP(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := map[string]any{"enabled": s.Enabled, "policy": s.Policy, "routers": s.Routers, "as_providers": s.ASProviders}
	if a.deps.Routing != nil {
		out["status"] = a.deps.Routing.BMPStatus()
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) putBMP(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in bmp.Settings
	if !httpx.Decode(w, r, &in) {
		return
	}
	s, err := in.Normalize()
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bmp_invalid", err.Error())
		return
	}
	ctx := r.Context()
	if err := a.st.PutSetting(ctx, SettingBMP, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.bmp", "", map[string]any{"enabled": s.Enabled, "policy": s.Policy, "routers": len(s.Routers)})
	a.reload(ctx, ReloadBMP)
	a.getBMP(w, r, p)
}

func (a *App) bmpLookup(w http.ResponseWriter, r *http.Request, p *Principal) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("address")))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_address", "address must be an IP address")
		return
	}
	if a.deps.Routing == nil || a.deps.Routing.BMPStatus() == nil {
		notImplemented(w, "the BMP routing table (it runs with the enricher)")
		return
	}
	var rd uint64
	if v := strings.TrimSpace(r.URL.Query().Get("rd")); v != "" {
		if rd, err = bmp.ParseRD(v); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_rd", err.Error())
			return
		}
	}
	route, ok := a.deps.Routing.BMPLookup(rd, addr)
	if !ok {
		httpx.Error(w, http.StatusNotFound, "no_route", "no route covers "+addr.String())
		return
	}
	httpx.JSON(w, http.StatusOK, route)
}
