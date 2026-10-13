package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/gnmi"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
)

// ---- gNMI (routes in routing.go)

func (a *App) loadGNMI(ctx context.Context) (gnmi.Settings, error) {
	var s gnmi.Settings
	found, err := a.st.Setting(ctx, SettingGNMI, &s)
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

// gnmiProfileView is a profile without secret references.
type gnmiProfileView struct {
	gnmi.Profile
	PasswordSet bool `json:"password_set"`
	CASet       bool `json:"ca_set"`
	CertSet     bool `json:"cert_set"` // client certificate and key (mutual TLS)
}

func gnmiView(s gnmi.Settings) map[string]any {
	profiles := make([]gnmiProfileView, 0, len(s.Profiles))
	for _, p := range s.Profiles {
		v := gnmiProfileView{Profile: p, PasswordSet: p.PasswordRef != "", CASet: p.CARef != "", CertSet: p.CertRef != "" && p.KeyRef != ""}
		v.PasswordRef, v.CARef, v.CertRef, v.KeyRef = "", "", "", ""
		profiles = append(profiles, v)
	}
	return map[string]any{"enabled": s.Enabled, "poll_exporters": s.PollExporters, "devices": s.Devices,
		"interval_minutes": s.IntervalMinutes, "ttl_minutes": s.TTLMinutes, "timeout_seconds": s.TimeoutSeconds,
		"concurrency": s.Concurrency, "profiles": profiles, "encodings": gnmi.Encodings, "modes": gnmi.Modes}
}

func (a *App) getGNMI(w http.ResponseWriter, r *http.Request, p *Principal) {
	s, err := a.loadGNMI(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := gnmiView(s)
	if a.deps.Routing != nil {
		out["status"] = a.deps.Routing.GNMIStatus()
	}
	httpx.JSON(w, http.StatusOK, out)
}

// gnmiProfileInput: secrets are write-only (nil = keep, "" = remove).
type gnmiProfileInput struct {
	gnmi.Profile
	Password *string `json:"password"`
	CAPEM    *string `json:"ca_pem"`
	// Client certificate and key for mutual TLS: sent together (both ""
	// removes them).
	CertPEM *string `json:"cert_pem"`
	KeyPEM  *string `json:"key_pem"`
}

type gnmiInput struct {
	Enabled         bool               `json:"enabled"`
	PollExporters   bool               `json:"poll_exporters"`
	Devices         []string           `json:"devices"`
	IntervalMinutes int                `json:"interval_minutes"`
	TTLMinutes      int                `json:"ttl_minutes"`
	TimeoutSeconds  int                `json:"timeout_seconds"`
	Concurrency     int                `json:"concurrency"`
	Profiles        []gnmiProfileInput `json:"profiles"`
}

func validCA(pem string) bool { return x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) }

// checkClientCert validates a client certificate / key input pair.
func checkClientCert(in gnmiProfileInput) error {
	if in.CertPEM == nil && in.KeyPEM == nil {
		return nil
	}
	if in.CertPEM == nil || in.KeyPEM == nil || (strings.TrimSpace(*in.CertPEM) == "") != (strings.TrimSpace(*in.KeyPEM) == "") {
		return errors.New("the client certificate and its key go together")
	}
	if strings.TrimSpace(*in.CertPEM) == "" {
		return nil
	}
	if _, err := tls.X509KeyPair([]byte(strings.TrimSpace(*in.CertPEM)), []byte(strings.TrimSpace(*in.KeyPEM))); err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	return nil
}

// mergeGNMIProfile keeps the stored references of a profile and lists the
// secret changes; it fails when a needed secret would be missing.
func mergeGNMIProfile(in gnmiProfileInput, stored map[string]gnmi.Profile) (gnmi.Profile, []secretChange, error) {
	p := in.Profile
	old, existed := stored[p.ID]
	if !existed {
		p.ID = newProfileID()
	}
	p.PasswordRef, p.CARef, p.CertRef, p.KeyRef = old.PasswordRef, old.CARef, old.CertRef, old.KeyRef
	p.Username = strings.TrimSpace(p.Username)
	name := strings.TrimSpace(p.Name)
	var ch []secretChange
	set := func(v *string, what string, ref *string) bool {
		if v == nil {
			return *ref != ""
		}
		ch = append(ch, secretChange{path: gnmi.SecretPath(p.ID, what), value: strings.TrimSpace(*v), ref: ref})
		return strings.TrimSpace(*v) != ""
	}
	if p.Username != "" {
		if !set(in.Password, "password", &p.PasswordRef) {
			return p, nil, fmt.Errorf("profile %q: the password is required with a user name", name)
		}
	} else {
		ch = append(ch, secretChange{path: gnmi.SecretPath(p.ID, "password")})
		p.PasswordRef = ""
	}
	if p.TLS {
		if in.CAPEM != nil && strings.TrimSpace(*in.CAPEM) != "" && !validCA(*in.CAPEM) {
			return p, nil, fmt.Errorf("profile %q: the CA certificate is not valid PEM", name)
		}
		set(in.CAPEM, "ca", &p.CARef)
		if err := checkClientCert(in); err != nil {
			return p, nil, fmt.Errorf("profile %q: %w", name, err)
		}
		set(in.CertPEM, "cert", &p.CertRef)
		set(in.KeyPEM, "key", &p.KeyRef)
	} else {
		for _, what := range []string{"ca", "cert", "key"} {
			ch = append(ch, secretChange{path: gnmi.SecretPath(p.ID, what)})
		}
		p.CARef, p.CertRef, p.KeyRef = "", "", ""
	}
	return p, ch, nil
}

// gnmiSecrets are the OpenBao secrets of a profile.
var gnmiSecrets = []string{"password", "ca", "cert", "key"}

func (a *App) putGNMI(w http.ResponseWriter, r *http.Request, pr *Principal) {
	var in gnmiInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	cur, err := a.loadGNMI(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	stored := map[string]gnmi.Profile{}
	for _, p := range cur.Profiles {
		stored[p.ID] = p
	}
	s := gnmi.Settings{Enabled: in.Enabled, PollExporters: in.PollExporters, Devices: in.Devices, IntervalMinutes: in.IntervalMinutes,
		TTLMinutes: in.TTLMinutes, TimeoutSeconds: in.TimeoutSeconds, Concurrency: in.Concurrency}
	var changes []secretChange
	kept := map[string]bool{}
	for _, pi := range in.Profiles {
		p, ch, err := mergeGNMIProfile(pi, stored)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "gnmi_invalid", err.Error())
			return
		}
		kept[p.ID] = true
		s.Profiles = append(s.Profiles, p)
		changes = append(changes, ch...)
	}
	if s, err = s.Normalize(); err != nil {
		httpx.Error(w, http.StatusBadRequest, "gnmi_invalid", err.Error())
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
		ref := map[string]*string{"password": &p.PasswordRef, "ca": &p.CARef, "cert": &p.CertRef, "key": &p.KeyRef}[what]
		if c.value == "" {
			if c.ref != nil || *ref == "" { // removed, or not used by this profile
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
			for _, what := range gnmiSecrets {
				a.deleteSecret(ctx, gnmi.SecretPath(id, what))
			}
		}
	}
	if err := a.st.PutSetting(ctx, SettingGNMI, s); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, pr, "settings.gnmi", "", map[string]any{"enabled": s.Enabled, "profiles": len(s.Profiles), "devices": len(s.Devices)})
	a.reload(ctx, ReloadGNMI)
	a.getGNMI(w, r, pr)
}

type gnmiTestInput struct {
	Address string           `json:"address"`
	Profile gnmiProfileInput `json:"profile"`
}

func (a *App) testGNMI(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in gnmiTestInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(in.Address))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_address", "address must be an IP address")
		return
	}
	ctx := r.Context()
	cur, err := a.loadGNMI(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	var stored gnmi.Profile
	for _, sp := range cur.Profiles {
		if sp.ID == in.Profile.ID {
			stored = sp
		}
	}
	prof := in.Profile.Profile
	prof.PasswordRef, prof.CARef, prof.CertRef, prof.KeyRef = "", "", "", "" // secrets come from cred
	if prof.ID == "" {
		prof.ID = "test"
	}
	if strings.TrimSpace(prof.Name) == "" {
		prof.Name = "test"
	}
	tmp, err := gnmi.Settings{Profiles: []gnmi.Profile{prof}}.Normalize()
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	pick := func(v *string, ref string) (string, error) {
		if v != nil {
			return strings.TrimSpace(*v), nil
		}
		if ref == "" {
			return "", nil
		}
		return a.secret(ref)
	}
	var cred gnmi.Credentials
	if err = checkClientCert(in.Profile); err == nil {
		cred.Password, err = pick(in.Profile.Password, stored.PasswordRef)
	}
	if err == nil && prof.TLS {
		cred.CA, err = pick(in.Profile.CAPEM, stored.CARef)
		if err == nil {
			cred.Cert, err = pick(in.Profile.CertPEM, stored.CertRef)
		}
		if err == nil {
			cred.Key, err = pick(in.Profile.KeyPEM, stored.KeyRef)
		}
	}
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	cur.TimeoutSeconds = max(cur.TimeoutSeconds, 1)
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ifs, err := gnmi.Get(tctx, addr, tmp.Profiles[0], cred, cur)
	if err != nil {
		httpx.JSON(w, http.StatusOK, setup.CheckResult{Error: err.Error()})
		return
	}
	type row struct {
		Index uint32 `json:"index"`
		gnmi.Interface
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
