// Package setup is the first-run wizard backend (docs/api.md, the setup
// wizard section). It runs while flow.json is missing: it checks the
// setup code (written to the log and to <data>/setup-token, attempts are
// rate-limited), tests every step, and on completion writes the secrets to
// OpenBao, migrates PostgreSQL and ClickHouse, stores the settings, creates
// the first administrator, writes flow.json and hands over to the
// application without a restart.
package setup

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

const (
	// TokenHeader may carry the setup code instead of the setup_code field.
	TokenHeader = "X-Setup-Token"

	maxFailures = 5
	lockout     = time.Minute
)

// Settings keys written by the wizard (table settings).
const (
	SettingGeneral        = "general"
	SettingCollector      = "collector"
	SettingPasswordPolicy = "password_policy"
	SettingUmbrella       = "umbrella"
	SettingGeoIP          = "geoip"
)

// OpenBao paths of the secrets the wizard writes (mount "flow").
const (
	SecretPostgres   = "postgres"     // #password
	SecretClickHouse = "clickhouse"   // #password
	SecretNATS       = "nats"         // #token
	SecretInventory  = "inventory-db" // #token
	SecretUmbrella   = "umbrella"     // #token
)

var UsernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$`)

type Options struct {
	DataDir        string
	Token          string // the setup code
	Version        string
	Commit         string
	BuiltAt        string
	Web            http.Handler
	TrustedProxies []netip.Prefix
	Defaults       Defaults
}

// Result is handed to the done callback after a successful setup; the store
// is open and migrated.
type Result struct {
	Config config.File
	Vault  *secrets.Client
	Store  *store.Store
}

type Module struct {
	opt  Options
	done func(Result)

	mu       sync.Mutex
	finished bool

	lmu      sync.Mutex
	failures int
	until    time.Time

	vmu   sync.Mutex
	vault *secrets.Client // OpenBao of the defaults, to resolve default secret references
}

func New(opt Options, done func(Result)) *Module {
	if opt.Web == nil {
		opt.Web = httpx.Web("")
	}
	return &Module{opt: opt, done: done}
}

// Handler serves the wizard API, /healthz, /metrics, /api/version and the web UI. Other
// /api/ paths answer 503 setup_required.
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, http.StatusOK, map[string]string{"version": m.opt.Version, "commit": m.opt.Commit, "built_at": m.opt.BuiltAt})
	})
	mux.HandleFunc("GET /api/setup", func(w http.ResponseWriter, r *http.Request) {
		if m.isFinished() {
			httpx.Error(w, http.StatusNotFound, "not_found", "setup is completed")
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"required": true, "defaults": m.opt.Defaults.view()})
	})
	mux.HandleFunc("POST /api/setup/check-code", m.checkCodeHandler)
	mux.HandleFunc("POST /api/setup/test/{step}", m.testStep)
	mux.HandleFunc("POST /api/setup", m.complete)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusServiceUnavailable, "setup_required", "finish the setup wizard first")
	})
	mux.Handle("/", m.opt.Web)
	return httpx.Secure(mux)
}

func (m *Module) isFinished() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.finished
}

// checkCode verifies the setup code with a lockout after repeated failures;
// on failure it writes the reply and returns false.
func (m *Module) checkCode(w http.ResponseWriter, r *http.Request, code string) bool {
	if m.isFinished() {
		httpx.Error(w, http.StatusNotFound, "not_found", "setup is completed")
		return false
	}
	m.lmu.Lock()
	locked := time.Now().Before(m.until)
	m.lmu.Unlock()
	if locked {
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "too many wrong setup codes, wait a minute")
		return false
	}
	if code == "" {
		code = r.Header.Get(TokenHeader)
	}
	if m.opt.Token == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(m.opt.Token)) != 1 {
		m.lmu.Lock()
		m.failures++
		if m.failures >= maxFailures {
			m.failures, m.until = 0, time.Now().Add(lockout)
		}
		m.lmu.Unlock()
		slog.Warn("setup: wrong setup code", "remote", httpx.ClientIP(r, m.opt.TrustedProxies))
		httpx.Error(w, http.StatusUnauthorized, "setup_code_invalid", "the setup code is wrong: see the server log or the setup-token file")
		return false
	}
	m.lmu.Lock()
	m.failures = 0
	m.lmu.Unlock()
	return true
}

func (m *Module) checkCodeHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupCode string `json:"setup_code"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if m.checkCode(w, r, in.SetupCode) {
		httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ---- inputs

// OpenBaoInput: credentials come from the request or, when it has none,
// from the defaults (AppRole files of the Docker stack). File paths cannot be
// set through the API.
type OpenBaoInput struct {
	Addr       string `json:"addr"`
	Mount      string `json:"mount"`
	Namespace  string `json:"namespace,omitempty"`
	Auth       string `json:"auth"`
	Token      string `json:"token,omitempty"`
	RoleID     string `json:"role_id,omitempty"`
	SecretID   string `json:"secret_id,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
	SkipVerify bool   `json:"skip_verify,omitempty"`
}

type PostgresInput struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	SSLMode        string `json:"sslmode"`
	AttachExisting bool   `json:"attach_existing,omitempty"`
}

type ClickHouseInput struct {
	Addr       string            `json:"addr"`
	Database   string            `json:"database"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	Secure     bool              `json:"secure"`
	SkipVerify bool              `json:"skip_verify,omitempty"`
	Retention  *config.Retention `json:"retention,omitempty"`
}

type NATSInput struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// Collector is where flows are received (settings key "collector").
type Collector struct {
	NetFlowAddr         string `json:"netflow_addr"`
	SFlowAddr           string `json:"sflow_addr"`
	DefaultSamplingRate uint64 `json:"default_sampling_rate"`
}

type InventoryInput struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Token    string `json:"token"`
	Interval string `json:"interval"`
}

type UmbrellaInput struct {
	Enabled   bool   `json:"enabled"`
	IngestURL string `json:"ingest_url"`
	Token     string `json:"token"`
}

type GeoIPInput struct {
	Databases []string `json:"databases"`
}

type AdminInput struct {
	Username       string               `json:"username"`
	Name           string               `json:"name"`
	Email          string               `json:"email"`
	Password       string               `json:"password"`
	PasswordPolicy *auth.PasswordPolicy `json:"password_policy,omitempty"`
}

// Input is the body of POST /api/setup.
type Input struct {
	SetupCode  string           `json:"setup_code"`
	Language   string           `json:"language"`
	Theme      string           `json:"theme"`
	Timezone   string           `json:"timezone"`
	PublicURL  string           `json:"public_url"`
	OpenBao    *OpenBaoInput    `json:"openbao"`
	Postgres   *PostgresInput   `json:"postgres"`
	ClickHouse *ClickHouseInput `json:"clickhouse"`
	NATS       *NATSInput       `json:"nats"`
	Collector  *Collector       `json:"collector"`
	Inventory  *InventoryInput  `json:"inventory"`
	Umbrella   *UmbrellaInput   `json:"umbrella"`
	GeoIP      *GeoIPInput      `json:"geoip"`
	Admin      *AdminInput      `json:"admin"`
	// PasswordPolicy for local users (the console sends it here; the
	// admin.password_policy field is also accepted).
	PasswordPolicy *auth.PasswordPolicy `json:"password_policy,omitempty"`
	// Retention of flows; the console sends it here, clickhouse.retention is
	// also accepted (and wins).
	Retention *config.Retention `json:"retention,omitempty"`
}

// General settings (settings key "general").
type General struct {
	Language  string `json:"language"`
	Theme     string `json:"theme"`
	Timezone  string `json:"timezone"`
	PublicURL string `json:"public_url"`
}

// UmbrellaSettings (settings key "umbrella"); TokenRef is an openbao:// reference.
type UmbrellaSettings struct {
	Enabled   bool   `json:"enabled"`
	IngestURL string `json:"ingest_url"`
	TokenRef  string `json:"token_ref,omitempty"`
}

// GeoIPSettings (settings key "geoip").
type GeoIPSettings struct {
	Databases []string `json:"databases"`
}

type stepError struct {
	status int
	code   string
	err    error
}

func (e *stepError) Error() string {
	if e.err == nil {
		return e.code
	}
	return e.code + ": " + e.err.Error()
}

func fail(status int, code string, err error) *stepError {
	return &stepError{status: status, code: code, err: err}
}

// ---- merging with the defaults

func (m *Module) openbaoConfig(in *OpenBaoInput) config.OpenBao {
	o := m.opt.Defaults.OpenBao
	if in == nil {
		return o
	}
	if a := strings.TrimRight(strings.TrimSpace(in.Addr), "/"); a != "" && a != strings.TrimRight(o.Addr, "/") {
		o = config.OpenBao{Addr: a, Mount: o.Mount} // another server: the default credentials do not apply
	}
	if in.Mount != "" {
		o.Mount = in.Mount
	}
	o.Namespace, o.CACert, o.SkipVerify = in.Namespace, in.CACert, in.SkipVerify
	switch {
	case in.Token != "":
		o = config.OpenBao{Addr: o.Addr, Mount: o.Mount, Namespace: o.Namespace, CACert: o.CACert, SkipVerify: o.SkipVerify,
			Auth: config.AuthToken, Token: in.Token}
	case in.RoleID != "" || in.SecretID != "":
		o = config.OpenBao{Addr: o.Addr, Mount: o.Mount, Namespace: o.Namespace, CACert: o.CACert, SkipVerify: o.SkipVerify,
			Auth: config.AuthAppRole, RoleID: in.RoleID, SecretID: in.SecretID}
	case in.Auth != "" && in.Auth != o.Auth:
		o.Auth, o.Token, o.TokenFile, o.RoleIDFile, o.SecretIDFile = in.Auth, "", "", "", ""
	}
	return o
}

// defaultVault is the OpenBao of the defaults, used by step checks to
// resolve default secret references.
func (m *Module) defaultVault(ctx context.Context) *secrets.Client {
	m.vmu.Lock()
	defer m.vmu.Unlock()
	if m.vault != nil || !m.opt.Defaults.OpenBao.Enabled() {
		return m.vault
	}
	o, err := m.opt.Defaults.OpenBao.Normalize()
	if err != nil {
		return nil
	}
	if c, err := o.Client(); err == nil && c.Verify(ctx).OK {
		m.vault = c
	}
	return m.vault
}

// secretOr returns the typed value, else resolves the default reference.
func secretOr(vault *secrets.Client, typed, defRef string) (string, error) {
	if typed != "" || defRef == "" {
		return typed, nil
	}
	if vault == nil {
		return "", errors.New("OpenBao is needed to read " + defRef)
	}
	return vault.Resolve(defRef)
}

// postgresConfig merges the input with the defaults; it returns the typed
// password and the default password reference separately.
func (m *Module) postgresConfig(in *PostgresInput) (config.Postgres, string, string, error) {
	p := m.opt.Defaults.Postgres
	typed := ""
	if in != nil {
		if in.Host != "" {
			p.Host = in.Host
		}
		if in.Port != 0 {
			p.Port = in.Port
		}
		if in.Database != "" {
			p.Database = in.Database
		}
		if in.Username != "" {
			p.Username = in.Username
		}
		if in.SSLMode != "" {
			p.SSLMode = in.SSLMode
		}
		typed = in.Password
	}
	defRef := p.Password
	p.Password = ""
	p, err := p.Normalize()
	return p, typed, defRef, err
}

func (m *Module) clickhouseConfig(in *ClickHouseInput) (config.ClickHouse, string, string, error) {
	c := m.opt.Defaults.ClickHouse
	typed := ""
	if in != nil {
		if in.Addr != "" {
			c.Addr = in.Addr
		}
		if in.Database != "" {
			c.Database = in.Database
		}
		if in.Username != "" {
			c.Username = in.Username
		}
		c.Secure = c.Secure || in.Secure
		c.SkipVerify = in.SkipVerify
		if in.Retention != nil {
			c.Retention = *in.Retention
		}
		typed = in.Password
	}
	defRef := c.Password
	c.Password = ""
	c, err := c.Normalize()
	return c, typed, defRef, err
}

// ---- step checks

var steps = map[string]bool{"openbao": true, "postgres": true, "clickhouse": true, "nats": true, "inventory": true, "umbrella": true, "geoip": true}

// decodeStep reads {setup_code, ...step fields} into the code and v.
func decodeStep(w http.ResponseWriter, r *http.Request, v any) (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, httpx.MaxBody))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "unreadable body")
		return "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return "", false
	}
	var code string
	_ = json.Unmarshal(fields["setup_code"], &code)
	delete(fields, "setup_code")
	rest, _ := json.Marshal(fields)
	dec := json.NewDecoder(strings.NewReader(string(rest)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return "", false
	}
	return code, true
}

func (m *Module) testStep(w http.ResponseWriter, r *http.Request) {
	step := r.PathValue("step")
	if !steps[step] {
		httpx.Error(w, http.StatusNotFound, "not_found", "unknown step "+step)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var res CheckResult
	switch step {
	case "openbao":
		var in OpenBaoInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		_, res = CheckOpenBao(ctx, m.openbaoConfig(&in))
	case "postgres":
		var in PostgresInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		p, typed, defRef, err := m.postgresConfig(&in)
		pw := typed
		if err == nil && typed == "" {
			pw, err = secretOr(m.defaultVault(ctx), "", defRef)
		}
		if err != nil {
			res = failed(err)
			break
		}
		res = CheckPostgres(ctx, p.BuildDSN(pw))
	case "clickhouse":
		var in ClickHouseInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		c, typed, defRef, err := m.clickhouseConfig(&in)
		pw := typed
		if err == nil && typed == "" {
			pw, err = secretOr(m.defaultVault(ctx), "", defRef)
		}
		if err != nil {
			res = failed(err)
			break
		}
		res = CheckClickHouse(ctx, c, pw)
	case "nats":
		var in NATSInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		tok, err := secretOr(m.defaultVault(ctx), in.Token, m.natsDefaultRef(in.URL))
		if err != nil {
			res = failed(err)
			break
		}
		res = CheckNATS(ctx, in.URL, tok)
	case "inventory":
		var in InventoryInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		res = CheckInventory(ctx, in.URL, in.Token)
	case "umbrella":
		var in UmbrellaInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		res = CheckUmbrella(ctx, in.IngestURL, in.Token)
	case "geoip":
		var in GeoIPInput
		code, ok := decodeStep(w, r, &in)
		if !ok || !m.checkCode(w, r, code) {
			return
		}
		res = CheckGeoIP(in.Databases)
	}
	httpx.JSON(w, http.StatusOK, res)
}

// natsDefaultRef: the default token applies only to the default URL.
func (m *Module) natsDefaultRef(u string) string {
	if strings.TrimSpace(u) == m.opt.Defaults.NATS.URL {
		return m.opt.Defaults.NATS.Token
	}
	return ""
}

// ---- completion

func (m *Module) complete(w http.ResponseWriter, r *http.Request) {
	var in Input
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !m.checkCode(w, r, in.SetupCode) {
		return
	}
	if in.Retention != nil && in.ClickHouse != nil && in.ClickHouse.Retention == nil {
		in.ClickHouse.Retention = in.Retention
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.finished {
		httpx.Error(w, http.StatusNotFound, "not_found", "setup is completed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := m.apply(ctx, in, httpx.ClientIP(r, m.opt.TrustedProxies))
	if err != nil {
		var se *stepError
		if !errors.As(err, &se) {
			se = fail(http.StatusInternalServerError, "internal", err)
		}
		slog.Warn("setup: not completed", "step", se.code, "err", se.err)
		msg := se.code
		if se.err != nil {
			msg = se.err.Error()
		}
		httpx.Error(w, se.status, se.code, msg)
		return
	}
	m.finished = true
	_ = os.Remove(filepath.Join(m.opt.DataDir, config.SetupTokenFile))
	slog.Info("setup completed", "openbao", res.Config.OpenBao.Addr, "clickhouse", res.Config.ClickHouse.Addr)
	if m.done != nil {
		m.done(res)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func checkGeneral(in Input, d Defaults) (General, error) {
	g := General{Language: firstNonEmpty(in.Language, d.Language, "ru"), Theme: firstNonEmpty(in.Theme, d.Theme, "system"),
		Timezone: firstNonEmpty(in.Timezone, d.Timezone, "UTC"), PublicURL: strings.TrimRight(firstNonEmpty(in.PublicURL, d.PublicURL), "/")}
	if g.Language != "ru" && g.Language != "en" {
		return g, errors.New("language must be ru or en")
	}
	if g.Theme != "light" && g.Theme != "dark" && g.Theme != "system" {
		return g, errors.New("theme must be light, dark or system")
	}
	if _, err := time.LoadLocation(g.Timezone); err != nil {
		return g, fmt.Errorf("unknown time zone %q", g.Timezone)
	}
	if g.PublicURL != "" {
		u, err := url.Parse(g.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return g, errors.New("the Flow address must look like https://flow.example")
		}
	}
	return g, nil
}

func (m *Module) apply(ctx context.Context, in Input, remote string) (Result, error) {
	var res Result
	d := m.opt.Defaults
	bad := func(code string, err error) error { return fail(http.StatusBadRequest, code, err) }

	general, err := checkGeneral(in, d)
	if err != nil {
		return res, bad("general_invalid", err)
	}

	// OpenBao: required, every secret goes there.
	ob, err := m.openbaoConfig(in.OpenBao).Normalize()
	if err != nil {
		return res, bad("openbao_invalid", err)
	}
	vault, chk := CheckOpenBao(ctx, ob)
	if !chk.OK {
		return res, bad("openbao_unavailable", errors.New(chk.Error))
	}

	// PostgreSQL
	pg, pgTyped, pgDefRef, err := m.postgresConfig(in.Postgres)
	if err != nil {
		return res, bad("postgres_invalid", err)
	}
	pgPassword, err := secretOr(vault, pgTyped, pgDefRef)
	if err != nil {
		return res, bad("postgres_invalid", err)
	}
	st, err := store.Open(ctx, pg.BuildDSN(pgPassword))
	if err != nil {
		return res, bad("postgres_unavailable", err)
	}
	keep := false
	defer func() {
		if !keep {
			st.Close()
		}
	}()
	pgd, err := postgresDetails(ctx, st)
	if err != nil {
		return res, bad("postgres_unavailable", err)
	}
	attach := in.Postgres != nil && in.Postgres.AttachExisting
	if pgd.HasState && !attach {
		return res, fail(http.StatusConflict, "postgres_has_state",
			fmt.Errorf("the database already has Flow data (%d users): attach to it or choose an empty database", pgd.Users))
	}

	// ClickHouse
	ch, chTyped, chDefRef, err := m.clickhouseConfig(in.ClickHouse)
	if err != nil {
		return res, bad("clickhouse_invalid", err)
	}
	chPassword, err := secretOr(vault, chTyped, chDefRef)
	if err != nil {
		return res, bad("clickhouse_invalid", err)
	}
	chConn, err := ch.Open(ctx, chPassword, "")
	if err != nil {
		return res, bad("clickhouse_unavailable", err)
	}
	defer chConn.Close()

	// NATS
	nc := d.NATS
	natsTyped := ""
	if in.NATS != nil {
		nc = config.NATS{URL: strings.TrimSpace(in.NATS.URL), Token: m.natsDefaultRef(in.NATS.URL)}
		natsTyped = in.NATS.Token
	}
	natsToken, err := secretOr(vault, natsTyped, nc.Token)
	if err != nil {
		return res, bad("nats_invalid", err)
	}
	if c := CheckNATS(ctx, nc.URL, natsToken); !c.OK {
		return res, bad("nats_unavailable", errors.New(c.Error))
	}

	// collector
	col := d.Collector
	if in.Collector != nil {
		col.NetFlowAddr = firstNonEmpty(in.Collector.NetFlowAddr, col.NetFlowAddr)
		col.SFlowAddr = firstNonEmpty(in.Collector.SFlowAddr, col.SFlowAddr)
	}
	col.NetFlowAddr = firstNonEmpty(col.NetFlowAddr, ":2055")
	col.SFlowAddr = firstNonEmpty(col.SFlowAddr, ":6343")
	if in.Collector != nil {
		if in.Collector.DefaultSamplingRate > 0 {
			col.DefaultSamplingRate = in.Collector.DefaultSamplingRate
		}
	}
	if col.DefaultSamplingRate == 0 {
		col.DefaultSamplingRate = 1
	}
	for _, a := range []string{col.NetFlowAddr, col.SFlowAddr} {
		if err := checkUDPAddr(a); err != nil {
			return res, bad("collector_invalid", err)
		}
	}

	// optional integrations
	inv := InventoryInput{}
	var invInterval time.Duration = 15 * time.Minute
	if in.Inventory != nil && in.Inventory.Enabled {
		inv = *in.Inventory
		if inv.Interval != "" {
			if invInterval, err = time.ParseDuration(inv.Interval); err != nil || invInterval < time.Minute {
				return res, bad("inventory_invalid", errors.New("interval must be a duration of at least 1m, like 15m"))
			}
		}
		if c := CheckInventory(ctx, inv.URL, inv.Token); !c.OK {
			return res, bad("inventory_unavailable", errors.New(c.Error))
		}
	}
	umb := UmbrellaInput{}
	if in.Umbrella != nil && in.Umbrella.Enabled {
		umb = *in.Umbrella
		if c := CheckUmbrella(ctx, umb.IngestURL, umb.Token); !c.OK {
			return res, bad("umbrella_unavailable", errors.New(c.Error))
		}
	}
	geo := GeoIPSettings{Databases: d.GeoIP}
	if in.GeoIP != nil {
		geo.Databases = in.GeoIP.Databases
	}
	geo.Databases = nonNil(geo.Databases)
	if len(geo.Databases) > 0 {
		if c := CheckGeoIP(geo.Databases); !c.OK {
			return res, bad("geoip_unavailable", errors.New(c.Error))
		}
	}

	// administrator: required for a new database, optional when attaching
	policy := auth.DefaultPolicy
	if attach {
		_, _ = st.Setting(ctx, SettingPasswordPolicy, &policy)
	}
	if in.PasswordPolicy != nil {
		policy = *in.PasswordPolicy
	}
	var admin *AdminInput
	if in.Admin != nil && (in.Admin.Username != "" || in.Admin.Password != "") {
		admin = in.Admin
		admin.Username = strings.TrimSpace(admin.Username)
		if admin.PasswordPolicy != nil {
			policy = *admin.PasswordPolicy
		}
		policy = policy.Normalize()
		if !UsernameRe.MatchString(admin.Username) {
			return res, bad("admin_invalid", errors.New("user name: 2-64 letters, digits, . _ @ -"))
		}
		if err := policy.Validate(admin.Password, admin.Username); err != nil {
			return res, bad("weak_password", err)
		}
	} else if !pgd.HasState {
		return res, bad("admin_required", errors.New("the first administrator is required"))
	}

	// ---- everything checked: write.
	if err := st.Migrate(ctx); err != nil {
		return res, fail(http.StatusBadGateway, "postgres_migrate_failed", err)
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		return res, fail(http.StatusBadGateway, "postgres_write_failed", err)
	}
	if err := chstore.Migrate(ctx, chConn, chstore.Config{Database: ch.Database, RawTTL: config.Days(ch.Retention.RawDays),
		TTL1m: config.Days(ch.Retention.D1m), TTL5m: config.Days(ch.Retention.D5m), TTL1h: config.Days(ch.Retention.D1h)}); err != nil {
		return res, fail(http.StatusBadGateway, "clickhouse_migrate_failed", err)
	}

	put := func(path, key, typed, defRef string) (string, error) {
		if typed == "" {
			return defRef, nil
		}
		ref, err := vault.PutRef(ctx, path, key, typed)
		if err != nil {
			return "", fail(http.StatusBadGateway, "openbao_write_failed", err)
		}
		return ref, nil
	}
	var pgRef, chRef, natsRef string
	if pgRef, err = put(SecretPostgres, "password", pgTyped, pgDefRef); err != nil {
		return res, err
	}
	if chRef, err = put(SecretClickHouse, "password", chTyped, chDefRef); err != nil {
		return res, err
	}
	if natsRef, err = put(SecretNATS, "token", natsTyped, nc.Token); err != nil {
		return res, err
	}
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		return res, fail(http.StatusBadGateway, "openbao_write_failed", err)
	}

	pgWrite := func(err error) error {
		if err != nil {
			return fail(http.StatusBadGateway, "postgres_write_failed", err)
		}
		return nil
	}
	if err := pgWrite(st.PutSetting(ctx, SettingGeneral, general)); err != nil {
		return res, err
	}
	if err := pgWrite(st.PutSetting(ctx, SettingCollector, col)); err != nil {
		return res, err
	}
	if err := pgWrite(st.PutSetting(ctx, SettingPasswordPolicy, policy.Normalize())); err != nil {
		return res, err
	}
	if !attach || len(geo.Databases) > 0 {
		if err := pgWrite(st.PutSetting(ctx, SettingGeoIP, geo)); err != nil {
			return res, err
		}
	}
	if umb.Enabled {
		ref, err := put(SecretUmbrella, "token", umb.Token, "")
		if err != nil {
			return res, err
		}
		if err := pgWrite(st.PutSetting(ctx, SettingUmbrella, UmbrellaSettings{Enabled: true,
			IngestURL: strings.TrimSpace(umb.IngestURL), TokenRef: ref})); err != nil {
			return res, err
		}
	}
	if inv.Enabled {
		ref, err := put(SecretInventory, "token", inv.Token, "")
		if err != nil {
			return res, err
		}
		if err := pgWrite(st.SetInventoryDB(ctx, store.InventoryDB{Enabled: true, URL: strings.TrimRight(strings.TrimSpace(inv.URL), "/"),
			TokenRef: ref, Interval: invInterval})); err != nil {
			return res, err
		}
	}
	if admin != nil {
		if err := m.createAdmin(ctx, st, vault, admin); err != nil {
			return res, err
		}
	}
	actor := "setup"
	if admin != nil {
		actor = admin.Username
	}
	_ = st.Audit(ctx, actor, "setup.complete", "", remote, map[string]any{
		"postgres": pg.Host + "/" + pg.Database, "attached": attach, "clickhouse": ch.Addr, "openbao": ob.Addr,
		"nats": nc.URL != "", "inventory": inv.Enabled, "umbrella": umb.Enabled, "geoip": len(geo.Databases)})

	now := time.Now().UTC()
	pg.Password = pgRef
	ch.Password = chRef
	file := config.File{OpenBao: ob, Postgres: pg, ClickHouse: ch, NATS: config.NATS{URL: nc.URL, Token: natsRef}, CompletedAt: &now}
	if err := config.Write(m.opt.DataDir, file); err != nil {
		return res, fail(http.StatusInternalServerError, "config_write_failed", err)
	}
	keep = true
	return Result{Config: file, Vault: vault, Store: st}, nil
}

func (m *Module) createAdmin(ctx context.Context, st *store.Store, vault *secrets.Client, a *AdminInput) error {
	role, err := st.RoleByName(ctx, access.RoleAdministrator)
	if err != nil {
		return fail(http.StatusBadGateway, "postgres_write_failed", err)
	}
	name := strings.TrimSpace(a.Name)
	if name == "" {
		name = a.Username
	}
	u, err := st.UserByUsername(ctx, a.Username)
	switch {
	case err == nil:
		if u.Source != store.SourceLocal {
			return fail(http.StatusConflict, "admin_invalid", errors.New("a directory user with this name exists"))
		}
		enabled := false
		if _, err := st.UpdateUser(ctx, u.ID, store.UserUpdate{RoleID: &role.ID, Disabled: &enabled}); err != nil {
			return fail(http.StatusBadGateway, "postgres_write_failed", err)
		}
	case errors.Is(err, store.ErrNotFound):
		if u, err = st.CreateUser(ctx, store.NewUser{Username: a.Username, Name: name, Email: strings.TrimSpace(a.Email), RoleID: role.ID}); err != nil {
			return fail(http.StatusBadGateway, "postgres_write_failed", err)
		}
	default:
		return fail(http.StatusBadGateway, "postgres_unavailable", err)
	}
	ref, err := auth.NewPasswords(vault).Set(ctx, u.ID, a.Password)
	if err != nil {
		return fail(http.StatusBadGateway, "openbao_write_failed", err)
	}
	if err := st.SetPasswordRef(ctx, u.ID, ref); err != nil {
		return fail(http.StatusBadGateway, "postgres_write_failed", err)
	}
	return nil
}

// Token returns the setup code: FLOW_SETUP_TOKEN (fixed), the code saved in
// <dir>/setup-token, or a new random one saved there.
func Token(dir, fixed string) (string, error) {
	if t := strings.TrimSpace(fixed); t != "" {
		return t, nil
	}
	path := filepath.Join(dir, config.SetupTokenFile)
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	t := auth.RandomToken("", 12)
	if err := config.WriteFileAtomic(path, []byte(t+"\n")); err != nil {
		return "", err
	}
	return t, nil
}
