// Package config reads the process environment (FLOW_* variables) and the
// data directory file flow.json written by the setup wizard.
//
// flow.json holds connections only: OpenBao, PostgreSQL, ClickHouse and NATS.
// Every secret in it is an openbao:// reference; the only credential kept in
// the file is the one for OpenBao itself, preferably as paths to the AppRole
// role_id / secret_id files (the file is 0600).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

const (
	FileName       = "flow.json"
	SetupTokenFile = "setup-token"
	version        = 1

	AuthToken   = "token"
	AuthAppRole = "approle"

	// Secret paths in the OpenBao mount.
	PostgresSecretPath   = "postgres"
	PostgresSecretKey    = "password"
	ClickHouseSecretPath = "clickhouse"
	ClickHouseSecretKey  = "password"
)

// OpenBao is the OpenBao connection. Empty Addr means OpenBao is not used.
type OpenBao struct {
	Addr      string `json:"addr"`
	Mount     string `json:"mount"`
	Namespace string `json:"namespace,omitempty"`
	Auth      string `json:"auth"`
	Token     string `json:"token,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	RoleID    string `json:"role_id,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
	// RoleIDFile / SecretIDFile: AppRole credentials read from files (the
	// openbao-init container of deploy/flow writes them to a shared volume).
	RoleIDFile   string `json:"role_id_file,omitempty"`
	SecretIDFile string `json:"secret_id_file,omitempty"`
	AppRolePath  string `json:"approle_path,omitempty"`
	CACert       string `json:"ca_cert,omitempty"`
	SkipVerify   bool   `json:"skip_verify,omitempty"`
}

// Enabled reports whether an OpenBao address is set.
func (o OpenBao) Enabled() bool { return strings.TrimSpace(o.Addr) != "" }

// Normalize trims the fields and checks them.
func (o OpenBao) Normalize() (OpenBao, error) {
	o.Addr = strings.TrimRight(strings.TrimSpace(o.Addr), "/")
	o.Mount = strings.Trim(strings.TrimSpace(o.Mount), "/")
	o.Namespace = strings.Trim(strings.TrimSpace(o.Namespace), "/")
	o.AppRolePath = strings.Trim(strings.TrimSpace(o.AppRolePath), "/")
	o.Token = strings.TrimSpace(o.Token)
	o.TokenFile = strings.TrimSpace(o.TokenFile)
	o.RoleID = strings.TrimSpace(o.RoleID)
	o.SecretID = strings.TrimSpace(o.SecretID)
	o.RoleIDFile = strings.TrimSpace(o.RoleIDFile)
	o.SecretIDFile = strings.TrimSpace(o.SecretIDFile)
	o.CACert = strings.TrimSpace(o.CACert)
	if o.Mount == "" {
		o.Mount = secrets.DefaultMount
	}
	u, err := url.Parse(o.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return o, errors.New("OpenBao address must look like https://openbao.example:8200")
	}
	if o.Auth == "" {
		if o.RoleID != "" || o.RoleIDFile != "" {
			o.Auth = AuthAppRole
		} else {
			o.Auth = AuthToken
		}
	}
	switch o.Auth {
	case AuthToken:
		if o.Token == "" && o.TokenFile == "" {
			return o, errors.New("OpenBao token is required")
		}
		o.RoleID, o.SecretID, o.RoleIDFile, o.SecretIDFile, o.AppRolePath = "", "", "", "", ""
	case AuthAppRole:
		if (o.RoleID == "" && o.RoleIDFile == "") || (o.SecretID == "" && o.SecretIDFile == "") {
			return o, errors.New("AppRole role_id and secret_id (or their files) are required")
		}
		if o.AppRolePath == "" {
			o.AppRolePath = "approle"
		}
		o.Token, o.TokenFile = "", ""
	default:
		return o, errors.New("OpenBao sign-in method must be token or approle")
	}
	return o, nil
}

// Client returns an OpenBao client, or nil when OpenBao is not configured.
func (o OpenBao) Client() (*secrets.Client, error) {
	if !o.Enabled() {
		return nil, nil
	}
	return secrets.New(secrets.Config{Addr: o.Addr, Mount: o.Mount, Namespace: o.Namespace, Token: o.Token, TokenFile: o.TokenFile,
		RoleID: o.RoleID, SecretID: o.SecretID, RoleIDFile: o.RoleIDFile, SecretIDFile: o.SecretIDFile, AppRolePath: o.AppRolePath, CACertPEM: o.CACert,
		InsecureSkipVerify: o.SkipVerify})
}

// Postgres is the configuration database. Password is an openbao://
// reference (or the password itself without OpenBao). DSN, when set, is used
// instead of the fields (it may also be a reference).
type Postgres struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Database string `json:"database,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	SSLMode  string `json:"sslmode,omitempty"`
	DSN      string `json:"dsn,omitempty"`
}

// Normalize trims the fields and applies defaults (port 5432, database flow, sslmode prefer).
func (p Postgres) Normalize() (Postgres, error) {
	p.Host = strings.TrimSpace(p.Host)
	p.Database = strings.TrimSpace(p.Database)
	p.Username = strings.TrimSpace(p.Username)
	p.SSLMode = strings.TrimSpace(p.SSLMode)
	p.DSN = strings.TrimSpace(p.DSN)
	if p.DSN != "" {
		return p, nil
	}
	if p.Port == 0 {
		p.Port = 5432
	}
	if p.Database == "" {
		p.Database = "flow"
	}
	if p.SSLMode == "" {
		p.SSLMode = "prefer"
	}
	switch p.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return p, errors.New("sslmode must be disable, allow, prefer, require, verify-ca or verify-full")
	}
	if p.Host == "" || p.Username == "" {
		return p, errors.New("PostgreSQL host and user are required")
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, errors.New("PostgreSQL port is invalid")
	}
	return p, nil
}

// BuildDSN returns the connection URL with the given (resolved) password.
func (p Postgres) BuildDSN(password string) string {
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(p.Host, fmt.Sprint(p.Port)), Path: "/" + p.Database}
	if password != "" {
		u.User = url.UserPassword(p.Username, password)
	} else {
		u.User = url.User(p.Username)
	}
	u.RawQuery = url.Values{"sslmode": {p.SSLMode}}.Encode()
	return u.String()
}

// Retention of flows in ClickHouse, in days.
type Retention struct {
	RawDays int `json:"raw_days"`
	D1m     int `json:"d1m"`
	D5m     int `json:"d5m"`
	D1h     int `json:"d1h"`
}

// DefaultRetention: raw 15 days, 1m 30 days, 5m 90 days, 1h 730 days.
var DefaultRetention = Retention{RawDays: 15, D1m: 30, D5m: 90, D1h: 730}

// WithDefaults fills zero fields.
func (r Retention) WithDefaults() Retention {
	if r.RawDays <= 0 {
		r.RawDays = DefaultRetention.RawDays
	}
	if r.D1m <= 0 {
		r.D1m = DefaultRetention.D1m
	}
	if r.D5m <= 0 {
		r.D5m = DefaultRetention.D5m
	}
	if r.D1h <= 0 {
		r.D1h = DefaultRetention.D1h
	}
	return r
}

// Days converts days to a duration.
func Days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// NATS is the bus; an empty URL means the in-process queue. Token is an
// openbao:// reference (credentials never go into the URL).
type NATS struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// ClickHouse is the flow storage connection (native protocol).
type ClickHouse struct {
	Addr       string    `json:"addr"` // host:9000; several separated by commas
	Database   string    `json:"database"`
	Username   string    `json:"username"`
	Password   string    `json:"password,omitempty"` // openbao:// reference or the plain password
	Secure     bool      `json:"secure,omitempty"`
	SkipVerify bool      `json:"skip_verify,omitempty"`
	Retention  Retention `json:"retention"`
}

// Addrs splits Addr into host:port items, adding the default port 9000 (9440 with TLS).
func (c ClickHouse) Addrs() []string {
	var out []string
	for _, a := range strings.Split(c.Addr, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			port := "9000"
			if c.Secure {
				port = "9440"
			}
			a = net.JoinHostPort(strings.Trim(a, "[]"), port)
		}
		out = append(out, a)
	}
	return out
}

// Normalize trims the fields, applies defaults and checks them.
func (c ClickHouse) Normalize() (ClickHouse, error) {
	c.Addr = strings.TrimSpace(c.Addr)
	c.Database = strings.TrimSpace(c.Database)
	c.Username = strings.TrimSpace(c.Username)
	if c.Database == "" {
		c.Database = "flow"
	}
	if c.Username == "" {
		c.Username = "default"
	}
	c.Retention = c.Retention.WithDefaults()
	if len(c.Addrs()) == 0 {
		return c, errors.New("ClickHouse address is required (host:9000)")
	}
	for _, r := range c.Database {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return c, errors.New("ClickHouse database name may contain only letters, digits and _")
		}
	}
	return c, nil
}

// File is flow.json.
type File struct {
	Version     int        `json:"version"`
	OpenBao     OpenBao    `json:"openbao"`
	Postgres    Postgres   `json:"postgres"`
	ClickHouse  ClickHouse `json:"clickhouse"`
	NATS        NATS       `json:"nats"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Read returns flow.json from dir; found is false when there is none.
func Read(dir string) (f File, found bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return f, false, nil
	}
	if err != nil {
		return f, false, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, false, fmt.Errorf("%s: %w", FileName, err)
	}
	if f.Version != version {
		return f, false, fmt.Errorf("%s: unsupported version %d", FileName, f.Version)
	}
	return f, true, nil
}

// Write stores flow.json in dir atomically with mode 0600.
func Write(dir string, f File) error {
	f.Version = version
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, FileName), append(b, '\n'))
}

// WriteFileAtomic writes data to a temporary file and renames it over path.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Role is the part of the pipeline a process runs.
type Role string

const (
	RoleAll       Role = "all"
	RoleCollector Role = "collector"
	RoleEnricher  Role = "enricher"
	RoleAPI       Role = "api"
	RoleDetector  Role = "detector"
)

// ParseRole checks a FLOW_ROLE value.
func ParseRole(s string) (Role, error) {
	switch r := Role(strings.ToLower(strings.TrimSpace(s))); r {
	case "":
		return RoleAll, nil
	case RoleAll, RoleCollector, RoleEnricher, RoleAPI, RoleDetector:
		return r, nil
	}
	return "", fmt.Errorf("FLOW_ROLE must be all, collector, enricher, api or detector, not %q", s)
}

// Runs reports whether a process with role r runs the component c.
func (r Role) Runs(c Role) bool { return r == RoleAll || r == c }

// NeedsConfig reports whether the role needs flow.json (PostgreSQL / ClickHouse).
// The collector only receives UDP and publishes to the bus.
func (r Role) NeedsConfig() bool { return r != RoleCollector }

// Env is the process configuration from FLOW_* environment variables.
type Env struct {
	Addr           string         // FLOW_ADDR, HTTP listen address (:8080)
	DataDir        string         // FLOW_DATA_DIR, flow.json, setup-token (data)
	WebDir         string         // FLOW_WEB_DIR, built web UI (../web/dist)
	StartupWait    time.Duration  // FLOW_STARTUP_WAIT, how long to wait for OpenBao / PostgreSQL (2m)
	SetupToken     string         // FLOW_SETUP_TOKEN, fixed setup code (default: random, in the log and data/setup-token)
	SecureCookies  bool           // FLOW_SECURE_COOKIES, Secure flag on cookies (behind HTTPS)
	TrustedProxies []netip.Prefix // FLOW_TRUSTED_PROXIES, comma-separated addresses / CIDRs whose X-Forwarded-For is trusted
	Role           Role           // FLOW_ROLE, all | collector | enricher | api | detector
	NetFlowAddr    string         // FLOW_NETFLOW_ADDR, UDP for NetFlow v5/v9 and IPFIX (:2055)
	SFlowAddr      string         // FLOW_SFLOW_ADDR, UDP for sFlow (:6343)
	NATSURL        string         // FLOW_NATS_URL, empty = in-process bus
	// SPA, the Single Point of Authorization: the connection key or the file
	// holding it (without both, the key is read from OpenBao, spa#connection_key)
	// and the address of Flow when it differs from the request address.
	SPAConnectionKey     string // SPA_CONNECTION_KEY
	SPAConnectionKeyFile string // SPA_CONNECTION_KEY_FILE
	SPAPublicURL         string // SPA_PUBLIC_URL
}

// LoadEnv reads the environment through getenv (os.Getenv when nil).
func LoadEnv(getenv func(string) string) (Env, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	e := Env{
		Addr:        get("FLOW_ADDR", ":8080"),
		DataDir:     get("FLOW_DATA_DIR", "data"),
		WebDir:      get("FLOW_WEB_DIR", "../web/dist"),
		SetupToken:  get("FLOW_SETUP_TOKEN", ""),
		NetFlowAddr: get("FLOW_NETFLOW_ADDR", ":2055"),
		SFlowAddr:   get("FLOW_SFLOW_ADDR", ":6343"),
		NATSURL:     get("FLOW_NATS_URL", ""),

		SPAConnectionKey:     get("SPA_CONNECTION_KEY", ""),
		SPAConnectionKeyFile: get("SPA_CONNECTION_KEY_FILE", ""),
		SPAPublicURL:         strings.TrimRight(get("SPA_PUBLIC_URL", ""), "/"),
	}
	var errs []error
	wait, err := time.ParseDuration(get("FLOW_STARTUP_WAIT", "2m"))
	if err != nil || wait < 0 {
		errs = append(errs, fmt.Errorf("FLOW_STARTUP_WAIT: %q is not a duration like 2m", getenv("FLOW_STARTUP_WAIT")))
		wait = 2 * time.Minute
	}
	e.StartupWait = wait
	switch strings.ToLower(get("FLOW_SECURE_COOKIES", "false")) {
	case "1", "true", "yes", "on":
		e.SecureCookies = true
	case "0", "false", "no", "off":
	default:
		errs = append(errs, errors.New("FLOW_SECURE_COOKIES must be true or false"))
	}
	if e.TrustedProxies, err = ParsePrefixes(getenv("FLOW_TRUSTED_PROXIES")); err != nil {
		errs = append(errs, fmt.Errorf("FLOW_TRUSTED_PROXIES: %w", err))
	}
	if e.Role, err = ParseRole(getenv("FLOW_ROLE")); err != nil {
		errs = append(errs, err)
	}
	if e.SPAPublicURL != "" {
		if u, err := url.Parse(e.SPAPublicURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("SPA_PUBLIC_URL must look like https://flow.example.com"))
		}
	}
	return e, errors.Join(errs...)
}

// ParsePrefixes parses a comma- or space-separated list of addresses and CIDRs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", item)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}
