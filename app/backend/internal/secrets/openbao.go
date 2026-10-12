// Package secrets is a small OpenBao (KV v2) client: token or AppRole sign-in,
// token renewal, a 30 s read cache and openbao:// references. Ported from
// Umbrella Monitoring.
package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scheme prefixes secret references: openbao://<mount>/<path>#<key>.
const Scheme = "openbao://"

// DefaultMount is the KV v2 mount Flow uses unless configured otherwise.
const DefaultMount = "flow"

type Resolver interface {
	Resolve(ref string) (string, error)
}

var (
	ErrNotConfigured = errors.New("OpenBao is not configured")
	ErrNotFound      = errors.New("secret not found in OpenBao")
)

type Config struct {
	Addr      string
	Mount     string
	Namespace string

	Token     string
	TokenFile string

	RoleID       string
	RoleIDFile   string
	SecretID     string
	SecretIDFile string
	AppRolePath  string

	CACert             string
	CACertPEM          string
	InsecureSkipVerify bool
	CacheTTL           time.Duration
}

type cached struct {
	data map[string]string
	at   time.Time
}

type Client struct {
	cur atomic.Pointer[conn]

	mu        sync.Mutex
	token     string
	expires   time.Time
	ttl       time.Duration // lease duration of the token
	renewable bool
	policies  []string
	cache     map[string]cached
	lastErr   string
	lastErrAt time.Time
	renewal   Renewal
}

func New(cfg Config) (*Client, error) {
	cn, err := newConn(cfg)
	if err != nil {
		return nil, err
	}
	c := &Client{cache: map[string]cached{}}
	c.cur.Store(cn)
	return c, nil
}

// Reconfigure switches the client to another OpenBao (or mount) in place:
// every holder of the client follows at once. The token and the read cache
// are dropped; the next request signs in to the new server.
func (c *Client) Reconfigure(cfg Config) error {
	cn, err := newConn(cfg)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur.Store(cn)
	c.token, c.expires, c.ttl, c.renewable, c.policies = "", time.Time{}, 0, false, nil
	c.cache = map[string]cached{}
	c.lastErr, c.renewal = "", Renewal{}
	return nil
}

// Config returns the current connection settings.
func (c *Client) Config() Config { return *c.conf() }

// conn is one connection: settings and the HTTP client built from them.
type conn struct {
	cfg  Config
	http *http.Client
}

func (c *Client) conf() *Config { return &c.cur.Load().cfg }

func newConn(cfg Config) (*conn, error) {
	if cfg.Mount == "" {
		cfg.Mount = DefaultMount
	}
	cfg.Mount = strings.Trim(cfg.Mount, "/")
	if cfg.AppRolePath == "" {
		cfg.AppRolePath = "approle"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	cfg.Addr = strings.TrimRight(cfg.Addr, "/")
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.CACert != "" || cfg.CACertPEM != "" {
		pem := []byte(cfg.CACertPEM)
		if cfg.CACert != "" {
			b, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("OpenBao CA: %w", err)
			}
			pem = b
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("OpenBao CA: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &conn{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second, Transport: tr}}, nil
}

func (c *Client) Enabled() bool { return c != nil && c.cur.Load() != nil && c.conf().Addr != "" }

func (c *Client) Mount() string { return c.conf().Mount }

func (c *Client) Ref(path, key string) string {
	return Scheme + c.conf().Mount + "/" + strings.Trim(path, "/") + "#" + key
}

func ParseRef(ref string) (mount, path, key string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(ref), Scheme)
	if !ok {
		return "", "", "", fmt.Errorf("secret reference must start with %s", Scheme)
	}
	rest, key, _ = strings.Cut(rest, "#")
	if key == "" {
		key = "value"
	}
	mount, path, _ = strings.Cut(strings.Trim(rest, "/"), "/")
	if mount == "" || path == "" || strings.Contains(path, "..") {
		return "", "", "", fmt.Errorf("secret reference format is %s<mount>/<path>#<key>", Scheme)
	}
	return mount, path, key, nil
}

func IsRef(v string) bool { return strings.HasPrefix(strings.TrimSpace(v), Scheme) }

func (c *Client) Resolve(ref string) (string, error) {
	mount, path, key, err := ParseRef(ref)
	if err != nil {
		return "", err
	}
	data, err := c.read(context.Background(), mount, path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ref, err)
	}
	v, ok := data[key]
	if !ok {
		return "", fmt.Errorf("%s: %w (no key %q)", ref, ErrNotFound, key)
	}
	return v, nil
}

func (c *Client) Put(ctx context.Context, path string, values map[string]string) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	path = strings.Trim(path, "/")
	data, err := c.read(ctx, c.conf().Mount, path)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	merged := map[string]string{}
	for k, v := range data {
		merged[k] = v
	}
	for k, v := range values {
		if v == "" {
			delete(merged, k)
		} else {
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return c.Delete(ctx, path)
	}
	if err := c.do(ctx, http.MethodPost, "/v1/"+c.conf().Mount+"/data/"+path, map[string]any{"data": merged}, nil); err != nil {
		return err
	}
	c.mu.Lock()
	c.cache[c.conf().Mount+"/"+path] = cached{data: merged, at: time.Now()}
	c.mu.Unlock()
	return nil
}

func (c *Client) PutRef(ctx context.Context, path, key, value string) (string, error) {
	if err := c.Put(ctx, path, map[string]string{key: value}); err != nil {
		return "", err
	}
	return c.Ref(path, key), nil
}

func (c *Client) Delete(ctx context.Context, path string) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	path = strings.Trim(path, "/")
	err := c.do(ctx, http.MethodDelete, "/v1/"+c.conf().Mount+"/metadata/"+path, nil, nil)
	c.mu.Lock()
	delete(c.cache, c.conf().Mount+"/"+path)
	c.mu.Unlock()
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func (c *Client) Owns(ref, path string) bool {
	mount, p, _, err := ParseRef(ref)
	return err == nil && mount == c.conf().Mount && p == strings.Trim(path, "/")
}

func (c *Client) read(ctx context.Context, mount, path string) (map[string]string, error) {
	if !c.Enabled() {
		return nil, ErrNotConfigured
	}
	k := mount + "/" + path
	c.mu.Lock()
	if e, ok := c.cache[k]; ok && time.Since(e.at) < c.conf().CacheTTL {
		c.mu.Unlock()
		return e.data, nil
	}
	c.mu.Unlock()
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/"+mount+"/data/"+path, nil, &out); err != nil {
		return nil, err
	}
	data := map[string]string{}
	for key, v := range out.Data.Data {
		switch x := v.(type) {
		case string:
			data[key] = x
		case nil:
		default:
			b, _ := json.Marshal(x)
			data[key] = string(b)
		}
	}
	c.mu.Lock()
	c.cache[k] = cached{data: data, at: time.Now()}
	c.mu.Unlock()
	return data, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.ensureToken(ctx, attempt > 0)
		if err != nil {
			c.fail(err)
			return err
		}
		code, err := c.raw(ctx, method, path, tok, body, out)
		if code == http.StatusForbidden && attempt == 0 && (c.conf().RoleID != "" || c.conf().RoleIDFile != "" || c.conf().TokenFile != "") {
			continue
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			c.fail(err)
		}
		return err
	}
	return errors.New("OpenBao: permission denied")
}

func (c *Client) raw(ctx context.Context, method, path, token string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.conf().Addr+path, rd)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.conf().Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.conf().Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cur.Load().http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("OpenBao is unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp.StatusCode, ErrNotFound
	case resp.StatusCode == http.StatusServiceUnavailable:
		return resp.StatusCode, errors.New("OpenBao is sealed or not initialized")
	case resp.StatusCode/100 != 2:
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.Join(e.Errors, "; ")
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return resp.StatusCode, fmt.Errorf("OpenBao answered %d: %s", resp.StatusCode, msg)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("OpenBao: invalid response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func readValue(v, file string) (string, error) {
	if v != "" {
		return v, nil
	}
	if file == "" {
		return "", nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) authMethod() string {
	if c.conf().RoleID != "" || c.conf().RoleIDFile != "" {
		return "approle"
	}
	if c.conf().Token != "" || c.conf().TokenFile != "" {
		return "token"
	}
	return ""
}

func (c *Client) ensureToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	tok, exp := c.token, c.expires
	c.mu.Unlock()
	if tok != "" && !force && (exp.IsZero() || time.Until(exp) > 5*time.Second) {
		return tok, nil
	}
	return c.login(ctx)
}

func (c *Client) login(ctx context.Context) (string, error) {
	switch c.authMethod() {
	case "approle":
		roleID, err := readValue(c.conf().RoleID, c.conf().RoleIDFile)
		if err != nil {
			return "", fmt.Errorf("OpenBao role_id: %w", err)
		}
		secretID, err := readValue(c.conf().SecretID, c.conf().SecretIDFile)
		if err != nil {
			return "", fmt.Errorf("OpenBao secret_id: %w", err)
		}
		var out struct {
			Auth struct {
				ClientToken   string   `json:"client_token"`
				LeaseDuration int      `json:"lease_duration"`
				Renewable     bool     `json:"renewable"`
				Policies      []string `json:"policies"`
			} `json:"auth"`
		}
		if _, err := c.raw(ctx, http.MethodPost, "/v1/auth/"+c.conf().AppRolePath+"/login",
			"", map[string]string{"role_id": roleID, "secret_id": secretID}, &out); err != nil {
			return "", fmt.Errorf("OpenBao AppRole login: %w", err)
		}
		c.setToken(out.Auth.ClientToken, out.Auth.LeaseDuration, out.Auth.Renewable, out.Auth.Policies)
		c.noteLogin()
		return out.Auth.ClientToken, nil
	case "token":
		tok, err := readValue(c.conf().Token, c.conf().TokenFile)
		if err != nil {
			return "", fmt.Errorf("OpenBao token: %w", err)
		}
		info, err := c.lookup(ctx, tok)
		if err != nil {
			return "", err
		}
		c.setToken(tok, info.TTL, info.Renewable, info.Policies)
		c.noteLogin()
		return tok, nil
	}
	return "", ErrNotConfigured
}

type tokenInfo struct {
	TTL       int      `json:"ttl"`
	Renewable bool     `json:"renewable"`
	Policies  []string `json:"policies"`
}

func (c *Client) lookup(ctx context.Context, tok string) (tokenInfo, error) {
	var out struct {
		Data tokenInfo `json:"data"`
	}
	if _, err := c.raw(ctx, http.MethodGet, "/v1/auth/token/lookup-self", tok, nil, &out); err != nil {
		return tokenInfo{}, fmt.Errorf("OpenBao token lookup: %w", err)
	}
	return out.Data, nil
}

func (c *Client) setToken(tok string, ttl int, renewable bool, policies []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.renewable, c.policies = tok, renewable, policies
	c.expires, c.ttl = time.Time{}, 0
	if ttl > 0 {
		c.ttl = time.Duration(ttl) * time.Second
		c.expires = time.Now().Add(c.ttl)
	}
	c.lastErr = ""
}

// Renewal is how the client keeps its token alive (Settings → OpenBao).
type Renewal struct {
	// Mode: "renew" (the token is renewed), "login" (a non-renewable token:
	// AppRole signs in again), "none" (a token without expiry).
	Mode        string     `json:"mode"`
	LoggedInAt  *time.Time `json:"logged_in_at,omitempty"`
	Logins      int        `json:"logins"`
	RenewedAt   *time.Time `json:"renewed_at,omitempty"`
	Renewals    int        `json:"renewals"`
	NextAt      *time.Time `json:"next_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

func (c *Client) noteLogin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	c.renewal.LoggedInAt = &now
	c.renewal.Logins++
}

func (c *Client) noteRenewal(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	if err != nil {
		c.renewal.LastError, c.renewal.LastErrorAt = err.Error(), &now
		return
	}
	c.renewal.RenewedAt = &now
	c.renewal.Renewals++
	c.renewal.LastError, c.renewal.LastErrorAt = "", nil
}

// renewalState returns the renewal record with the mode and next check.
func (c *Client) renewalState() Renewal {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.renewal
	switch {
	case c.expires.IsZero():
		r.Mode = "none"
	case c.renewable:
		r.Mode = "renew"
	default:
		r.Mode = "login"
	}
	if !c.expires.IsZero() {
		next := c.expires.Add(-c.ttl / 3)
		if c.ttl == 0 || next.Before(time.Now()) {
			next = time.Now()
		}
		next = next.UTC()
		r.NextAt = &next
	}
	return r
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	c.lastErr, c.lastErrAt = err.Error(), time.Now()
	c.mu.Unlock()
}

func (c *Client) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	for {
		wait := time.Minute
		c.mu.Lock()
		tok, exp, ttl, renewable := c.token, c.expires, c.ttl, c.renewable
		c.mu.Unlock()
		if tok == "" {
			if _, err := c.login(ctx); err != nil {
				c.fail(err)
				slog.Warn("openbao login failed", "err", err)
				wait = 15 * time.Second
			}
		} else if !exp.IsZero() {
			// Renew once two thirds of the lease have passed (or in the last minute).
			left := time.Until(exp)
			if left < ttl/3 || left < time.Minute {
				err := c.renew(ctx, renewable)
				c.noteRenewal(err)
				if err != nil {
					slog.Warn("openbao token renewal failed, logging in again", "err", err)
					if _, err := c.login(ctx); err != nil {
						c.fail(err)
						wait = 15 * time.Second
					}
				}
			}
			c.mu.Lock()
			if !c.expires.IsZero() {
				w := time.Until(c.expires.Add(-c.ttl / 3))
				if w < 5*time.Second {
					w = 5 * time.Second
				}
				if w < wait {
					wait = w
				}
			}
			c.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *Client) renew(ctx context.Context, renewable bool) error {
	if !renewable {
		_, err := c.login(ctx)
		return err
	}
	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()
	var out struct {
		Auth struct {
			LeaseDuration int      `json:"lease_duration"`
			Renewable     bool     `json:"renewable"`
			Policies      []string `json:"policies"`
		} `json:"auth"`
	}
	if _, err := c.raw(ctx, http.MethodPost, "/v1/auth/token/renew-self", tok, map[string]any{}, &out); err != nil {
		return err
	}
	c.setToken(tok, out.Auth.LeaseDuration, out.Auth.Renewable, out.Auth.Policies)
	return nil
}

type Status struct {
	Configured  bool       `json:"configured"`
	Addr        string     `json:"addr,omitempty"`
	Mount       string     `json:"mount,omitempty"`
	Auth        string     `json:"auth,omitempty"`
	Namespace   string     `json:"namespace,omitempty"`
	Reachable   bool       `json:"reachable"`
	Initialized bool       `json:"initialized"`
	Sealed      bool       `json:"sealed"`
	Version     string     `json:"version,omitempty"`
	ClusterName string     `json:"cluster_name,omitempty"`
	TokenOK     bool       `json:"token_ok"`
	TokenExpiry *time.Time `json:"token_expires,omitempty"`
	Renewable   bool       `json:"renewable"`
	Policies    []string   `json:"policies,omitempty"`
	MountOK     bool       `json:"mount_ok"`
	Error       string     `json:"error,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	Renewal     Renewal    `json:"renewal"`
}

func (c *Client) Status(ctx context.Context) Status {
	if !c.Enabled() {
		return Status{Error: ErrNotConfigured.Error()}
	}
	s := Status{Configured: true, Addr: c.conf().Addr, Mount: c.conf().Mount, Auth: c.authMethod(), Namespace: c.conf().Namespace}
	var h struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
		ClusterName string `json:"cluster_name"`
	}
	q := url.Values{"standbyok": {"true"}, "sealedcode": {"200"}, "uninitcode": {"200"}}
	if _, err := c.raw(ctx, http.MethodGet, "/v1/sys/health?"+q.Encode(), "", nil, &h); err != nil {
		s.Error = err.Error()
		return c.withLast(s)
	}
	s.Reachable, s.Initialized, s.Sealed, s.Version, s.ClusterName = true, h.Initialized, h.Sealed, h.Version, h.ClusterName
	if !h.Initialized || h.Sealed {
		s.Error = "OpenBao is sealed or not initialized"
		return c.withLast(s)
	}
	tok, err := c.ensureToken(ctx, false)
	if err != nil {
		s.Error = err.Error()
		return c.withLast(s)
	}
	info, err := c.lookup(ctx, tok)
	if err != nil {
		s.Error = err.Error()
		return c.withLast(s)
	}
	s.TokenOK, s.Policies, s.Renewable = true, info.Policies, info.Renewable
	if info.TTL > 0 {
		t := time.Now().Add(time.Duration(info.TTL) * time.Second)
		s.TokenExpiry = &t
	}

	_, err = c.raw(ctx, http.MethodGet, "/v1/"+c.conf().Mount+"/data/_flow_probe", tok, nil, nil)
	if err == nil || errors.Is(err, ErrNotFound) {
		s.MountOK = true
	} else {
		s.Error = "no access to the KV mount " + c.conf().Mount + ": " + err.Error()
	}
	return c.withLast(s)
}

func (c *Client) withLast(s Status) Status {
	s.Renewal = c.renewalState()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr != "" {
		s.LastError = c.lastErr
		t := c.lastErrAt
		s.LastErrorAt = &t
	}
	return s
}

func (c *Client) Ready(ctx context.Context, timeout time.Duration) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	deadline := time.Now().Add(timeout)
	for {
		st := c.Status(ctx)
		if st.TokenOK && st.MountOK {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New(st.Error)
		}
		slog.Info("waiting for openbao", "state", st.Error)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func Value(r Resolver, v string) (string, error) {
	if !IsRef(v) {
		return v, nil
	}
	if r == nil {
		return "", ErrNotConfigured
	}
	return r.Resolve(v)
}
