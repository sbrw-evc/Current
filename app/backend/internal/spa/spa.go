// Package spa is the client of SPA, the Single Point of Authorization of the
// Umbrella family (https://github.com/sbrw-evc/SPA-Single-point-of-authorization-,
// docs/protocol.md): the connection key, sign-in through SPA (OpenID Connect,
// authorization code flow with PKCE S256 and a nonce) and the federation API
// (configuration, users, the role catalogue).
package spa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
)

const (
	// KeyPrefix starts a connection key.
	KeyPrefix = "spa1."
	// CallbackPath is where SPA sends the browser back (<address>/api/auth/spa/callback).
	CallbackPath = "/api/auth/spa/callback"
	// StartPath starts a sign-in.
	StartPath = "/api/auth/spa/start"
	// Env and EnvFile name the connection key in the deployment configuration.
	Env     = "SPA_CONNECTION_KEY"
	EnvFile = "SPA_CONNECTION_KEY_FILE"
	// EnvPublicURL is the address of the application when it differs from the request address.
	EnvPublicURL = "SPA_PUBLIC_URL"
	// SecretPath / SecretKey: the connection key in OpenBao (spa/connection_key).
	SecretPath = "spa"
	SecretKey  = "connection_key"
	// SyncEvery is how often the users are synchronized.
	SyncEvery = 5 * time.Minute
)

// Scopes asked at sign-in.
var Scopes = []string{"openid", "profile", "email", "groups", "roles"}

// Key is the connection key SPA shows when an application is connected.
type Key struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Token        string `json:"token"`
}

// ErrKey: the text is not a connection key.
var ErrKey = errors.New("this is not an SPA connection key (spa1.…): copy it again from SPA → Applications")

// ParseKey reads a connection key.
func ParseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, KeyPrefix) {
		return Key{}, ErrKey
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(s, KeyPrefix), "="))
	if err != nil {
		return Key{}, ErrKey
	}
	var k Key
	if err := json.Unmarshal(b, &k); err != nil || k.Issuer == "" || k.ClientID == "" || k.ClientSecret == "" || k.Token == "" {
		return Key{}, ErrKey
	}
	u, err := url.Parse(k.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Key{}, ErrKey
	}
	k.Issuer = strings.TrimRight(k.Issuer, "/")
	return k, nil
}

// String is the key in its spa1. form.
func (k Key) String() string {
	b, _ := json.Marshal(k)
	return KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// Timeout bounds every call to SPA.
var Timeout = 20 * time.Second

func client() *http.Client { return &http.Client{Timeout: Timeout} }

// Role is a role of the application's catalogue.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// RoleIDRe is the form of a role ID.
var RoleIDRe = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)

// Method is a sign-in method SPA offers.
type Method struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Config is GET /api/spa/v1/config.
type Config struct {
	Application struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"application"`
	Roles      []Role   `json:"roles"`
	Methods    []Method `json:"methods"`
	SignOutURL string   `json:"sign_out_url"`
	AccountURL string   `json:"account_url"`
}

// User is a person who has at least one role in the application.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Disabled  bool      `json:"disabled"`
	Roles     []string  `json:"roles"`
	Groups    []string  `json:"groups"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HTTPError is an answer of SPA that is not 200 / 304.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "SPA refused the federation token: the key was replaced or the application removed; issue a new connection key in SPA"
	case http.StatusForbidden:
		return "SPA refused access"
	}
	return fmt.Sprintf("SPA answered HTTP %d %s", e.Status, e.Body)
}

func (k Key) do(ctx context.Context, method, path, etag string, body, out any) (string, bool, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", false, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Issuer+path, rd)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+k.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := client().Do(req)
	if err != nil {
		return "", false, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		return etag, true, nil
	case http.StatusOK, http.StatusNoContent:
	default:
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return "", false, &HTTPError{Status: res.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil && res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(out); err != nil {
			return "", false, fmt.Errorf("SPA answer: %w", err)
		}
	}
	return res.Header.Get("ETag"), false, nil
}

// Config reads the configuration of the application; same = 304 for etag.
func (k Key) Config(ctx context.Context, etag string) (c Config, tag string, same bool, err error) {
	tag, same, err = k.do(ctx, http.MethodGet, "/api/spa/v1/config", etag, nil, &c)
	return c, tag, same, err
}

// Users reads the people of the application; same = 304 for etag.
func (k Key) Users(ctx context.Context, etag string) ([]User, string, bool, error) {
	var doc struct {
		Users []User `json:"users"`
	}
	tag, same, err := k.do(ctx, http.MethodGet, "/api/spa/v1/users", etag, nil, &doc)
	return doc.Users, tag, same, err
}

// Catalogue is the role catalogue of the application.
type Catalogue struct {
	Roles   []Role `json:"roles"`
	Default string `json:"default,omitempty"`
}

// PublishRoles replaces the role catalogue of the application in SPA.
func (k Key) PublishRoles(ctx context.Context, c Catalogue) error {
	_, _, err := k.do(ctx, http.MethodPut, "/api/spa/v1/roles", "", c, nil)
	return err
}

func (k Key) client(redirect string) oidcx.Client {
	return oidcx.Client{Issuer: k.Issuer, ClientID: k.ClientID, Secret: k.ClientSecret, RedirectURI: redirect,
		Scopes: Scopes, Extra: url.Values{}}
}

// AuthOptions are the optional parameters of the authorization request.
type AuthOptions struct {
	LoginHint string // login_hint
	IDPHint   string // idp_hint: password, passkey, ldap, entra, google, apple, oidc
	Prompt    string // prompt=login asks again even with an SPA session
}

// AuthURL is SPA's sign-in page for the request.
func (k Key) AuthURL(ctx context.Context, redirect string, o AuthOptions, r oidcx.Request) (string, error) {
	m, err := oidcx.Discover(ctx, k.Issuer)
	if err != nil {
		return "", err
	}
	c := k.client(redirect)
	if o.LoginHint != "" {
		c.Extra.Set("login_hint", o.LoginHint)
	}
	if o.IDPHint != "" {
		c.Extra.Set("idp_hint", o.IDPHint)
	}
	if o.Prompt != "" {
		c.Extra.Set("prompt", o.Prompt)
	}
	return oidcx.AuthURL(c, m, r), nil
}

// Identity is the person SPA signed in.
type Identity struct {
	Subject  string
	Username string
	Name     string
	Email    string
	Roles    []string
	Groups   []string
	Methods  []string // amr
	Admin    bool     // spa_admin (information only)
}

// Finish redeems the code with the PKCE verifier and verifies the ID token:
// the RS256 signature against the issuer's JWKS, iss, aud, exp and nonce.
func (k Key) Finish(ctx context.Context, redirect, code string, r oidcx.Request) (Identity, error) {
	m, err := oidcx.Discover(ctx, k.Issuer)
	if err != nil {
		return Identity{}, err
	}
	t, err := oidcx.Exchange(ctx, k.client(redirect), m, code, r)
	if err != nil {
		return Identity{}, err
	}
	if alg := oidcx.Algorithm(t.IDToken); alg != "RS256" {
		return Identity{}, fmt.Errorf("%w: algorithm %q", oidcx.ErrInvalidToken, alg)
	}
	// The issuer is the one of the key, not only the one the discovery names.
	m.Issuer = k.Issuer
	cl, err := oidcx.Verify(ctx, m, k.ClientID, t.IDToken, r.Nonce, time.Now())
	if err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: cl.String("sub"), Username: cl.String("preferred_username"), Name: cl.String("name"),
		Email: cl.String("email"), Roles: cl.Strings("roles"), Groups: cl.Strings("groups"), Methods: cl.Strings("amr"),
		Admin: cl.Bool("spa_admin")}
	if id.Subject == "" || id.Username == "" {
		return Identity{}, fmt.Errorf("%w: no sub or preferred_username", oidcx.ErrInvalidToken)
	}
	return id, nil
}

// Check tells whether SPA accepts the key: the discovery, the federation
// token (configuration) and the client secret (a token request with a
// made-up code is refused as invalid_grant for a known client and as
// invalid_client otherwise).
func (k Key) Check(ctx context.Context, redirect string) (Config, error) {
	m, err := oidcx.Discover(ctx, k.Issuer)
	if err != nil {
		return Config{}, err
	}
	cfg, _, _, err := k.Config(ctx, "")
	if err != nil {
		return Config{}, err
	}
	_, err = oidcx.Exchange(ctx, k.client(redirect), m, "check-"+oidcx.Random(), oidcx.NewRequest())
	switch {
	case err == nil:
		return cfg, errors.New("SPA accepted a made-up code")
	case strings.Contains(err.Error(), "invalid_client"):
		return cfg, errors.New("SPA refused the client secret: issue a new connection key in SPA")
	case strings.Contains(err.Error(), "invalid_grant"):
		return cfg, nil
	}
	return cfg, err
}

// SignOutURL is SPA's sign-out address that returns to back.
func SignOutURL(signOut, clientID, back string) string {
	if signOut == "" {
		return ""
	}
	q := url.Values{"client_id": {clientID}}
	if back != "" {
		q.Set("post_logout_redirect_uri", back)
	}
	sep := "?"
	if strings.Contains(signOut, "?") {
		sep = "&"
	}
	return signOut + sep + q.Encode()
}
