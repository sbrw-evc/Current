// Package umbrellaid is the member side of Umbrella Identity
// (docs/identity-federation.md): the connection key, single sign-in through
// the Umbrella Monitoring hub (OpenID Connect with PKCE and idp_hint) and the
// federation API (configuration and users with ETags).
package umbrellaid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
)

// KeyPrefix starts a connection key.
const KeyPrefix = "umbid1."

// CallbackPath is where the hub sends the browser back.
const CallbackPath = "/api/auth/umbrella/callback"

// Key is the connection key made by the hub for this application.
type Key struct {
	Hub          string `json:"hub"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Token        string `json:"token"`
}

var ErrKey = errors.New("this is not an Umbrella connection key: copy it again from Umbrella Monitoring → Settings → Sign-in and Umbrella Identity")

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
	if err := json.Unmarshal(b, &k); err != nil || k.Hub == "" || k.ClientID == "" || k.ClientSecret == "" || k.Token == "" {
		return Key{}, ErrKey
	}
	u, err := url.Parse(k.Hub)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Key{}, ErrKey
	}
	k.Hub = strings.TrimRight(k.Hub, "/")
	return k, nil
}

// Timeout bounds every call to the hub.
var Timeout = 20 * time.Second

func client() *http.Client { return &http.Client{Timeout: Timeout} }

// Method is a sign-in method of the hub.
type Method struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Config is GET /api/identity/v1/config.
type Config struct {
	Version     int    `json:"version"`
	Issuer      string `json:"issuer"`
	Application struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		SyncPasskeys bool   `json:"sync_passkeys"`
	} `json:"application"`
	Policy   json.RawMessage `json:"password_policy"`
	Passkeys struct {
		Enabled bool   `json:"enabled"`
		RPID    string `json:"rp_id"`
	} `json:"passkeys"`
	Methods []Method `json:"methods"`
}

// User is a person of the hub.
type User struct {
	ID        string            `json:"id"`
	Username  string            `json:"username"`
	Email     string            `json:"email"`
	Name      string            `json:"name"`
	FirstName string            `json:"first_name"`
	LastName  string            `json:"last_name"`
	Source    string            `json:"source"`
	Disabled  bool              `json:"disabled"`
	Role      map[string]string `json:"role"`
	Admin     bool              `json:"admin"`
	Groups    []string          `json:"groups"`
	Teams     []string          `json:"teams"`
	Passkeys  []Passkey         `json:"passkeys"`
}

// RoleName is the name of the hub role.
func (u User) RoleName() string { return u.Role["name"] }

// Passkey is a passkey of a hub user (binary fields in base64url).
type Passkey struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	CredentialID   string    `json:"credential_id"`
	PublicKey      string    `json:"public_key"`
	UserHandle     string    `json:"user_handle"`
	SignCount      uint32    `json:"sign_count"`
	AAGUID         string    `json:"aaguid"`
	Transports     []string  `json:"transports"`
	BackupEligible bool      `json:"backup_eligible"`
	CreatedAt      time.Time `json:"created_at"`
}

// HTTPError is an answer of the hub that is not 200 / 304.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "Umbrella refused the synchronization token: issue a new connection key"
	case http.StatusForbidden:
		return "Umbrella refused access"
	}
	return fmt.Sprintf("Umbrella answered HTTP %d %s", e.Status, e.Body)
}

// get reads a federation document. With a matching etag it answers
// notModified.
func (k Key) get(ctx context.Context, path, etag string, out any) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.Hub+path, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+k.Token)
	req.Header.Set("Accept", "application/json")
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
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return "", false, &HTTPError{Status: res.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(out); err != nil {
		return "", false, fmt.Errorf("Umbrella answer: %w", err)
	}
	return res.Header.Get("ETag"), false, nil
}

// Config reads the configuration of the application.
func (k Key) Config(ctx context.Context, etag string) (Config, string, bool, error) {
	var c Config
	tag, same, err := k.get(ctx, "/api/identity/v1/config", etag, &c)
	return c, tag, same, err
}

// Users reads the people of the application.
func (k Key) Users(ctx context.Context, etag string) ([]User, string, bool, error) {
	var doc struct {
		Users []User `json:"users"`
	}
	tag, same, err := k.get(ctx, "/api/identity/v1/users", etag, &doc)
	return doc.Users, tag, same, err
}

// CheckSecret tells whether the hub accepts the client secret: a token request
// with a wrong code is refused as invalid_grant for a known client and as
// invalid_client otherwise.
func (k Key) CheckSecret(ctx context.Context, redirect string) error {
	m, err := oidcx.Discover(ctx, k.Hub)
	if err != nil {
		return err
	}
	_, err = oidcx.Exchange(ctx, k.client(redirect), m, "check-"+oidcx.Random(), oidcx.NewRequest())
	if err == nil {
		return errors.New("Umbrella accepted a made-up code")
	}
	if strings.Contains(err.Error(), "invalid_client") {
		return errors.New("Umbrella refused the client secret: issue a new connection key")
	}
	if strings.Contains(err.Error(), "invalid_grant") {
		return nil
	}
	return err
}

func (k Key) client(redirect string) oidcx.Client {
	return oidcx.Client{Issuer: k.Hub, ClientID: k.ClientID, Secret: k.ClientSecret, RedirectURI: redirect,
		Scopes: []string{"openid", "profile", "email", "groups"}, Extra: url.Values{}}
}

// AuthURL starts single sign-in; hint is the hub method to start at once.
func (k Key) AuthURL(ctx context.Context, redirect, hint string, r oidcx.Request) (string, error) {
	m, err := oidcx.Discover(ctx, k.Hub)
	if err != nil {
		return "", err
	}
	c := k.client(redirect)
	if hint != "" {
		c.Extra.Set("idp_hint", hint)
	}
	return oidcx.AuthURL(c, m, r), nil
}

// Identity is the person the hub signed in.
type Identity struct {
	Subject  string
	Username string
	Name     string
	Email    string
	Role     string
	Admin    bool
	Groups   []string
	Methods  []string
}

// Finish redeems the code and verifies the ID token.
func (k Key) Finish(ctx context.Context, redirect, code string, r oidcx.Request) (Identity, error) {
	m, err := oidcx.Discover(ctx, k.Hub)
	if err != nil {
		return Identity{}, err
	}
	t, err := oidcx.Exchange(ctx, k.client(redirect), m, code, r)
	if err != nil {
		return Identity{}, err
	}
	cl, err := oidcx.Verify(ctx, m, k.ClientID, t.IDToken, r.Nonce, time.Now())
	if err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: cl.String("sub"), Username: cl.String("preferred_username"), Name: cl.String("name"),
		Email: cl.String("email"), Admin: cl.Bool("umbrella_admin"), Groups: cl.Strings("groups"), Methods: cl.Strings("amr")}
	if role, ok := cl["umbrella_role"].(map[string]any); ok {
		id.Role, _ = role["name"].(string)
	}
	if id.Subject == "" || id.Username == "" {
		return Identity{}, oidcx.ErrInvalidToken
	}
	return id, nil
}
