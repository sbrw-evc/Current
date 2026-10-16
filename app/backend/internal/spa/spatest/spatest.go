// Package spatest is a fake SPA for tests: an in-process OpenID Connect issuer
// (discovery, RS256 keys, authorize → code, token, user info, sign-out) and
// the federation API (config, users with ETags, the role catalogue).
package spatest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
	"github.com/sbrw-evc/network/app/backend/internal/spa"
)

// SPA is the fake. Change its fields between requests (under no lock: tests
// drive it from one goroutine).
type SPA struct {
	Server  *httptest.Server
	Key     spa.Key
	Users   []spa.User
	Methods []spa.Method
	// SignedIn is the ID of the user an authorization request signs in.
	SignedIn string
	// Requests are the query strings of the authorization requests.
	Requests []url.Values
	// Catalogue is the last role catalogue the application published, and
	// Published how many times it did.
	Catalogue *spa.Catalogue
	Published int

	// Tampering with the next ID tokens, for negative tests.
	Nonce    string // a nonce other than the one asked
	Audience string // an audience other than the client ID
	Issuer   string // an issuer other than the server
	Alg      string // "none" signs nothing

	mu    sync.Mutex
	key   *rsa.PrivateKey
	codes map[string]code
}

type code struct {
	user, nonce, challenge, redirect string
}

// New starts a fake SPA.
func New(t testing.TB) *SPA {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &SPA{key: k, codes: map[string]code{},
		Methods: []spa.Method{{ID: "passkey", Title: "Passkey"}, {ID: "ldap", Title: "Active Directory"}, {ID: "password", Title: "Password"}}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Server.Close)
	s.Key = spa.Key{Issuer: s.Server.URL, ClientID: "app_flow", ClientSecret: "secret-1", Token: "fed-token-1"}
	return s
}

// kid names the signing key of this fake. It differs between fakes: a later
// test can get the same address, and the verifier keeps the keys of an
// address for an hour, so a fixed kid would find a previous fake's key.
func (s *SPA) kid() string {
	h := sha256.Sum256(s.key.N.Bytes())
	return hex.EncodeToString(h[:8])
}

// ConnectionKey is the key SPA would show.
func (s *SPA) ConnectionKey() string { return s.Key.String() }

// AccountURL and SignOutURL are what the configuration names.
func (s *SPA) AccountURL() string { return s.Server.URL + "/profile" }
func (s *SPA) SignOutURL() string { return s.Server.URL + "/oauth2/logout" }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *SPA) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+s.Key.Token {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

func (s *SPA) etagged(w http.ResponseWriter, r *http.Request, v any) {
	if !s.authorized(w, r) {
		return
	}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	tag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *SPA) user(id string) (spa.User, bool) {
	for _, u := range s.Users {
		if u.ID == id {
			return u, true
		}
	}
	return spa.User{}, false
}

func (s *SPA) serve(w http.ResponseWriter, r *http.Request) {
	iss := s.Server.URL
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, 200, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/oauth2/authorize",
			"token_endpoint": iss + "/oauth2/token", "jwks_uri": iss + "/oauth2/jwks", "userinfo_endpoint": iss + "/oauth2/userinfo",
			"end_session_endpoint": iss + "/oauth2/logout", "id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported": []string{"S256"}})
	case "/oauth2/jwks":
		writeJSON(w, 200, map[string]any{"keys": []oidcx.JWK{oidcx.RSAJWK(s.kid(), &s.key.PublicKey)}})
	case "/oauth2/authorize":
		q := r.URL.Query()
		s.Requests = append(s.Requests, q)
		back := q.Get("redirect_uri")
		fail := func(e, d string) {
			http.Redirect(w, r, back+"?"+url.Values{"error": {e}, "error_description": {d}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
		}
		if q.Get("client_id") != s.Key.ClientID {
			http.Error(w, "unknown client", http.StatusBadRequest)
			return
		}
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
			fail("invalid_request", "PKCE S256 and a nonce are required")
			return
		}
		u, ok := s.user(s.SignedIn)
		if !ok || u.Disabled || len(u.Roles) == 0 {
			fail("access_denied", "you have no role in this application")
			return
		}
		c := oidcx.Random()
		s.codes[c] = code{user: u.ID, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: back}
		http.Redirect(w, r, back+"?"+url.Values{"code": {c}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	case "/oauth2/token":
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != s.Key.ClientID || secret != s.Key.ClientSecret {
			writeJSON(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		c, ok := s.codes[r.PostForm.Get("code")]
		delete(s.codes, r.PostForm.Get("code"))
		if !ok || c.redirect != r.PostForm.Get("redirect_uri") || oidcx.Challenge(r.PostForm.Get("code_verifier")) != c.challenge {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		u, _ := s.user(c.user)
		now := time.Now()
		claims := map[string]any{"iss": iss, "aud": s.Key.ClientID, "sub": u.ID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"auth_time": now.Unix(), "sid": "sid-" + u.ID, "nonce": c.nonce, "preferred_username": u.Username, "name": u.Name,
			"email": u.Email, "email_verified": true, "roles": u.Roles, "groups": u.Groups, "amr": []string{"hwk", "user"}}
		if s.Nonce != "" {
			claims["nonce"] = s.Nonce
		}
		if s.Audience != "" {
			claims["aud"] = s.Audience
		}
		if s.Issuer != "" {
			claims["iss"] = s.Issuer
		}
		tok, _ := oidcx.Sign(s.key, s.kid(), claims)
		if s.Alg == "none" {
			b, _ := json.Marshal(claims)
			tok = "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + "."
		}
		writeJSON(w, 200, map[string]any{"id_token": tok, "access_token": "at-" + u.ID, "token_type": "Bearer", "expires_in": 600})
	case "/oauth2/logout":
		if back := r.URL.Query().Get("post_logout_redirect_uri"); back != "" {
			http.Redirect(w, r, back, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case "/api/spa/v1/config":
		roles := []spa.Role{}
		if s.Catalogue != nil {
			roles = s.Catalogue.Roles
		}
		s.etagged(w, r, map[string]any{"application": map[string]string{"id": s.Key.ClientID, "name": "Umbrella Flow", "type": "umbrella-flow"},
			"roles": roles, "methods": s.Methods, "sign_out_url": s.SignOutURL(), "account_url": s.AccountURL()})
	case "/api/spa/v1/users":
		users := s.Users
		if users == nil {
			users = []spa.User{}
		}
		s.etagged(w, r, map[string]any{"users": users})
	case "/api/spa/v1/roles":
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !s.authorized(w, r) {
			return
		}
		var c spa.Catalogue
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil || len(c.Roles) == 0 {
			writeJSON(w, 400, map[string]string{"error": "invalid_catalogue"})
			return
		}
		for _, role := range c.Roles {
			if !spa.RoleIDRe.MatchString(role.ID) || role.Name == "" {
				writeJSON(w, 400, map[string]string{"error": "invalid_role", "message": role.ID})
				return
			}
		}
		if c.Default != "" && !slices.ContainsFunc(c.Roles, func(r spa.Role) bool { return r.ID == c.Default }) {
			writeJSON(w, 400, map[string]string{"error": "invalid_default"})
			return
		}
		s.Catalogue = &c
		s.Published++
		writeJSON(w, 200, map[string]any{"roles": len(c.Roles)})
	default:
		http.NotFound(w, r)
	}
}
