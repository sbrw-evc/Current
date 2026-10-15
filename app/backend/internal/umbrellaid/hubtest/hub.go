// Package hubtest is a fake Umbrella Identity hub for tests: OpenID Connect
// discovery, keys, authorization (the browser is signed in as Hub.SignedIn at
// once), token, and the federation API with ETags.
package hubtest

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
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/oidcx"
	"github.com/sbrw-evc/network/app/backend/internal/umbrellaid"
)

type Hub struct {
	Server   *httptest.Server
	Key      umbrellaid.Key
	Policy   map[string]any
	Passkeys map[string]any
	Methods  []umbrellaid.Method
	Users    []umbrellaid.User
	// SignedIn is the hub user an authorization request signs in.
	SignedIn string
	// Hints are the idp_hint values the hub was asked for.
	Hints []string

	mu    sync.Mutex
	key   *rsa.PrivateKey
	codes map[string]code
}

type code struct {
	user, nonce, challenge, redirect string
}

func New(t *testing.T) *Hub {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	h := &Hub{key: k, codes: map[string]code{}, Policy: map[string]any{"min_length": 14, "require_digits": true, "min_digits": 2,
		"require_special": true, "min_special": 1, "require_mixed_case": true, "letters": "latin", "history_count": 5,
		"block_common": true, "lockout_attempts": 6, "lockout_minutes": 30},
		Passkeys: map[string]any{"enabled": true, "rp_id": "example.com"},
		Methods:  []umbrellaid.Method{{ID: "passkey", Title: "Passkey"}, {ID: "ldap", Title: "Active Directory"}, {ID: "local", Title: "Umbrella"}}}
	h.Server = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.Server.Close)
	h.Key = umbrellaid.Key{Hub: h.Server.URL, ClientID: "umb-test", ClientSecret: "secret-1", Token: "umb_token-1"}
	return h
}

// ConnectionKey is the key the hub would show.
func (h *Hub) ConnectionKey() string {
	b, _ := json.Marshal(h.Key)
	return umbrellaid.KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Hub) etagged(w http.ResponseWriter, r *http.Request, v any) {
	if r.Header.Get("Authorization") != "Bearer "+h.Key.Token {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

func (h *Hub) serve(w http.ResponseWriter, r *http.Request) {
	iss := h.Server.URL
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, 200, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/oauth2/authorize", "token_endpoint": iss + "/oauth2/token",
			"jwks_uri": iss + "/oauth2/jwks", "userinfo_endpoint": iss + "/oauth2/userinfo"})
	case "/oauth2/jwks":
		writeJSON(w, 200, map[string]any{"keys": []oidcx.JWK{oidcx.RSAJWK("k1", &h.key.PublicKey)}})
	case "/oauth2/authorize":
		q := r.URL.Query()
		h.Hints = append(h.Hints, q.Get("idp_hint"))
		c := oidcx.Random()
		h.codes[c] = code{user: h.SignedIn, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {c}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	case "/oauth2/token":
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != h.Key.ClientID || secret != h.Key.ClientSecret {
			writeJSON(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		c, ok := h.codes[r.PostForm.Get("code")]
		delete(h.codes, r.PostForm.Get("code"))
		if !ok || c.redirect != r.PostForm.Get("redirect_uri") || oidcx.Challenge(r.PostForm.Get("code_verifier")) != c.challenge {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		var u umbrellaid.User
		for _, x := range h.Users {
			if x.ID == c.user {
				u = x
			}
		}
		now := time.Now()
		claims := map[string]any{"iss": iss, "aud": h.Key.ClientID, "sub": u.ID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"nonce": c.nonce, "preferred_username": u.Username, "name": u.Name, "email": u.Email, "groups": u.Groups,
			"umbrella_role": u.Role, "umbrella_admin": u.Admin, "amr": []string{"hwk", "user"}}
		tok, _ := oidcx.Sign(h.key, "k1", claims)
		writeJSON(w, 200, map[string]any{"id_token": tok, "access_token": "at", "token_type": "Bearer", "expires_in": 600})
	case "/api/identity/v1/config":
		h.etagged(w, r, map[string]any{"version": 1, "issuer": iss, "application": map[string]any{"id": "APP-1", "name": "Umbrella Flow", "sync_passkeys": true},
			"password_policy": h.Policy, "passkeys": h.Passkeys, "methods": h.Methods})
	case "/api/identity/v1/users":
		h.etagged(w, r, map[string]any{"users": h.Users})
	default:
		http.NotFound(w, r)
	}
}
