// Package entratest is a small Microsoft Entra ID (OpenID Connect provider)
// and Microsoft Graph stand-in for tests, ported from Umbrella Monitoring.
package entratest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/entra"
)

const (
	Cloud    = "test"
	TenantID = "11111111-2222-3333-4444-555555555555"
	ClientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	Secret   = "entra-client-secret"
)

type User struct {
	ObjectID      string
	Username      string
	Name          string
	Groups        []string
	GroupsInToken bool
}

type Server struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu    sync.Mutex
	User  User
	codes map[string]grant
	// Nonce, when set, replaces the nonce in the next ID token.
	Nonce string
}

type grant struct {
	user      User
	nonce     string
	challenge string
	redirect  string
}

// Start runs the stand-in and registers it as the "test" cloud.
func Start(t *testing.T) *Server {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{key: key, codes: map[string]grant{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	entra.Clouds[Cloud] = entra.Cloud{Login: s.URL, Graph: s.URL}
	t.Cleanup(func() { delete(entra.Clouds, Cloud) })
	return s
}

func (s *Server) Issuer() string { return s.URL + "/" + TenantID + "/v2.0" }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/v2.0/.well-known/openid-configuration"):
		tenant := strings.Split(strings.Trim(p, "/"), "/")[0]
		if tenant != TenantID && tenant != "contoso.onmicrosoft.com" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_tenant"})
			return
		}
		base := s.URL + "/" + TenantID
		writeJSON(w, http.StatusOK, map[string]string{"issuer": s.Issuer(), "authorization_endpoint": base + "/oauth2/v2.0/authorize",
			"token_endpoint": base + "/oauth2/v2.0/token", "jwks_uri": base + "/discovery/v2.0/keys"})
	case strings.HasSuffix(p, "/discovery/v2.0/keys"):
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes())}}})
	case strings.HasSuffix(p, "/oauth2/v2.0/authorize"):
		s.authorize(w, r)
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		s.token(w, r)
	case strings.HasPrefix(p, "/v1.0/"):
		s.graph(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authorize signs the current user in at once, as if they had entered their password.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := strings.ToLower(rand.Text())
	s.mu.Lock()
	s.codes[code] = grant{user: s.User, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	s.mu.Unlock()
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	if f.Get("client_id") != ClientID || f.Get("client_secret") != Secret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"})
		return
	}
	switch f.Get("grant_type") {
	case "client_credentials":
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "app-token", "token_type": "Bearer"})
		return
	case "authorization_code":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	s.mu.Lock()
	g, ok := s.codes[f.Get("code")]
	delete(s.codes, f.Get("code"))
	nonce := g.nonce
	if s.Nonce != "" {
		nonce, s.Nonce = s.Nonce, ""
	}
	s.mu.Unlock()
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !ok || g.redirect != f.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	c := map[string]any{"iss": s.Issuer(), "aud": ClientID, "exp": now.Add(time.Hour).Unix(), "nbf": now.Unix(), "iat": now.Unix(),
		"nonce": nonce, "tid": TenantID, "oid": g.user.ObjectID, "preferred_username": g.user.Username, "name": g.user.Name}
	if g.user.GroupsInToken {
		c["groups"] = g.user.Groups
	}
	access := "user:" + g.user.ObjectID
	s.mu.Lock()
	s.codes[access] = g
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id_token": s.Sign(c), "access_token": access, "token_type": "Bearer"})
}

// Sign makes an RS256 JWT with the server key.
func (s *Server) Sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	b, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	g, ok := s.codes[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "InvalidAuthenticationToken", "message": "Access token is empty."}})
		return
	}
	u := g.user
	switch r.URL.Path {
	case "/v1.0/me":
		writeJSON(w, http.StatusOK, map[string]string{"displayName": u.Name, "mail": u.Username, "userPrincipalName": u.Username})
	case "/v1.0/me/transitiveMemberOf/microsoft.graph.group":
		s.groupPage(w, r, u)
	default:
		http.NotFound(w, r)
	}
}

// groupPage lists one group per page, to exercise paging.
func (s *Server) groupPage(w http.ResponseWriter, r *http.Request, u User) {
	i := 0
	if v := r.URL.Query().Get("page"); v != "" {
		i = int(v[0] - '0')
	}
	out := map[string]any{"value": []map[string]string{}}
	if i < len(u.Groups) {
		out["value"] = []map[string]string{{"id": u.Groups[i]}}
		if i+1 < len(u.Groups) {
			out["@odata.nextLink"] = s.URL + r.URL.Path + "?page=" + string(rune('0'+i+1))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
