// Package secretstest is an in-memory fake OpenBao for tests.
package secretstest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

const (
	RoleID   = "role-1"
	SecretID = "secret-1"
	token    = "s.test-token"
)

type Fake struct {
	Server *httptest.Server
	mu     sync.Mutex
	data   map[string]map[string]any
	Sealed bool
	Logins int
}

func New(t *testing.T) (*Fake, *secrets.Client) {
	t.Helper()
	f := &Fake{data: map[string]map[string]any{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	c, err := secrets.New(secrets.Config{Addr: f.Server.URL, RoleID: RoleID, SecretID: SecretID})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *Fake) Get(path string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[path]
}

func (f *Fake) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.data))
	for k := range f.data {
		out = append(out, k)
	}
	return out
}

func (f *Fake) Set(path string, v map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[path] = v
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if p == "sys/health" {
		reply(200, map[string]any{"initialized": true, "sealed": f.Sealed, "version": "2.7.1"})
		return
	}
	if f.Sealed {
		reply(503, map[string]any{"errors": []string{"Vault is sealed"}})
		return
	}
	if p == "auth/approle/login" {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != RoleID || body["secret_id"] != SecretID {
			reply(400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		f.Logins++
		reply(200, map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": 3600, "renewable": true, "policies": []string{"flow"}}})
		return
	}
	if r.Header.Get("X-Vault-Token") != token {
		reply(403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	switch {
	case p == "auth/token/lookup-self":
		reply(200, map[string]any{"data": map[string]any{"ttl": 3600, "renewable": true, "policies": []string{"flow"}}})
	case p == "auth/token/renew-self":
		reply(200, map[string]any{"auth": map[string]any{"lease_duration": 3600, "renewable": true}})
	case strings.HasPrefix(p, "sys/internal/ui/mounts/"):
		reply(200, map[string]any{"data": map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}})
	case strings.Contains(p, "/metadata/") && r.Method == http.MethodGet && r.URL.Query().Get("list") == "true":
		mount, prefix, _ := strings.Cut(p, "/metadata/")
		keys := f.keysUnder(mount + "/" + prefix)
		if len(keys) == 0 {
			reply(404, map[string]any{"errors": []string{}})
			return
		}
		reply(200, map[string]any{"data": map[string]any{"keys": keys}})
	case strings.Contains(p, "/data/"):
		mount, path, _ := strings.Cut(p, "/data/")
		key := mount + "/" + path
		switch r.Method {
		case http.MethodGet:
			d, ok := f.data[key]
			if !ok {
				reply(404, map[string]any{"errors": []string{}})
				return
			}
			reply(200, map[string]any{"data": map[string]any{"data": d}})
		case http.MethodPost, http.MethodPut:
			var body struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.data[key] = body.Data
			reply(200, map[string]any{"data": map[string]any{"version": 1}})
		}
	case strings.Contains(p, "/metadata/") && r.Method == http.MethodDelete:
		mount, path, _ := strings.Cut(p, "/metadata/")
		delete(f.data, mount+"/"+path)
		w.WriteHeader(204)
	default:
		reply(404, map[string]any{"errors": []string{}})
	}
}

func (f *Fake) keysUnder(prefix string) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range f.data {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok || rest == "" {
			continue
		}
		if dir, _, nested := strings.Cut(rest, "/"); nested {
			rest = dir + "/"
		}
		if !seen[rest] {
			seen[rest] = true
			keys = append(keys, rest)
		}
	}
	return keys
}
