package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

type fakeVisualizer struct{}

func (fakeVisualizer) Visualize(_ context.Context, req json.RawMessage) (any, error) {
	var in struct{ Limit int }
	_ = json.Unmarshal(req, &in)
	if in.Limit > 50 {
		return nil, httpx.BadRequest("invalid_limit", "limit must be 1-50")
	}
	return map[string]any{"rows": [][]string{{"Total"}}}, nil
}

// fakeDetector accepts rules with an id and kind; SendTest posts like the setup check.
type fakeDetector struct{}

func (fakeDetector) DefaultRules() []json.RawMessage {
	return []json.RawMessage{json.RawMessage(`{"id":"link-utilization","kind":"link_utilization","enabled":true}`)}
}

func (fakeDetector) ValidateRule(raw json.RawMessage) (string, error) {
	var r struct{ ID, Kind string }
	if err := json.Unmarshal(raw, &r); err != nil || r.ID == "" || r.Kind == "" {
		return r.ID, errors.New("id and kind are required")
	}
	return r.ID, nil
}

func (fakeDetector) Status(context.Context) (any, error) {
	return map[string]any{"rules": []any{}, "alerts": []any{}, "queued": 0}, nil
}

func (fakeDetector) SendTest(ctx context.Context, url, token string) (any, error) {
	if c := setup.CheckUmbrella(ctx, url, token); !c.OK {
		return nil, errors.New(c.Error)
	}
	return map[string]any{"id": "test"}, nil
}

type fakeClassifiers struct{}

func (fakeClassifiers) Validate(kind string, rules []string) error {
	for _, r := range rules {
		if strings.Contains(r, "syntax error") {
			return errors.New("rule 1: syntax error")
		}
	}
	return nil
}

func (fakeClassifiers) Preview(_ context.Context, kind string, rules []string, sample json.RawMessage) (any, error) {
	return map[string]any{"kind": kind, "rules": len(rules)}, nil
}

type reloads []string

func (r *reloads) Reload(_ context.Context, what string) error { *r = append(*r, what); return nil }

type env struct {
	t     *testing.T
	srv   *httptest.Server
	st    *store.Store
	fake  *secretstest.Fake
	rel   *reloads
	admin store.User
	view  store.User
}

func newEnv(t *testing.T) *env {
	t.Helper()
	auth.Iterations = 1000
	st := storetest.New(t)
	fake, vault := secretstest.New(t)
	ctx := context.Background()
	adminRole, _ := st.RoleByName(ctx, access.RoleAdministrator)
	viewerRole, _ := st.RoleByName(ctx, access.RoleViewer)
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	mk := func(name, password string, roleID int64) store.User {
		u, err := st.CreateUser(ctx, store.NewUser{Username: name, Name: name, RoleID: roleID})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := auth.NewPasswords(vault).Set(ctx, u.ID, password)
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SetPasswordRef(ctx, u.ID, ref)
		u.PasswordRef = ref
		return u
	}
	admin := mk("admin", "admin-password", adminRole.ID)
	viewer := mk("viewer", "viewer-password", viewerRole.ID)
	rel := &reloads{}
	a := New(Options{Version: "test"}, Deps{Store: st, Vault: vault, Visualizer: fakeVisualizer{}, Classifiers: fakeClassifiers{},
		Detector: fakeDetector{}, Reloaders: []Reloader{rel}})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, fake: fake, rel: rel, admin: admin, view: viewer}
}

type client struct {
	e    *env
	http *http.Client
	csrf string
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, rd)
	if c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

func (c *client) login(user, password string) {
	c.e.t.Helper()
	code, out := c.do("POST", "/api/auth/login", map[string]string{"username": user, "password": password})
	if code != 200 {
		c.e.t.Fatalf("login %s: %d %v", user, code, out)
	}
	c.csrf = out["csrf"].(string)
}

func TestServiceEndpoints(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if code, out := c.do("GET", "/healthz", nil); code != 200 || out["_raw"] != "ok" {
		t.Fatal(code, out)
	}
	if code, out := c.do("GET", "/api/version", nil); code != 200 || out["version"] != "test" {
		t.Fatal(code, out)
	}
	if code, out := c.do("GET", "/metrics", nil); code != 200 || !strings.Contains(out["_raw"].(string), "go_goroutines") {
		t.Fatal(code)
	}
	if code, _ := c.do("GET", "/api/setup", nil); code != 404 {
		t.Fatal("setup endpoints must be gone after setup", code)
	}
	if code, out := c.do("GET", "/api/schema", nil); code != 401 || out["error"] != "unauthorized" {
		t.Fatal(code, out)
	}
	if code, out := c.do("GET", "/api/nothing", nil); code != 404 || out["error"] != "not_found" {
		t.Fatal(code, out)
	}
}

func TestLoginAndLockout(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if code, out := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong"}); code != 401 || out["error"] != "invalid_credentials" {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/auth/login", map[string]string{"username": "nobody", "password": "wrong"}); code != 401 {
		t.Fatal(code)
	}
	c.login("ADMIN", "admin-password")
	code, out := c.do("GET", "/api/auth/me", nil)
	if code != 200 || out["csrf"] != c.csrf {
		t.Fatal(code, out)
	}
	user := out["user"].(map[string]any)
	if user["username"] != "admin" || user["role"] != access.RoleAdministrator || len(user["permissions"].([]any)) != len(access.BuiltinRoles()[0].Permissions) {
		t.Fatal(user)
	}
	if code, out := c.do("GET", "/api/schema", nil); code != 200 || len(out["columns"].([]any)) == 0 {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/auth/logout", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("session survived logout", code)
	}

	// lockout: 5 failures lock the user name even with the right password
	v := e.client()
	for i := 0; i < 5; i++ {
		v.do("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "nope"})
	}
	if code, out := v.do("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "viewer-password"}); code != 429 || out["error"] != "too_many_attempts" {
		t.Fatal(code, out)
	}
}

func TestCSRFAndPermissions(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	viewer := e.client()
	viewer.login("viewer", "viewer-password")

	view := map[string]any{"name": "Top AS", "shared": true, "request": map[string]any{"dimensions": []string{"SrcAS"}}}
	csrf := admin.csrf
	admin.csrf = ""
	if code, out := admin.do("POST", "/api/saved-views", view); code != 403 || out["error"] != "csrf" {
		t.Fatal(code, out)
	}
	admin.csrf = "wrong"
	if code, _ := admin.do("POST", "/api/saved-views", view); code != 403 {
		t.Fatal(code)
	}
	admin.csrf = csrf
	code, created := admin.do("POST", "/api/saved-views", view)
	if code != 201 || created["owner"] != "admin" {
		t.Fatal(code, created)
	}
	id := int(created["id"].(float64))

	// viewer sees the shared view but cannot delete it
	if code, out := viewer.do("GET", "/api/saved-views", nil); code != 200 || len(out["results"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	if code, _ := viewer.do("DELETE", "/api/saved-views/"+itoa(id), nil); code != 403 {
		t.Fatal(code)
	}
	if code, _ := admin.do("DELETE", "/api/saved-views/"+itoa(id), nil); code != 200 {
		t.Fatal(code)
	}

	// permissions
	for path, want := range map[string]int{"/api/users": 403, "/api/roles": 403, "/api/inventory-db": 403, "/api/classifiers": 403,
		"/api/status": 403, "/api/exporters": 501, "/api/widgets/summary": 501, "/api/sampling-overrides": 200} {
		if code, out := viewer.do("GET", path, nil); code != want {
			t.Errorf("viewer GET %s: %d %v, want %d", path, code, out, want)
		}
	}
	for path, want := range map[string]int{"/api/users": 200, "/api/roles": 200, "/api/inventory-db": 200, "/api/classifiers": 200,
		"/api/status": 200, "/api/audit": 200, "/api/settings/ldap": 200, "/api/access/catalog": 200} {
		if code, out := admin.do("GET", path, nil); code != want {
			t.Errorf("admin GET %s: %d %v, want %d", path, code, out, want)
		}
	}
	if code, _ := viewer.do("PUT", "/api/sampling-overrides", map[string]any{"results": []any{}}); code != 403 {
		t.Fatal(code)
	}

	// traffic through Deps
	if code, out := viewer.do("POST", "/api/visualize", map[string]any{"limit": 10}); code != 200 || out["rows"] == nil {
		t.Fatal(code, out)
	}
	if code, out := viewer.do("POST", "/api/visualize", map[string]any{"limit": 100}); code != 400 || out["error"] != "invalid_limit" {
		t.Fatal(code, out)
	}
	if code, out := viewer.do("POST", "/api/flows/search", map[string]any{}); code != 501 || out["error"] != "not_implemented" {
		t.Fatal(code, out)
	}
	if code, _ := viewer.do("POST", "/api/filter/validate", map[string]any{"filter": ""}); code != 501 {
		t.Fatal(code)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestSettings(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")

	// Inventory DB: the token goes to OpenBao
	code, out := admin.do("PUT", "/api/inventory-db", map[string]any{"enabled": true, "url": "https://inventory.example/", "token": "xc-123", "interval": "10m"})
	if code != 200 || out["token_set"] != true || out["interval"] != "10m" || out["url"] != "https://inventory.example" {
		t.Fatal(code, out)
	}
	if e.fake.Get("flow/inventory-db")["token"] != "xc-123" {
		t.Fatal("token not in OpenBao")
	}
	inv, _ := e.st.InventoryDB(context.Background())
	if inv.TokenRef != "openbao://flow/inventory-db#token" {
		t.Fatal(inv.TokenRef)
	}
	if code, out := admin.do("PUT", "/api/inventory-db", map[string]any{"enabled": true, "url": "https://inventory.example", "interval": 300}); code != 200 || out["token_set"] != true {
		t.Fatal("token kept", code, out)
	}
	if code, _ := admin.do("POST", "/api/inventory-db/sync", nil); code != 501 {
		t.Fatal(code)
	}

	// classifiers
	rules := map[string]any{"exporter": []string{`exporter.name.startsWith("edge") ? {"role": "edge"} : {}`, " "}, "interface": []string{}}
	code, out = admin.do("PUT", "/api/classifiers", rules)
	if code != 200 || len(out["exporter"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/classifiers", map[string]any{"exporter": []string{"syntax error"}}); code != 400 || out["error"] != "invalid_rule" {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/classifiers", map[string]any{"bogus": []string{}}); code != 400 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/classifiers/preview", map[string]any{"kind": "exporter", "rules": []string{"x"}, "sample": map[string]any{}}); code != 200 || out["rules"] != float64(1) {
		t.Fatal(code, out)
	}
	if code, _ := admin.do("PUT", "/api/sampling-overrides", map[string]any{"results": []any{map[string]any{"exporter": "192.0.2.1", "rate": 1000}}}); code != 200 {
		t.Fatal(code)
	}
	if strings.Join(*e.rel, ",") != "inventory,inventory,classifiers,sampling" {
		t.Fatal(*e.rel)
	}
}

func TestUsersAndRoles(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	ctx := context.Background()
	adminRole, _ := e.st.RoleByName(ctx, access.RoleAdministrator)
	viewerRole, _ := e.st.RoleByName(ctx, access.RoleViewer)

	// the last administrator cannot be disabled, demoted or delete themselves
	if code, out := admin.do("PUT", "/api/users/"+itoa(int(e.admin.ID)), map[string]any{"disabled": true}); code != 409 || out["error"] != "last_admin" {
		t.Fatal(code, out)
	}
	if code, _ := admin.do("PUT", "/api/users/"+itoa(int(e.admin.ID)), map[string]any{"role_id": viewerRole.ID}); code != 409 {
		t.Fatal(code)
	}
	if code, _ := admin.do("DELETE", "/api/users/"+itoa(int(e.admin.ID)), nil); code != 409 {
		t.Fatal(code)
	}
	if code, _ := admin.do("PUT", "/api/roles/"+itoa(int(adminRole.ID)), map[string]any{"name": "x"}); code != 409 {
		t.Fatal("built-in role changed", code)
	}

	// a custom role and a user with it
	code, role := admin.do("POST", "/api/roles", map[string]any{"name": "NOC", "permissions": []string{"settings.inventory:sync", "flows:view"}})
	if code != 201 || len(role["permissions"].([]any)) != 3 {
		t.Fatal(code, role)
	}
	if code, out := admin.do("POST", "/api/roles", map[string]any{"name": "Bad", "permissions": []string{"nope:x"}}); code != 400 {
		t.Fatal(code, out)
	}
	code, u := admin.do("POST", "/api/users", map[string]any{"username": "noc1", "password": "noc-password", "role_id": role["id"]})
	if code != 201 || u["role"] != "NOC" {
		t.Fatal(code, u)
	}
	noc := e.client()
	noc.login("noc1", "noc-password")
	if code, _ := noc.do("GET", "/api/inventory-db", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := noc.do("PUT", "/api/inventory-db", map[string]any{}); code != 403 {
		t.Fatal(code)
	}
	if code, _ := admin.do("DELETE", "/api/roles/"+itoa(int(role["id"].(float64))), nil); code != 409 {
		t.Fatal("role in use deleted", code)
	}

	// password reset ends the user's sessions; disabling too
	if code, _ := admin.do("PUT", "/api/users/"+itoa(int(u["id"].(float64)))+"/password", map[string]any{"password": "short"}); code != 400 {
		t.Fatal(code)
	}
	if code, _ := admin.do("PUT", "/api/users/"+itoa(int(u["id"].(float64)))+"/password", map[string]any{"password": "new-noc-password"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := noc.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("session survived password reset", code)
	}
	noc.login("noc1", "new-noc-password")
	if code, _ := admin.do("PUT", "/api/users/"+itoa(int(u["id"].(float64))), map[string]any{"disabled": true}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := noc.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("disabled user kept the session", code)
	}
	if code, out := noc.do("POST", "/api/auth/login", map[string]string{"username": "noc1", "password": "new-noc-password"}); code != 403 || out["error"] != "user_disabled" {
		t.Fatal(code, out)
	}

	// own password change
	if code, _ := admin.do("POST", "/api/auth/password", map[string]any{"current": "wrong", "new": "another-password"}); code != 403 {
		t.Fatal(code)
	}
	if code, _ := admin.do("POST", "/api/auth/password", map[string]any{"current": "admin-password", "new": "another-password"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := admin.do("GET", "/api/auth/me", nil); code != 200 {
		t.Fatal("own session ended by own password change", code)
	}

	// LDAP settings: the bind password goes to OpenBao
	code, out := admin.do("PUT", "/api/settings/ldap", map[string]any{"enabled": true, "url": "ldap://dc.example.com", "bind_dn": "cn=svc,dc=example,dc=com",
		"base_dn": "dc=example,dc=com", "bind_password": "bind-pw", "default_role_id": viewerRole.ID,
		"group_roles": []any{map[string]any{"group_dn": "CN=Flow Admins,DC=example,DC=com", "role_id": adminRole.ID}}})
	if code != 200 || out["bind_password_set"] != true || out["bind_password_ref"] != nil {
		t.Fatal(code, out)
	}
	if e.fake.Get("flow/ldap")["bind_password"] != "bind-pw" {
		t.Fatal("bind password not in OpenBao")
	}
	ls, _ := (&App{st: e.st}).ldapSettings(ctx)
	if id, _ := (&App{st: e.st}).directoryRole(ctx, ls, []string{"cn=flow admins,dc=example,dc=com"}); id != adminRole.ID {
		t.Fatal("group mapping", id)
	}
	if id, _ := (&App{st: e.st}).directoryRole(ctx, ls, nil); id != viewerRole.ID {
		t.Fatal("default role", id)
	}

	if code, out := admin.do("GET", "/api/audit", nil); code != 200 || len(out["results"].([]any)) < 5 {
		t.Fatal(code, out)
	}
}

func TestGeneralUmbrellaOpenBao(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	code, out := admin.do("GET", "/api/settings/general", nil)
	if code != 200 || out["language"] != "ru" || out["password_policy"].(map[string]any)["min_length"] != float64(12) {
		t.Fatal(code, out)
	}
	code, out = admin.do("PUT", "/api/settings/general", map[string]any{"language": "en", "theme": "dark", "timezone": "Europe/Moscow",
		"public_url": "https://flow.example/", "password_policy": map[string]any{"min_length": 16}, "geoip": map[string]any{"databases": []string{}}})
	if code != 200 || out["public_url"] != "https://flow.example" || out["password_policy"].(map[string]any)["min_length"] != float64(16) {
		t.Fatal(code, out)
	}
	// the stricter policy applies to new passwords
	if code, out := admin.do("POST", "/api/users", map[string]any{"username": "u2", "password": "fifteen-chars-x", "role_id": e.view.RoleID}); code != 400 || out["error"] != "weak_password" {
		t.Fatal(code, out)
	}

	var got map[string]any
	umb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer umb-secret" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(202)
	}))
	defer umb.Close()
	url := umb.URL + "/api/ingest/network-flow"
	if code, out := admin.do("POST", "/api/settings/umbrella/test", map[string]any{"enabled": true, "ingest_url": url, "token": "umb-secret"}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	code, out = admin.do("PUT", "/api/settings/umbrella", map[string]any{"enabled": true, "ingest_url": url, "token": "umb-secret"})
	if code != 200 || out["token_set"] != true || strings.Contains(toJSON(out), "umb-secret") {
		t.Fatal(code, out)
	}
	if e.fake.Get("flow/umbrella")["token"] != "umb-secret" {
		t.Fatal("token not in OpenBao")
	}
	// the stored token is used when none is given
	if code, out := admin.do("POST", "/api/settings/umbrella/test", map[string]any{"enabled": true, "ingest_url": url}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	if code, out := admin.do("GET", "/api/settings/openbao", nil); code != 200 || out["mount"] != "flow" ||
		out["status"].(map[string]any)["ok"] != true || out["status"].(map[string]any)["token_ok"] != true {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/settings/openbao/test", nil); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	// the console posts {} for "check the current connection"
	if code, out := admin.do("POST", "/api/settings/openbao/test", map[string]any{}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	if code, _ := viewer.do("GET", "/api/settings/openbao", nil); code != 403 {
		t.Fatal(code)
	}

	// no secret value reaches PostgreSQL
	rows, _ := e.st.Pool().Query(context.Background(), `SELECT t::text FROM settings t UNION ALL SELECT t::text FROM audit_log t UNION ALL SELECT t::text FROM users t UNION ALL SELECT t::text FROM sessions t`)
	defer rows.Close()
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		for _, secret := range []string{"umb-secret", "admin-password", "viewer-password"} {
			if strings.Contains(s, secret) {
				t.Fatalf("plaintext secret in PostgreSQL: %s", s)
			}
		}
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestDetectorRules(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	code, out := admin.do("GET", "/api/detector/rules", nil)
	if code != 200 || out["default"] != true || len(out["rules"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	rules := []map[string]any{{"id": "a", "kind": "custom"}, {"id": "b", "kind": "exporter_silent"}}
	code, out = admin.do("PUT", "/api/detector/rules", map[string]any{"rules": rules})
	if code != 200 || out["default"] != false || len(out["rules"].([]any)) != 2 || out["rules"].([]any)[1].(map[string]any)["id"] != "b" {
		t.Fatal(code, out)
	}
	if !slices.Contains(*e.rel, ReloadDetector) {
		t.Fatalf("reloads %v", *e.rel)
	}
	if code, out := admin.do("PUT", "/api/detector/rules", map[string]any{"rules": []map[string]any{{"id": "a", "kind": "x"}, {"id": "a", "kind": "x"}}}); code != 400 || out["error"] != "duplicate_rule" {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/detector/rules", map[string]any{"rules": []map[string]any{{"kind": "x"}}}); code != 400 || out["error"] != "invalid_rule" {
		t.Fatal(code, out)
	}
	// an empty set stays empty (not the defaults)
	if code, out := admin.do("PUT", "/api/detector/rules", map[string]any{"rules": []any{}}); code != 200 || out["default"] != false || len(out["rules"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	if code, _ := admin.do("GET", "/api/detector/status", nil); code != 200 {
		t.Fatal(code)
	}
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	if code, _ := viewer.do("GET", "/api/detector/rules", nil); code != 403 {
		t.Fatal(code)
	}
}
