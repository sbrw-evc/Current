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
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/spa"
	"github.com/sbrw-evc/network/app/backend/internal/spa/spatest"
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

// fakeLaterDefaults are built-in rules "added by a later version" (TestDetectorNewDefaults).
var fakeLaterDefaults []json.RawMessage

func (fakeDetector) DefaultRules() []json.RawMessage {
	return append([]json.RawMessage{json.RawMessage(`{"id":"link-utilization","kind":"link_utilization","enabled":true}`)}, fakeLaterDefaults...)
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
	spa   *spatest.SPA
	app   *App
}

// newEnv: Flow connected to a fake SPA that knows "admin" (role admin) and
// "viewer" (role viewer); both exist in Flow as legacy accounts and are bound
// on their first sign-in.
func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	fake, vault := secretstest.New(t)
	ctx := context.Background()
	adminRole, _ := st.RoleByName(ctx, access.RoleAdministrator)
	viewerRole, _ := st.RoleByName(ctx, access.RoleViewer)
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	admin := legacyUser(t, st, "admin", adminRole.ID)
	viewer := legacyUser(t, st, "viewer", viewerRole.ID)
	sp := spatest.New(t)
	sp.Users = []spa.User{spaUser("admin", "admin"), spaUser("viewer", "viewer")}
	rel := &reloads{}
	a := New(Options{Version: "test", SPAKey: sp.ConnectionKey()}, Deps{Store: st, Vault: vault, Visualizer: fakeVisualizer{},
		Classifiers: fakeClassifiers{}, Detector: fakeDetector{}, Reloaders: []Reloader{rel}})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, fake: fake, rel: rel, admin: admin, view: viewer, spa: sp, app: a}
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

// login signs the person in through the fake SPA.
func (c *client) login(user string) {
	c.e.t.Helper()
	if e := c.signIn(user, ""); e != "" {
		c.e.t.Fatalf("login %s: %s", user, e)
	}
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

func TestSignInAndSignOut(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if code, out := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "x"}); code != 404 {
		t.Fatal("password sign-in still answers", code, out)
	}
	c.login("ADMIN")
	code, out := c.do("GET", "/api/auth/me", nil)
	if code != 200 || out["csrf"] != c.csrf || out["account_url"] != e.spa.AccountURL() {
		t.Fatal(code, out)
	}
	user := out["user"].(map[string]any)
	if user["username"] != "admin" || user["source"] != "spa" || user["role_ident"] != "admin" || user["role"] != access.RoleAdministrator ||
		len(user["permissions"].([]any)) != len(access.BuiltinRoles()[0].Permissions) {
		t.Fatal(user)
	}
	if code, out := c.do("GET", "/api/schema", nil); code != 200 || len(out["columns"].([]any)) == 0 {
		t.Fatal(code, out)
	}
	code, out = c.do("POST", "/api/auth/logout", nil)
	back := url.QueryEscape(e.srv.URL + "/")
	if code != 200 || !strings.HasPrefix(out["redirect"].(string), e.spa.SignOutURL()+"?") || !strings.Contains(out["redirect"].(string), "post_logout_redirect_uri="+back) ||
		!strings.Contains(out["redirect"].(string), "client_id=app_flow") {
		t.Fatal(code, out)
	}
	if code, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("session survived logout", code)
	}
}

func TestCSRFAndPermissions(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin")
	viewer := e.client()
	viewer.login("viewer")

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
		"/api/status": 200, "/api/audit": 200, "/api/settings/spa": 200, "/api/access/catalog": 200, "/api/settings/ldap": 404,
		"/api/settings/password-policy": 404, "/api/settings/entra": 404, "/api/settings/identity": 404} {
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
	admin.login("admin")

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
	admin.login("admin")
	ctx := context.Background()
	adminRole, _ := e.st.RoleByName(ctx, access.RoleAdministrator)

	// Users are managed in SPA: no creation, change, password or deletion here.
	for _, req := range [][2]string{{"POST", "/api/users"}, {"PUT", "/api/users/1"}, {"DELETE", "/api/users/1"}, {"PUT", "/api/users/1/password"},
		{"POST", "/api/auth/password"}, {"POST", "/api/auth/passkey/begin"}, {"GET", "/api/auth/methods"}} {
		if code, _ := admin.do(req[0], req[1], map[string]any{}); code != 404 && code != 405 {
			t.Errorf("%s %s: %d", req[0], req[1], code)
		}
	}
	if code, _ := admin.do("PUT", "/api/roles/"+itoa(int(adminRole.ID)), map[string]any{"name": "x"}); code != 409 {
		t.Fatal("built-in role changed", code)
	}

	// A custom role: published to SPA by its ident, then given by SPA.
	code, role := admin.do("POST", "/api/roles", map[string]any{"name": "NOC", "description": "Network operations", "permissions": []string{"settings.inventory:sync", "flows:view"}})
	if code != 201 || len(role["permissions"].([]any)) != 3 || role["ident"] != "noc" {
		t.Fatal(code, role)
	}
	if c := e.spa.Catalogue; c == nil || len(c.Roles) != 3 || c.Default != "viewer" || !slices.ContainsFunc(c.Roles, func(r spa.Role) bool {
		return r.ID == "noc" && r.Name == "NOC" && r.Description == "Network operations"
	}) || !slices.ContainsFunc(c.Roles, func(r spa.Role) bool { return r.ID == "admin" && r.Name == access.RoleAdministrator }) {
		t.Fatal("catalogue not published", e.spa.Catalogue)
	}
	if code, out := admin.do("POST", "/api/roles", map[string]any{"name": "Bad", "permissions": []string{"nope:x"}}); code != 400 {
		t.Fatal(code, out)
	}
	e.spa.Users = append(e.spa.Users, spaUser("noc1", "noc"))
	noc := e.client()
	noc.login("noc1")
	if code, _ := noc.do("GET", "/api/inventory-db", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := noc.do("PUT", "/api/inventory-db", map[string]any{}); code != 403 {
		t.Fatal(code)
	}
	if code, _ := admin.do("DELETE", "/api/roles/"+itoa(int(role["id"].(float64))), nil); code != 409 {
		t.Fatal("role in use deleted", code)
	}
	// A rename keeps the ident and is published again.
	published := e.spa.Published
	if code, out := admin.do("PUT", "/api/roles/"+itoa(int(role["id"].(float64))), map[string]any{"name": "NOC engineers", "permissions": []string{"flows:view"}}); code != 200 || out["ident"] != "noc" {
		t.Fatal(code, out)
	}
	if e.spa.Published != published+1 || !slices.ContainsFunc(e.spa.Catalogue.Roles, func(r spa.Role) bool { return r.ID == "noc" && r.Name == "NOC engineers" }) {
		t.Fatal("rename not published", e.spa.Catalogue)
	}

	users := usersByName(t, admin)
	if users["noc1"]["source"] != "spa" || users["noc1"]["role"] != "NOC engineers" || users["noc1"]["spa_id"] != "usr_noc1" || users["noc1"]["password_ref"] != nil {
		t.Fatal(users["noc1"])
	}
	if code, out := admin.do("GET", "/api/audit", nil); code != 200 || len(out["results"].([]any)) < 4 {
		t.Fatal(code, out)
	}
}

func usersByName(t *testing.T, c *client) map[string]map[string]any {
	t.Helper()
	code, out := c.do("GET", "/api/users", nil)
	if code != 200 {
		t.Fatal(code, out)
	}
	m := map[string]map[string]any{}
	for _, u := range out["results"].([]any) {
		x := u.(map[string]any)
		m[x["username"].(string)] = x
	}
	return m
}

func TestGeneralUmbrellaOpenBao(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin")
	code, out := admin.do("GET", "/api/settings/general", nil)
	if code != 200 || out["language"] != "ru" || out["password_policy"] != nil {
		t.Fatal(code, out)
	}
	code, out = admin.do("PUT", "/api/settings/general", map[string]any{"language": "en", "theme": "dark", "timezone": "Europe/Moscow",
		"public_url": "https://flow.example/", "geoip": map[string]any{"databases": []string{}}})
	if code != 200 || out["public_url"] != "https://flow.example" {
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
	viewer.login("viewer")
	if code, _ := viewer.do("GET", "/api/settings/openbao", nil); code != 403 {
		t.Fatal(code)
	}

	// no secret value reaches PostgreSQL
	rows, _ := e.st.Pool().Query(context.Background(), `SELECT t::text FROM settings t UNION ALL SELECT t::text FROM audit_log t UNION ALL SELECT t::text FROM users t UNION ALL SELECT t::text FROM sessions t`)
	defer rows.Close()
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		for _, secret := range []string{"umb-secret", e.spa.Key.ClientSecret, e.spa.Key.Token} {
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
	admin.login("admin")
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
	viewer.login("viewer")
	if code, _ := viewer.do("GET", "/api/detector/rules", nil); code != 403 {
		t.Fatal(code)
	}
}

func TestDetectorNewDefaults(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin")
	ids := func(v any) []string {
		var out []string
		for _, r := range v.([]any) {
			out = append(out, r.(map[string]any)["id"].(string))
		}
		return out
	}
	// Saved with the built-in rule and a custom one, before the new defaults existed.
	t.Cleanup(func() { fakeLaterDefaults = nil })
	rules := []map[string]any{{"id": "link-utilization", "kind": "link_utilization", "enabled": false}, {"id": "mine", "kind": "custom"}}
	if code, out := admin.do("PUT", "/api/detector/rules", map[string]any{"rules": rules}); code != 200 || len(out["new_defaults"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	// A later version adds two built-in rules: offered, never merged silently.
	fakeLaterDefaults = []json.RawMessage{json.RawMessage(`{"id":"threat-contact","kind":"threat_contact","enabled":true}`),
		json.RawMessage(`{"id":"exporter-silent","kind":"exporter_silent","enabled":true}`)}
	code, out := admin.do("GET", "/api/detector/rules", nil)
	if code != 200 || !slices.Equal(ids(out["new_defaults"]), []string{"threat-contact", "exporter-silent"}) || len(out["rules"].([]any)) != 2 {
		t.Fatal(code, out)
	}
	// Add one, dismiss the other; the saved rules are untouched.
	if code, out := admin.do("POST", "/api/detector/rules/add-defaults", map[string]any{"ids": []string{"nope"}}); code != 400 || out["error"] != "unknown_default" {
		t.Fatal(code, out)
	}
	code, out = admin.do("POST", "/api/detector/rules/add-defaults", map[string]any{"ids": []string{"threat-contact"}, "dismiss": []string{"exporter-silent"}})
	if code != 200 || !slices.Equal(ids(out["rules"]), []string{"link-utilization", "mine", "threat-contact"}) || len(out["new_defaults"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	if out["rules"].([]any)[0].(map[string]any)["enabled"] != false {
		t.Fatal("saved rule changed", out)
	}
	// A built-in rule deleted from the saved set is not offered again.
	rules = []map[string]any{{"id": "mine", "kind": "custom"}, {"id": "threat-contact", "kind": "threat_contact"}}
	if code, out := admin.do("PUT", "/api/detector/rules", map[string]any{"rules": rules}); code != 200 || len(out["new_defaults"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	// Without a body every new default is added.
	fakeLaterDefaults = append(fakeLaterDefaults, json.RawMessage(`{"id":"ddos","kind":"ddos_volumetric"}`))
	code, out = admin.do("POST", "/api/detector/rules/add-defaults", nil)
	if code != 200 || !slices.Equal(ids(out["rules"]), []string{"mine", "threat-contact", "ddos"}) {
		t.Fatal(code, out)
	}
	viewer := e.client()
	viewer.login("viewer")
	if code, _ := viewer.do("POST", "/api/detector/rules/add-defaults", nil); code != 403 {
		t.Fatal(code)
	}
}
