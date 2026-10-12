package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
	"github.com/sbrw-evc/network/app/backend/internal/umbrella"
)

// fakeUmbrella serves the scope and proposals endpoints of §3.2 / §3.3.
type fakeUmbrella struct {
	srv         *httptest.Server
	scopeCalls  atomic.Int32
	mu          sync.Mutex
	batches     []umbrella.Batch
	down        atomic.Bool
	lastAuth    string
	lastUserArg string
}

func newFakeUmbrella(t *testing.T) *fakeUmbrella {
	f := &fakeUmbrella{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			http.Error(w, "maintenance", http.StatusBadGateway)
			return
		}
		f.mu.Lock()
		f.lastAuth = r.Header.Get("Authorization")
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer umb_service" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/integrations/flow/scope":
			f.scopeCalls.Add(1)
			u := strings.ToLower(r.URL.Query().Get("username"))
			f.mu.Lock()
			f.lastUserArg = u
			f.mu.Unlock()
			switch u {
			case "scoped":
				_, _ = w.Write([]byte(`{"username":"scoped","known":true,"mode":"selected","cis":[{"id":"ci_1","name":"app-01",
					"source_refs":["inventory-db:dcim.device:100"],"ips":["10.0.0.5"]}],"services":[{"id":"svc_1","name":"Billing"}]}`))
			case "admin", "viewer", "everything":
				_, _ = w.Write([]byte(`{"username":"` + u + `","known":true,"mode":"all","cis":[],"services":[]}`))
			default:
				_, _ = w.Write([]byte(`{"known":false}`))
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/cmdb/proposals":
			var b umbrella.Batch
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			f.mu.Lock()
			f.batches = append(f.batches, b)
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"accepted":` + umbItoa(len(b.Proposals)) + `,"updated":0,"ignored":0}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func umbItoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// scopeEcho is a Visualizer that answers with the scope of its context, as
// query.ScopedConn would apply it.
type scopeEcho struct{}

func (scopeEcho) Visualize(ctx context.Context, _ json.RawMessage) (any, error) {
	s, err := query.ScopeFrom(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"scoped": query.Scoped(ctx), "where": s.SQL(true)}, nil
}

type fakeFinder struct {
	pairs  []query.DependencyPair
	params query.DependencyParams
	calls  int
}

func (f *fakeFinder) DependencyPairs(_ context.Context, p query.DependencyParams) ([]query.DependencyPair, error) {
	f.calls++
	f.params = p
	return f.pairs, nil
}

func newUmbrellaEnv(t *testing.T, finder DependencyFinder) (*env, *App) {
	t.Helper()
	auth.Iterations = 1000
	st := storetest.New(t)
	fake, vault := secretstest.New(t)
	ctx := context.Background()
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	adminRole, _ := st.RoleByName(ctx, access.RoleAdministrator)
	viewerRole, _ := st.RoleByName(ctx, access.RoleViewer)
	scopedRole, err := st.CreateRole(ctx, "Scoped", "", []string{access.VisualizeView, access.ScopeUmbrella, access.DependenciesView})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string, roleID int64) store.User {
		u, err := st.CreateUser(ctx, store.NewUser{Username: name, Name: name, RoleID: roleID})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := auth.NewPasswords(vault).Set(ctx, u.ID, name+"-password")
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SetPasswordRef(ctx, u.ID, ref)
		return u
	}
	admin := mk("admin", adminRole.ID)
	viewer := mk("viewer", viewerRole.ID)
	mk("Scoped", scopedRole.ID)
	deps := Deps{Store: st, Vault: vault, Visualizer: scopeEcho{}}
	if finder != nil {
		deps.Dependencies = finder
	}
	a := New(Options{Version: "test"}, deps)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, fake: fake, rel: &reloads{}, admin: admin, view: viewer}, a
}

func configureUmbrella(t *testing.T, c *client, url string) {
	t.Helper()
	if code, out := c.do("PUT", "/api/settings/umbrella/api", map[string]any{"url": url + "/api/", "token": "umb_service"}); code != 200 ||
		out["url"] != url || out["token_set"] != true {
		t.Fatal(code, out)
	}
}

func TestUmbrellaAPISettings(t *testing.T) {
	um := newFakeUmbrella(t)
	e, _ := newUmbrellaEnv(t, nil)
	admin := e.client()
	admin.login("admin", "admin-password")
	if code, out := admin.do("GET", "/api/settings/umbrella/api", nil); code != 200 || out["token_set"] != false {
		t.Fatal(code, out)
	}
	if code, _ := admin.do("PUT", "/api/settings/umbrella/api", map[string]any{"url": "ftp://x", "token": "t"}); code != 400 {
		t.Fatal("bad URL accepted", code)
	}
	configureUmbrella(t, admin, um.srv.URL)
	// The token lives in OpenBao only.
	if got := e.fake.Get("flow/" + secretUmbrellaAPI)["token"]; got != "umb_service" {
		t.Fatalf("OpenBao: %v", got)
	}
	var s umbrellaAPISettings
	_, _ = e.st.Setting(context.Background(), settingUmbrellaAPI, &s)
	if s.TokenRef == "" || strings.Contains(s.TokenRef, "umb_service") {
		t.Fatalf("stored settings: %+v", s)
	}
	// Test: the scope of the signed-in user, with the stored token.
	code, out := admin.do("POST", "/api/settings/umbrella/api/test", map[string]any{})
	if code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	if d := out["details"].(map[string]any); d["mode"] != "all" || d["known"] != true || d["restricted"] != false {
		t.Fatal(d)
	}
	// A wrong draft token is reported, not saved.
	if code, out := admin.do("POST", "/api/settings/umbrella/api/test", map[string]any{"token": "umb_wrong"}); code != 200 || out["ok"] != false ||
		!strings.Contains(out["error"].(string), "401") {
		t.Fatal(code, out)
	}
	// The viewer may not change it.
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	if code, _ := viewer.do("PUT", "/api/settings/umbrella/api", map[string]any{"url": um.srv.URL}); code != 403 {
		t.Fatal(code)
	}
	// Removing the token deletes the secret.
	if code, out := admin.do("PUT", "/api/settings/umbrella/api", map[string]any{"token": ""}); code != 200 || out["token_set"] != false {
		t.Fatal(code, out)
	}
	if len(e.fake.Get("flow/"+secretUmbrellaAPI)) != 0 {
		t.Fatal("secret not deleted")
	}
}

func TestUmbrellaScopeRestrictsQueries(t *testing.T) {
	um := newFakeUmbrella(t)
	e, _ := newUmbrellaEnv(t, nil)
	admin := e.client()
	admin.login("admin", "admin-password")
	scoped := e.client()
	scoped.login("Scoped", "Scoped-password")
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	body := map[string]any{"start": "2026-10-12T09:00:00Z", "end": "2026-10-12T10:00:00Z"}

	// Not configured: the restricted user fails closed, the others are unaffected.
	if code, out := scoped.do("POST", "/api/visualize", body); code != 503 || out["error"] != "scope_unavailable" {
		t.Fatal(code, out)
	}
	if code, out := scoped.do("GET", "/api/umbrella/scope", nil); code != 200 || out["restricted"] != true || out["ok"] != false ||
		!strings.Contains(out["error"].(string), "not configured") {
		t.Fatal(code, out)
	}
	for _, c := range []*client{admin, viewer} {
		if code, out := c.do("POST", "/api/visualize", body); code != 200 || out["scoped"] != false || out["where"] != "1" {
			t.Fatal(code, out)
		}
	}

	configureUmbrella(t, admin, um.srv.URL)
	um.scopeCalls.Store(0)
	code, out := scoped.do("POST", "/api/visualize", body)
	if code != 200 || out["scoped"] != true {
		t.Fatal(code, out)
	}
	where := out["where"].(string)
	if !strings.Contains(where, "SrcCI IN ('inventory-db:dcim.device:100')") || !strings.Contains(where, "DstAddr IN (toIPv6('::ffff:10.0.0.5'))") {
		t.Fatal(where)
	}
	// Cached for 60 s per user: a second request does not ask Umbrella again.
	_, _ = scoped.do("POST", "/api/visualize", body)
	if n := um.scopeCalls.Load(); n != 1 {
		t.Fatalf("scope fetched %d times", n)
	}
	if um.lastUserArg != "scoped" {
		t.Fatalf("username sent: %q", um.lastUserArg)
	}
	if code, out := scoped.do("GET", "/api/umbrella/scope", nil); code != 200 || out["ok"] != true || out["mode"] != "selected" ||
		out["cis"] != float64(1) || out["refs"] != float64(1) || out["addresses"] != float64(1) {
		t.Fatal(code, out)
	}
	if code, out := admin.do("GET", "/api/umbrella/scope", nil); code != 200 || out["restricted"] != false {
		t.Fatal(code, out)
	}

	// Umbrella goes down: once the cache expires (here: settings saved again,
	// which drops it), the restricted user gets 503, never unrestricted data.
	um.down.Store(true)
	configureUmbrella(t, admin, um.srv.URL)
	if code, out := scoped.do("POST", "/api/visualize", body); code != 503 || out["error"] != "scope_unavailable" ||
		!strings.Contains(out["message"].(string), "Umbrella answered 502") {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/visualize", body); code != 200 || out["scoped"] != false {
		t.Fatal(code, out)
	}
}

func TestUmbrellaScopeUnknownUserSeesNothing(t *testing.T) {
	r := &umbrella.ScopeReply{Known: false}
	if got := umbrella.QueryScope(r).SQL(true); got != "0" {
		t.Fatal(got)
	}
	p := &Principal{User: store.User{Role: access.RoleAdministrator}, Perms: access.NewSet([]string{access.ScopeUmbrella})}
	if scopeRestricted(p) {
		t.Fatal("the built-in Administrator is never restricted")
	}
	p.User.Role = "Ops"
	if !scopeRestricted(p) {
		t.Fatal("a role with scope:umbrella is restricted")
	}
}

func TestDependencies(t *testing.T) {
	um := newFakeUmbrella(t)
	day := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	finder := &fakeFinder{pairs: []query.DependencyPair{
		{ClientRef: "inventory-db:dcim.device:100", ClientName: "app-01", ClientIP: "10.0.0.5", ServerRef: "inventory-db:dcim.device:200",
			ServerName: "db-01", ServerIP: "10.0.1.9", Proto: 6, Port: 5432, App: "postgres", Bytes: 123456789, Flows: 4200, DaysSeen: 7,
			FirstSeen: day.Add(-6 * 24 * time.Hour), LastSeen: day},
		{ClientRef: "inventory-db:dcim.device:100", ServerRef: "inventory-db:dcim.device:300", Proto: 17, Port: 53, Flows: 900, DaysSeen: 4},
	}}
	e, a := newUmbrellaEnv(t, finder)
	ctx := context.Background()
	_ = e.st.PutSetting(ctx, setup.SettingGeneral, setup.General{Language: "en", Theme: "system", Timezone: "UTC", PublicURL: "https://flow.corp"})
	admin := e.client()
	admin.login("admin", "admin-password")

	if code, out := admin.do("GET", "/api/dependencies", nil); code != 200 || out["last_run"] != nil || out["configured"] != false || out["available"] != true {
		t.Fatal(code, out)
	}
	// Thresholds.
	if code, _ := admin.do("PUT", "/api/dependencies/settings", map[string]any{"enabled": true, "hour": 25}); code != 400 {
		t.Fatal(code)
	}
	if code, out := admin.do("PUT", "/api/dependencies/settings", map[string]any{"enabled": false, "hour": 0, "min_flows": 50, "min_days": 4, "max_proposals": 100}); code != 200 ||
		out["settings"].(map[string]any)["min_flows"] != float64(50) {
		t.Fatal(code, out)
	}

	// Preview (dry run) works without Umbrella.
	code, out := admin.do("POST", "/api/dependencies/run", map[string]any{"dry_run": true})
	if code != 200 {
		t.Fatal(code, out)
	}
	if finder.params.MinFlows != 50 || finder.params.MinDays != 4 || finder.params.Limit != 100 || finder.params.Days != 7 {
		t.Fatalf("params %+v", finder.params)
	}
	props := out["proposals"].([]any)
	if len(props) != 2 {
		t.Fatal(out)
	}
	p0 := props[0].(map[string]any)
	if p0["key"] != "flow:inventory-db:dcim.device:100->inventory-db:dcim.device:200:tcp/5432" || p0["type"] != "depends_on" {
		t.Fatal(p0)
	}
	ev := p0["evidence"].(map[string]any)
	if ev["protocol"] != "tcp" || ev["port"] != float64(5432) || ev["app"] != "postgres" || ev["flows_7d"] != float64(4200) ||
		!strings.HasPrefix(ev["flow_url"].(string), "https://flow.corp/visualize?q=") {
		t.Fatal(ev)
	}
	if run := out["run"].(map[string]any); run["ok"] != true || run["dry_run"] != true || run["sent"] != float64(0) || run["pairs"] != float64(2) {
		t.Fatal(run)
	}
	if len(um.batches) != 0 {
		t.Fatal("dry run sent proposals")
	}

	// A real run without the Umbrella connection fails and records why.
	if code, out := admin.do("POST", "/api/dependencies/run", nil); code != 200 || out["run"].(map[string]any)["ok"] != false ||
		!strings.Contains(out["run"].(map[string]any)["error"].(string), "not configured") {
		t.Fatal(code, out)
	}

	configureUmbrella(t, admin, um.srv.URL)
	if code, out := admin.do("POST", "/api/dependencies/run", map[string]any{}); code != 200 || out["run"].(map[string]any)["ok"] != true ||
		out["run"].(map[string]any)["accepted"] != float64(2) {
		t.Fatal(code, out)
	}
	if len(um.batches) != 1 || um.batches[0].Source != "umbrella-flow" || len(um.batches[0].Proposals) != 2 ||
		um.batches[0].Proposals[0].To.Name != "db-01" {
		t.Fatalf("%+v", um.batches)
	}
	code, out = admin.do("GET", "/api/dependencies", nil)
	if code != 200 || out["configured"] != true || len(out["proposals"].([]any)) != 2 || len(out["runs"].([]any)) != 3 {
		t.Fatal(code, out)
	}
	if lr := out["last_run"].(map[string]any); lr["sent"] != float64(2) || lr["trigger"] != "manual" || lr["actor"] != "admin" {
		t.Fatal(lr)
	}

	// Permissions: the scoped role may view, not run; the viewer neither.
	scoped := e.client()
	scoped.login("Scoped", "Scoped-password")
	if code, _ := scoped.do("GET", "/api/dependencies", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := scoped.do("POST", "/api/dependencies/run", nil); code != 403 {
		t.Fatal(code)
	}
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	if code, _ := viewer.do("GET", "/api/dependencies", nil); code != 403 {
		t.Fatal(code)
	}

	// The daily schedule: off → nothing; on → one run per day.
	now := time.Now().UTC()
	before := finder.calls
	a.dependencyTick(ctx, now)
	if finder.calls != before {
		t.Fatal("disabled schedule ran")
	}
	_ = e.st.PutSetting(ctx, settingDependencies, dependencySettings{Enabled: true, Hour: 0, MinFlows: 10, MinDays: 1, MaxProposals: 10})
	a.dependencyTick(ctx, now)
	a.dependencyTick(ctx, now)
	if finder.calls != before+1 || len(um.batches) != 2 {
		t.Fatalf("scheduled runs: %d, batches %d", finder.calls-before, len(um.batches))
	}
	if code, out := admin.do("GET", "/api/dependencies", nil); code != 200 || out["next_run"] == nil ||
		out["last_run"].(map[string]any)["trigger"] != "schedule" {
		t.Fatal(code, out)
	}
}
