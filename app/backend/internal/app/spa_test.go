package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/spa"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

func TestSPASignIn(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	nf := noFollow(c)

	// The authorization request: code flow, PKCE S256, nonce, signed state, scopes, hints.
	res, err := nf.Get(e.srv.URL + spa.StartPath + "?return=" + url.QueryEscape("/visualize?x=1") + "&idp_hint=passkey&login_hint=viewer&prompt=login")
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatal(err, res.StatusCode)
	}
	auth, _ := url.Parse(res.Header.Get("Location"))
	q := auth.Query()
	if auth.Path != "/oauth2/authorize" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("nonce") == "" || !strings.Contains(q.Get("state"), ".") || q.Get("scope") != "openid profile email groups roles" ||
		q.Get("redirect_uri") != e.srv.URL+spa.CallbackPath || q.Get("client_id") != "app_flow" || q.Get("idp_hint") != "passkey" ||
		q.Get("login_hint") != "viewer" || q.Get("prompt") != "login" {
		t.Fatal(auth)
	}
	var flowCookie *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name == spaCookie {
			flowCookie = ck
		}
	}
	if flowCookie == nil || !flowCookie.HttpOnly || flowCookie.Path != "/api/auth/spa/" || flowCookie.SameSite != http.SameSiteLaxMode || flowCookie.MaxAge != 600 ||
		strings.Contains(flowCookie.Value, q.Get("code_challenge")) {
		t.Fatalf("%+v", flowCookie)
	}
	// SPA signs the viewer in; the callback returns to the page asked for.
	e.spa.SignedIn = "usr_viewer"
	res, _ = nf.Get(auth.String())
	callback := res.Header.Get("Location")
	res, _ = nf.Get(callback)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/visualize?x=1" {
		t.Fatal(res.StatusCode, res.Header.Get("Location"))
	}
	// The legacy viewer is now bound to the SPA person.
	if u, err := e.st.UserBySPA(context.Background(), "usr_viewer"); err != nil || u.ID != e.view.ID {
		t.Fatal(u, err)
	}
	// The callback is single use (the state and the cookie are spent).
	res, _ = nf.Get(callback)
	if loc := res.Header.Get("Location"); loc != "/login?sso_error=state" {
		t.Fatal("callback replayed", loc)
	}
	// An open redirect is refused.
	if safeReturn("//evil.example/x") != "/" || safeReturn("https://evil.example") != "/" || safeReturn("/api/users") != "/" || safeReturn("/flows") != "/flows" {
		t.Fatal("return path")
	}

	// Without the cookie of the start: a state from another browser.
	other := e.client()
	res, _ = noFollow(other).Get(e.srv.URL + spa.StartPath)
	authURL := res.Header.Get("Location")
	res, _ = nf.Get(authURL) // the code arrives in this browser
	res, _ = nf.Get(res.Header.Get("Location"))
	if loc := res.Header.Get("Location"); loc != "/login?sso_error=state" {
		t.Fatal("state of another browser accepted", loc)
	}

	// The ID token is checked: nonce, audience, issuer, algorithm.
	for name, tamper := range map[string]func(){
		"nonce":    func() { e.spa.Nonce = "other" },
		"audience": func() { e.spa.Audience = "app_other" },
		"issuer":   func() { e.spa.Issuer = "https://evil.example" },
		"alg none": func() { e.spa.Alg = "none" },
	} {
		tamper()
		if got := e.client().signIn("admin", ""); got != "invalid_token" {
			t.Errorf("%s: %q", name, got)
		}
		e.spa.Nonce, e.spa.Audience, e.spa.Issuer, e.spa.Alg = "", "", "", ""
	}

	// SPA refuses people without a role in Flow: access_denied with the description.
	e.spa.Users = append(e.spa.Users, spaUser("nobody"))
	if got := e.client().signIn("nobody", ""); got != "access_denied" {
		t.Fatal(got)
	}
	// A role SPA gives that Flow does not know (deleted from the catalogue).
	e.spa.Users = append(e.spa.Users, spaUser("ghost", "deleted-role"))
	if got := e.client().signIn("ghost", ""); got != "no_role" {
		t.Fatal(got)
	}
	// A new person is created from the claims, with the role of the claim.
	e.spa.Users = append(e.spa.Users, spaUser("newbie", "viewer", "admin"))
	n := e.client()
	n.login("newbie")
	if _, out := n.do("GET", "/api/auth/me", nil); out["user"].(map[string]any)["role_ident"] != "admin" {
		t.Fatal("the role with the most permissions", out)
	}
	if u, _ := e.st.UserByUsername(context.Background(), "newbie"); u.Source != store.SourceSPA || u.Email != "newbie@example.com" {
		t.Fatal(u)
	}
}

func TestSPANotConnected(t *testing.T) {
	st := storetest.New(t)
	_, vault := secretstest.New(t)
	if err := auth.NewKeys(vault).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Version: "test"}, Deps{Store: st, Vault: vault})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, st: st, app: a}
	c := e.client()
	if code, out := c.do("GET", "/api/auth/spa", nil); code != 200 || out["connected"] != false {
		t.Fatal(code, out)
	}
	res, _ := noFollow(c).Get(srv.URL + spa.StartPath)
	if loc := res.Header.Get("Location"); loc != "/login?sso_error=not_connected" {
		t.Fatal(loc)
	}
	// A broken key is told apart from no key.
	a.opt.SPAKey = "umbid1.old"
	if code, out := c.do("GET", "/api/auth/spa", nil); code != 200 || out["connected"] != false || out["error"] != "invalid_key" {
		t.Fatal(code, out)
	}
}

func TestSPASync(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	viewerRole, _ := e.st.RoleByName(ctx, "Viewer")
	legacyUser(t, e.st, "carol", viewerRole.ID) // nobody in SPA claims her
	admin := e.client()
	admin.login("admin")
	bob := e.client()
	e.spa.Users = append(e.spa.Users, spaUser("bob", "viewer"))
	bob.login("bob")
	viewer := e.client()
	viewer.login("viewer")

	// The admin issues a token: it belongs to them and works while SPA keeps them.
	_, sa := admin.do("POST", "/api/service-accounts", map[string]any{"name": "grafana", "role_id": viewerRole.ID})
	_, tok := admin.do("POST", "/api/tokens", map[string]any{"service_account_id": sa["id"], "name": "dash"})
	plain := tok["token"].(string)
	if code, _ := e.bearer(plain, "GET", "/api/schema", nil); code != 200 {
		t.Fatal(code)
	}

	// SPA: alice is new, viewer is renamed, bob is disabled, dave has no role here.
	e.spa.Users = []spa.User{spaUser("admin", "admin"), spaUser("alice", "viewer"), spaUser("dave"),
		{ID: "usr_viewer", Username: "viewer2", Name: "Viewer Two", Roles: []string{"viewer"}},
		{ID: "usr_bob", Username: "bob", Disabled: true, Roles: []string{"viewer"}}}
	code, v := admin.do("POST", "/api/settings/spa/sync", nil)
	st := v
	if code != 200 || st["ok"] != true || st["created"] != float64(1) || st["disabled"] != float64(2) || st["users"] != float64(3) ||
		st["application"].(map[string]any)["name"] != "Umbrella Flow" || st["account_url"] != e.spa.AccountURL() || st["connected"] != true ||
		st["key_source"] != "env" || st["issuer"] != e.spa.Server.URL || st["redirect_uri"] != e.srv.URL+spa.CallbackPath {
		t.Fatal(code, v)
	}
	users := usersByName(t, admin)
	if users["alice"]["source"] != "spa" || users["alice"]["role"] != "Viewer" || users["alice"]["disabled"] != false {
		t.Fatal(users["alice"])
	}
	if users["viewer2"]["id"] != float64(e.view.ID) || users["viewer2"]["name"] != "Viewer Two" {
		t.Fatal("rename by sub", users["viewer2"])
	}
	if users["bob"]["disabled"] != true || users["carol"]["disabled"] != true {
		t.Fatal("disabled", users["bob"], users["carol"])
	}
	if _, ok := users["dave"]; ok {
		t.Fatal("a person without a role here was created")
	}
	// bob's session and token stop working; the others' do not.
	if code, _ := bob.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("disabled person kept the session", code)
	}
	if code, _ := viewer.do("GET", "/api/auth/me", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := e.bearer(plain, "GET", "/api/schema", nil); code != 200 {
		t.Fatal("the token belongs to the admin who issued it", code)
	}
	var owner int64
	_ = e.st.Pool().QueryRow(ctx, `SELECT created_by_id FROM api_tokens`).Scan(&owner)
	if owner != e.admin.ID {
		t.Fatal("token owner", owner)
	}
	// The catalogue was published; nothing changed → 304 and no new publication.
	published := e.spa.Published
	if e.spa.Catalogue == nil || len(e.spa.Catalogue.Roles) != 2 {
		t.Fatal(e.spa.Catalogue)
	}
	if _, v := admin.do("POST", "/api/settings/spa/sync", nil); v["ok"] != true || v["created"] != float64(0) || e.spa.Published != published {
		t.Fatal(v, e.spa.Published)
	}
	if code, _ := viewer.do("POST", "/api/settings/spa/sync", nil); code != 403 {
		t.Fatal("viewer synchronizes", code)
	}

	// SPA disables the admin who issued the token: it stops working.
	e.spa.Users[0].Disabled = true
	_, v = admin.do("POST", "/api/settings/spa/sync", nil)
	if code, out := e.bearer(plain, "GET", "/api/schema", nil); code != 401 || out["error"] != "invalid_token" {
		t.Fatal("token of a disabled person works", code, out, v)
	}
	if code, _ := admin.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal(code)
	}

	// A replaced key is reported.
	e.spa.Users[0].Disabled = false
	a2 := e.client()
	a2.login("admin")
	e.spa.Key.Token = "fed-token-2"
	if code, v := a2.do("POST", "/api/settings/spa/sync", nil); code != 200 || v["ok"] != false || !strings.Contains(v["error"].(string), "new connection key") {
		t.Fatal(code, v)
	}
}
