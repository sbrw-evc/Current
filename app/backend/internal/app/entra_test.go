package app

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/entra"
	"github.com/sbrw-evc/network/app/backend/internal/entra/entratest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// entraBrowser signs in through the Entra flow like a browser and returns
// where the callback sent it.
func entraBrowser(t *testing.T, e *env, jar http.CookieJar) *url.URL {
	t.Helper()
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := e.srv.URL + "/api/auth/entra/start"
	for range 3 { // start → Microsoft → callback → Flow
		resp, err := c.Get(next)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s: %d", next, resp.StatusCode)
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if !loc.IsAbs() {
			return loc
		}
		next = loc.String()
	}
	t.Fatal("too many redirects")
	return nil
}

func TestEntraSignIn(t *testing.T) {
	idp := entratest.Start(t)
	e := newEnv(t)
	ctx := context.Background()
	admin := e.client()
	admin.login("admin", "admin-password")
	viewerRole, _ := e.st.RoleByName(ctx, access.RoleViewer)
	adminRole, _ := e.st.RoleByName(ctx, access.RoleAdministrator)
	adminGroup := "aaaaaaaa-0000-0000-0000-00000000000a"

	settings := map[string]any{"enabled": true, "cloud": entratest.Cloud, "tenant_id": entratest.TenantID, "client_id": entratest.ClientID,
		"redirect_url": e.srv.URL + entra.CallbackPath, "default_role_id": viewerRole.ID,
		"group_roles": []map[string]any{{"group_id": strings.ToUpper(adminGroup), "role_id": adminRole.ID}}}

	if code, out := e.client().do("GET", "/api/auth/entra", nil); code != 200 || out["enabled"] != false {
		t.Fatal(code, out)
	}
	// A wrong secret is refused by the check and by saving.
	settings["client_secret"] = "wrong"
	if code, out := admin.do("POST", "/api/settings/entra/test", settings); code != 200 || out["ok"] != false {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/settings/entra", settings); code != 400 || out["error"] != "entra_unavailable" {
		t.Fatal(code, out)
	}
	settings["client_secret"] = entratest.Secret
	if code, out := admin.do("POST", "/api/settings/entra/test", settings); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	code, out := admin.do("PUT", "/api/settings/entra", settings)
	if code != 200 || out["client_secret_set"] != true || out["client_secret_ref"] != nil || out["enabled"] != true {
		t.Fatal(code, out)
	}
	if e.fake.Get("flow/entra")["client_secret"] != entratest.Secret {
		t.Fatal("client secret not in OpenBao")
	}
	var raw string
	_ = e.st.Pool().QueryRow(ctx, `SELECT value::text FROM settings WHERE key = 'entra'`).Scan(&raw)
	if strings.Contains(raw, entratest.Secret) || !strings.Contains(raw, "openbao://flow/entra#client_secret") {
		t.Fatal(raw)
	}
	// Saving again without the secret keeps it.
	delete(settings, "client_secret")
	if code, out := admin.do("PUT", "/api/settings/entra", settings); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := e.client().do("GET", "/api/auth/entra", nil); code != 200 || out["enabled"] != true {
		t.Fatal(code, out)
	}

	// First sign-in creates the user with the default role.
	idp.User = entratest.User{ObjectID: "0f0f0f0f-1111-2222-3333-444444444444", Username: "Petrov@Corp.example", Name: "Petr Petrov",
		Groups: []string{"bbbbbbbb-0000-0000-0000-000000000001"}}
	jar, _ := cookiejar.New(nil)
	if loc := entraBrowser(t, e, jar); loc.Path != "/" || loc.RawQuery != "" {
		t.Fatal("redirect", loc)
	}
	c := &client{e: e, http: &http.Client{Jar: jar}}
	code, me := c.do("GET", "/api/auth/me", nil)
	if code != 200 {
		t.Fatal(code, me)
	}
	u := me["user"].(map[string]any)
	if u["username"] != "petrov@corp.example" || u["source"] != store.SourceEntra || u["role"] != access.RoleViewer || u["name"] != "Petr Petrov" {
		t.Fatal(u)
	}

	// Group mapping: membership in the mapped group gives its role.
	idp.User.Groups = append(idp.User.Groups, adminGroup)
	jar2, _ := cookiejar.New(nil)
	entraBrowser(t, e, jar2)
	c2 := &client{e: e, http: &http.Client{Jar: jar2}}
	if _, me := c2.do("GET", "/api/auth/me", nil); me["user"].(map[string]any)["role"] != access.RoleAdministrator {
		t.Fatal(me)
	}
	users, _ := e.st.ListUsers(ctx)
	if len(users) != 3 {
		t.Fatalf("users: %d", len(users))
	}

	// A callback without the state cookie (another browser) is refused.
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).
		Get(e.srv.URL + entra.CallbackPath + "?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/login?signin_error=entra_state" {
		t.Fatal(loc)
	}

	// A local user with the same name is not taken over.
	idp.User.Username = "viewer"
	jar3, _ := cookiejar.New(nil)
	if loc := entraBrowser(t, e, jar3); loc.Query().Get("signin_error") != "entra_conflict" {
		t.Fatal(loc)
	}

	// Switching Entra off signs its users out and hides the button.
	if code, out := admin.do("PUT", "/api/settings/entra", map[string]any{"enabled": false}); code != 200 || out["enabled"] != false {
		t.Fatal(code, out)
	}
	if code, _ := c.do("GET", "/api/auth/me", nil); code != 401 {
		t.Fatal("entra session survived", code)
	}
	jar4, _ := cookiejar.New(nil)
	if loc := entraBrowser(t, e, jar4); loc.Query().Get("signin_error") != "entra_off" {
		t.Fatal(loc)
	}
	if code, _ := e.client().do("GET", "/api/settings/entra", nil); code != 401 {
		t.Fatal(code)
	}
}
