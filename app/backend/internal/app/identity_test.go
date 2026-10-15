package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/passkey"
	"github.com/sbrw-evc/network/app/backend/internal/passkey/passkeytest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/umbrellaid"
	"github.com/sbrw-evc/network/app/backend/internal/umbrellaid/hubtest"
)

const flowURL = "https://flow.example.com"

func noFollow(c *client) *http.Client {
	return &http.Client{Jar: c.http.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *client) raw(method, path, origin string, body any) (int, map[string]any) {
	c.e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, c.e.srv.URL+path, strings.NewReader(string(b)))
	req.Header.Set("Origin", origin)
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func usersByName(t *testing.T, c *client) map[string]map[string]any {
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

func TestUmbrellaIdentity(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.client()
	admin.login("admin", "admin-password")
	if code, out := admin.do("PUT", "/api/settings/general", map[string]any{"language": "en", "theme": "dark", "timezone": "UTC",
		"public_url": flowURL, "geoip": map[string]any{"databases": []string{}}}); code != 200 {
		t.Fatal(code, out)
	}
	adminRole, _ := e.st.RoleByName(ctx, access.RoleAdministrator)
	viewerRole, _ := e.st.RoleByName(ctx, access.RoleViewer)

	hub := hubtest.New(t)
	auth := passkeytest.New(flowURL, "example.com")
	credID, pub := auth.Credential([]byte("USR-2"))
	hub.Users = []umbrellaid.User{
		{ID: "USR-1", Username: "alice", Name: "Alice", Email: "alice@example.com", Role: map[string]string{"id": "R3", "name": "On-call engineer"}, Groups: []string{"cn=noc,dc=example,dc=com"}},
		{ID: "USR-2", Username: "bob", Name: "Bob", Admin: true, Role: map[string]string{"id": "admin", "name": "Administrator"},
			Passkeys: []umbrellaid.Passkey{{ID: "PK-1", Name: "Windows Hello", CredentialID: passkey.Encode(credID), PublicKey: passkey.Encode(pub), UserHandle: passkey.Encode([]byte("USR-2"))}}},
		{ID: "USR-3", Username: "carol", Disabled: true, Role: map[string]string{"name": "On-call engineer"}},
		{ID: "USR-4", Username: "dave", Role: map[string]string{"name": "Guest"}},
		{ID: "USR-5", Username: "viewer", Role: map[string]string{"name": "On-call engineer"}},
	}
	// Step 1: the key is checked against the hub.
	code, check := admin.do("POST", "/api/settings/identity/check", map[string]any{"key": hub.ConnectionKey()})
	if code != 200 || check["application"] != "Umbrella Flow" || check["passkeys_here"] != true || len(check["conflicts"].([]any)) != 1 {
		t.Fatal(code, check)
	}
	if code, out := admin.do("POST", "/api/settings/identity/check", map[string]any{"key": "umbid1.garbage"}); code != 400 || out["error"] != "identity_key" {
		t.Fatal(code, out)
	}
	// Steps 2 and 3: roles and options.
	code, v := admin.do("PUT", "/api/settings/identity", map[string]any{"key": hub.ConnectionKey(), "enabled": true,
		"role_map": []any{map[string]any{"match": "On-call engineer", "role_id": viewerRole.ID}}, "admin_role_id": adminRole.ID,
		"default_role_id": 0, "link_local": true, "sso": true, "sync_users": true, "sync_policy": true, "sync_passkeys": true})
	if code != 200 || v["connected"] != true || v["status"].(map[string]any)["ok"] != true {
		t.Fatal(code, v)
	}
	if strings.Contains(e.fake.Get("flow/identity/umbrella")["client_secret"].(string), "secret-1") == false {
		t.Fatal("client secret not in OpenBao")
	}
	users := usersByName(t, admin)
	if users["alice"]["source"] != "umbrella" || users["alice"]["role"] != access.RoleViewer {
		t.Fatal(users["alice"])
	}
	if users["bob"]["role"] != access.RoleAdministrator || users["viewer"]["source"] != "umbrella" {
		t.Fatal(users["bob"], users["viewer"])
	}
	if _, ok := users["carol"]; ok {
		t.Fatal("a disabled hub user was created")
	}
	if _, ok := users["dave"]; ok {
		t.Fatal("a person without a mapped role was created")
	}
	// The hub's password policy applies and cannot be changed here.
	code, pol := admin.do("GET", "/api/settings/password-policy", nil)
	if code != 200 || pol["managed_by_hub"] != true || pol["policy"].(map[string]any)["min_length"] != float64(14) {
		t.Fatal(code, pol)
	}
	if code, _ := admin.do("PUT", "/api/settings/password-policy", map[string]any{"min_length": 8}); code != 409 {
		t.Fatal("hub policy overwritten", code)
	}
	// The sign-in page shows the hub's methods.
	code, m := e.client().do("GET", "/api/auth/methods", nil)
	if code != 200 || m["passkeys"] != true || len(m["umbrella"].(map[string]any)["methods"].([]any)) != 3 {
		t.Fatal(code, m)
	}

	// Single sign-in with idp_hint.
	hub.SignedIn = "USR-2"
	b := e.client()
	nf := noFollow(b)
	res, err := nf.Get(e.srv.URL + "/api/auth/umbrella/start?method=passkey")
	if err != nil || res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), hub.Server.URL+"/oauth2/authorize") {
		t.Fatal(err, res.StatusCode, res.Header.Get("Location"))
	}
	res, err = nf.Get(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatal(err)
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	if back.Path != umbrellaid.CallbackPath || hub.Hints[len(hub.Hints)-1] != "passkey" {
		t.Fatal(back, hub.Hints)
	}
	res, err = nf.Get(e.srv.URL + back.Path + "?" + back.RawQuery)
	if err != nil || res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatal(err, res.StatusCode, res.Header.Get("Location"))
	}
	if code, me := b.do("GET", "/api/auth/me", nil); code != 200 || me["user"].(map[string]any)["username"] != "bob" {
		t.Fatal(code, me)
	}

	// The hub's passkey signs in to Flow (the domain example.com covers flow.example.com).
	p := e.client()
	code, started := p.raw("POST", "/api/auth/passkey/begin", flowURL, nil)
	if code != 200 {
		t.Fatal(code, started)
	}
	code, out := p.raw("POST", "/api/auth/passkey/finish", flowURL, map[string]any{"ceremony": started["ceremony"], "credential": auth.Get(started["options"])})
	if code != 200 || out["user"].(map[string]any)["username"] != "bob" {
		t.Fatal(code, out)
	}

	// Deprovisioning: alice leaves the hub.
	hub.Users = hub.Users[1:]
	if code, v := admin.do("POST", "/api/settings/identity/sync", nil); code != 200 || v["status"].(map[string]any)["disabled"] != float64(1) {
		t.Fatal(code, v)
	}
	alice, _ := e.st.UserByExternal(ctx, store.SourceUmbrella, "USR-1")
	if !alice.Disabled {
		t.Fatal("alice not disabled")
	}
	// A wrong token is reported.
	hub.Key.Token = "umb_other"
	if code, v := admin.do("POST", "/api/settings/identity/sync", nil); code != 200 || v["status"].(map[string]any)["ok"] != false {
		t.Fatal(code, v)
	}
	_ = strconv.Itoa
}

func TestFlowPasskeysAndPolicyHistory(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	if code, out := admin.do("PUT", "/api/settings/passkeys", map[string]any{"enabled": true, "rp_id": "example.com"}); code != 200 || out["enabled"] != true {
		t.Fatal(code, out)
	}
	code, started := admin.raw("POST", "/api/auth/me/passkeys/begin", flowURL, nil)
	if code != 200 {
		t.Fatal(code, started)
	}
	auth := passkeytest.New(flowURL, "example.com")
	code, pk := admin.raw("POST", "/api/auth/me/passkeys/finish", flowURL, map[string]any{"ceremony": started["ceremony"], "credential": auth.Create(started["options"]), "name": "YubiKey"})
	if code != 201 || pk["name"] != "YubiKey" {
		t.Fatal(code, pk)
	}
	if code, _ := admin.raw("POST", "/api/auth/passkey/begin", "https://evil.example.org", nil); code != 400 {
		t.Fatal("foreign origin accepted", code)
	}
	b := e.client()
	_, started = b.raw("POST", "/api/auth/passkey/begin", flowURL, nil)
	code, out := b.raw("POST", "/api/auth/passkey/finish", flowURL, map[string]any{"ceremony": started["ceremony"], "credential": auth.Get(started["options"])})
	if code != 200 || out["user"].(map[string]any)["username"] != "admin" {
		t.Fatal(code, out)
	}

	// The corporate policy: common passwords and the history are refused.
	if code, out := admin.do("PUT", "/api/settings/password-policy", map[string]any{"min_length": 12, "require_digits": true, "min_digits": 1,
		"require_special": true, "min_special": 1, "require_mixed_case": true, "letters": "latin", "history_count": 3, "block_common": true,
		"lockout_attempts": 3, "lockout_minutes": 10}); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/auth/password", map[string]any{"current": "admin-password", "new": "Qwerty123456!"}); code != 400 || out["violations"].([]any)[0] != "common" {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/auth/password", map[string]any{"current": "admin-password", "new": "Battery-Staple-42"}); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/auth/password", map[string]any{"current": "Battery-Staple-42", "new": "Battery-Staple-42"}); code != 400 || out["violations"].([]any)[0] != "history" {
		t.Fatal(code, out)
	}
	// Lockout from the policy: 3 attempts.
	v := e.client()
	for i := 0; i < 3; i++ {
		v.do("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "nope"})
	}
	if code, _ := v.do("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "viewer-password"}); code != 429 {
		t.Fatal("policy lockout not applied", code)
	}
}
