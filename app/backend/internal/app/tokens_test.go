package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
)

// bearer calls the API with an API token (no cookies, no CSRF).
func (e *env) bearer(token, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.client()
	admin.login("admin", "admin-password")
	viewer := e.client()
	viewer.login("viewer", "viewer-password")
	viewerRole, _ := e.st.RoleByName(ctx, access.RoleViewer)
	adminRole, _ := e.st.RoleByName(ctx, access.RoleAdministrator)

	if code, _ := viewer.do("GET", "/api/tokens", nil); code != 403 {
		t.Fatal("viewer lists tokens", code)
	}
	code, sa := admin.do("POST", "/api/service-accounts", map[string]any{"name": "inventory-db", "description": "Inventory DB integration", "role_id": viewerRole.ID})
	if code != 201 || sa["role"] != access.RoleViewer || sa["created_by"] != "admin" {
		t.Fatal(code, sa)
	}
	saID := sa["id"]
	if code, out := admin.do("POST", "/api/service-accounts", map[string]any{"name": "Inventory-DB", "role_id": viewerRole.ID}); code != 409 {
		t.Fatal("duplicate name", code, out)
	}
	if code, out := admin.do("POST", "/api/service-accounts", map[string]any{"name": "bad name", "role_id": viewerRole.ID}); code != 400 {
		t.Fatal(code, out)
	}

	// Issue: the plaintext comes once; only the HMAC is stored.
	code, tok := admin.do("POST", "/api/tokens", map[string]any{"service_account_id": saID, "name": "prod",
		"expires_at": time.Now().AddDate(0, 1, 0).Format(time.DateOnly)})
	if code != 201 || tok["active"] != true || tok["expires_at"] == nil {
		t.Fatal(code, tok)
	}
	plain := tok["token"].(string)
	if !strings.HasPrefix(plain, "flow_") || len(plain) != 48 || !strings.HasPrefix(plain, strings.TrimSuffix(tok["display"].(string), "…")) {
		t.Fatal(plain, tok["display"])
	}
	var stored string
	_ = e.st.Pool().QueryRow(ctx, `SELECT token_hash FROM api_tokens`).Scan(&stored)
	if stored == "" || strings.Contains(stored, plain[5:]) {
		t.Fatal("token stored in plain text")
	}
	if e.fake.Get("flow/keys")["tokens"] == nil {
		t.Fatal("token key not in OpenBao")
	}
	if code, out := admin.do("POST", "/api/tokens", map[string]any{"service_account_id": saID, "name": "old", "expires_at": "2020-01-01"}); code != 400 {
		t.Fatal("past expiry", code, out)
	}
	code, list := admin.do("GET", "/api/tokens", nil)
	if code != 200 || len(list["results"].([]any)) != 1 || list["results"].([]any)[0].(map[string]any)["token"] != nil {
		t.Fatal(code, list)
	}

	// Use: the role of the service account, no CSRF; last_used_at recorded.
	if code, out := e.bearer(plain, "POST", "/api/visualize", map[string]any{"limit": 1}); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := e.bearer(plain, "GET", "/api/auth/me", nil); code != 200 || out["user"].(map[string]any)["username"] != "service:inventory-db" {
		t.Fatal(code, out)
	}
	if code, _ := e.bearer(plain, "GET", "/api/users", nil); code != 403 {
		t.Fatal("viewer token reads users", code)
	}
	if code, out := e.bearer(plain+"x", "GET", "/api/schema", nil); code != 401 || out["error"] != "invalid_token" {
		t.Fatal(code, out)
	}
	if code, _ := e.bearer("flow_"+strings.Repeat("A", 43), "GET", "/api/schema", nil); code != 401 {
		t.Fatal("unknown token", code)
	}
	_, list = admin.do("GET", "/api/tokens", nil)
	if list["results"].([]any)[0].(map[string]any)["last_used_at"] == nil {
		t.Fatal("last_used_at not set")
	}
	var uses int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'token.use_new_address'`).Scan(&uses)
	if uses != 1 {
		t.Fatalf("new address audited %d times", uses)
	}

	// A token of an account with tokens:edit manages tokens without CSRF.
	code, adminSA := admin.do("POST", "/api/service-accounts", map[string]any{"name": "automation", "role_id": adminRole.ID})
	if code != 201 {
		t.Fatal(code, adminSA)
	}
	_, adminTok := admin.do("POST", "/api/tokens", map[string]any{"service_account_id": adminSA["id"], "name": "ci"})
	if code, out := e.bearer(adminTok["token"].(string), "GET", "/api/service-accounts", nil); code != 200 || len(out["results"].([]any)) != 2 {
		t.Fatal(code, out)
	}

	// Revoke: the token stops working at once.
	id := itoa(int(tok["id"].(float64)))
	if code, out := admin.do("DELETE", "/api/tokens/"+id, nil); code != 200 || out["active"] != false || out["revoked_by"] != "admin" {
		t.Fatal(code, out)
	}
	if code, _ := e.bearer(plain, "GET", "/api/schema", nil); code != 401 {
		t.Fatal("revoked token works", code)
	}
	for _, action := range []string{"service_account.create", "token.create", "token.revoke"} {
		var n int
		_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n)
		if n == 0 {
			t.Errorf("%s not audited", action)
		}
	}
	// Deleting the account removes its tokens.
	if code, _ := admin.do("DELETE", "/api/service-accounts/"+itoa(int(adminSA["id"].(float64))), nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := e.bearer(adminTok["token"].(string), "GET", "/api/schema", nil); code != 401 {
		t.Fatal("token of a deleted account works", code)
	}

	// No privilege escalation: a role with more rights than the caller is refused.
	limited, err := e.st.CreateRole(ctx, "Token admins", "", []string{access.TokensEdit})
	if err != nil {
		t.Fatal(err)
	}
	_, saLim := admin.do("POST", "/api/service-accounts", map[string]any{"name": "limited", "role_id": limited.ID})
	_, limTok := admin.do("POST", "/api/tokens", map[string]any{"service_account_id": saLim["id"], "name": "t"})
	if code, out := e.bearer(limTok["token"].(string), "POST", "/api/service-accounts", map[string]any{"name": "root", "role_id": adminRole.ID}); code != 403 || out["error"] != "role_not_grantable" {
		t.Fatal(code, out)
	}
}
