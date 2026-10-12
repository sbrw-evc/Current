package app

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

func TestOpenBaoMigrate(t *testing.T) {
	auth.Iterations = 1000
	ctx := context.Background()
	st := storetest.New(t)
	srcFake, vault := secretstest.New(t)
	dstFake, _ := secretstest.New(t)
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	adminRole, _ := st.RoleByName(ctx, access.RoleAdministrator)
	u, _ := st.CreateUser(ctx, store.NewUser{Username: "admin", RoleID: adminRole.ID})
	ref, _ := auth.NewPasswords(vault).Set(ctx, u.ID, "admin-password")
	_ = st.SetPasswordRef(ctx, u.ID, ref)
	// References in a column and in a JSON setting.
	invRef, _ := vault.PutRef(ctx, "inventory-db", "token", "inv-token")
	inv, _ := st.InventoryDB(ctx)
	inv.TokenRef, inv.URL = invRef, "https://inventory.example"
	_ = st.SetInventoryDB(ctx, inv)
	_ = st.PutSetting(ctx, "umbrella", map[string]any{"token_ref": "openbao://flow/umbrella#token", "other": "openbao://elsewhere/x#y"})

	dir := t.TempDir()
	now := time.Now().UTC()
	cur := config.OpenBao{Addr: srcFake.Server.URL, Mount: "flow", Auth: config.AuthAppRole, RoleID: secretstest.RoleID, SecretID: secretstest.SecretID}
	file := config.File{OpenBao: cur, Postgres: config.Postgres{Host: "db", Password: "openbao://flow/postgres#password"}, CompletedAt: &now}
	if err := config.Write(dir, file); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Version: "test", DataDir: dir}, Deps{Config: file, Store: st, Vault: vault})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, st: st, fake: srcFake}
	c := e.client()
	c.login("admin", "admin-password")

	target := map[string]any{"addr": dstFake.Server.URL, "mount": "flow-new", "auth": "approle", "role_id": secretstest.RoleID, "secret_id": secretstest.SecretID}
	if code, out := c.do("POST", "/api/settings/openbao/probe", target); code != 200 || out["ok"] != true || out["secrets"] != float64(0) {
		t.Fatal(code, out)
	}
	if code, out := c.do("POST", "/api/settings/openbao/probe", map[string]any{"addr": dstFake.Server.URL, "mount": "x", "auth": "approle", "role_id": "bad", "secret_id": "bad"}); code != 200 || out["ok"] != false {
		t.Fatal(code, out)
	}
	if code, out := c.do("POST", "/api/settings/openbao/migrate", map[string]any{"target": map[string]any{"addr": srcFake.Server.URL, "mount": "flow"}}); code != 400 || out["error"] != "openbao_same_store" {
		t.Fatal(code, out)
	}
	// A target with secrets needs a confirmation.
	dstFake.Set("flow-new/old", map[string]any{"v": "1"})
	if code, out := c.do("POST", "/api/settings/openbao/migrate", map[string]any{"target": target}); code != 409 || out["error"] != "openbao_target_not_empty" {
		t.Fatal(code, out)
	}
	code, out := c.do("POST", "/api/settings/openbao/migrate", map[string]any{"target": target, "overwrite": true})
	if code != 200 || out["mount"] != "flow-new" || out["copied"] != float64(3) {
		t.Fatal(code, out)
	}

	// Copied as is; the source is intact.
	if dstFake.Get("flow-new/inventory-db")["token"] != "inv-token" || dstFake.Get("flow-new/keys")["session"] == nil ||
		dstFake.Get("flow-new/users/" + itoa(int(u.ID)))["password_hash"] == nil {
		t.Fatal("not copied", dstFake.Paths())
	}
	if srcFake.Get("flow/inventory-db") == nil {
		t.Fatal("source changed")
	}
	// References follow the new mount.
	inv, _ = st.InventoryDB(ctx)
	if inv.TokenRef != "openbao://flow-new/inventory-db#token" {
		t.Fatal(inv.TokenRef)
	}
	var umb map[string]string
	_, _ = st.Setting(ctx, "umbrella", &umb)
	if umb["token_ref"] != "openbao://flow-new/umbrella#token" || umb["other"] != "openbao://elsewhere/x#y" {
		t.Fatal(umb)
	}
	written, _, err := config.Read(dir)
	if err != nil || written.OpenBao.Addr != dstFake.Server.URL || written.OpenBao.Mount != "flow-new" ||
		written.Postgres.Password != "openbao://flow-new/postgres#password" || written.CompletedAt == nil {
		t.Fatalf("flow.json %+v %v", written, err)
	}
	// Live: the running client now reads and writes the new OpenBao.
	if vault.Mount() != "flow-new" {
		t.Fatal("client not switched")
	}
	if v, err := vault.Resolve(inv.TokenRef); err != nil || v != "inv-token" {
		t.Fatal(v, err)
	}
	if code, _ := c.do("GET", "/api/auth/me", nil); code != 200 {
		t.Fatal("session lost after the switch", code)
	}
	c2 := e.client()
	c2.login("admin", "admin-password") // password hash from the new OpenBao
	if code, out := c.do("GET", "/api/settings/openbao", nil); code != 200 || out["addr"] != dstFake.Server.URL || out["mount"] != "flow-new" {
		t.Fatal(code, out)
	}
	if code, out := c.do("GET", "/api/settings/openbao", nil); code != 200 || !strings.Contains(stringify(out), `"renewal"`) {
		t.Fatal(code, out)
	}
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'settings.openbao.migrate'`).Scan(&n)
	if n != 1 {
		t.Fatal("not audited")
	}
}

func stringify(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, y := range x {
				b.WriteString(`"` + k + `"`)
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(v)
	return b.String()
}
