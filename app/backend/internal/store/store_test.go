package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

func TestStore(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()

	// migrations are idempotent, built-in roles too
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatal(err)
	}
	if v, err := st.Version(ctx); err != nil || v < 1 {
		t.Fatal(v, err)
	}
	empty, err := st.IsEmpty(ctx)
	if err != nil || !empty {
		t.Fatal(empty, err)
	}

	roles, err := st.ListRoles(ctx)
	if err != nil || len(roles) != 2 {
		t.Fatal(roles, err)
	}
	admin, err := st.RoleByName(ctx, "administrator")
	if err != nil || len(admin.Permissions) != len(access.BuiltinRoles()[0].Permissions) || !admin.Builtin {
		t.Fatal(admin, err)
	}
	viewer, _ := st.RoleByName(ctx, access.RoleViewer)
	if _, err := st.UpdateRole(ctx, viewer.ID, "x", "", nil); !errors.Is(err, store.ErrBuiltin) {
		t.Fatal("built-in role changed", err)
	}
	custom, err := st.CreateRole(ctx, "NOC", "noc", []string{"settings.inventory:sync", "nope:x"})
	if err != nil || len(custom.Permissions) != 2 {
		t.Fatal(custom, err)
	}
	if _, err := st.CreateRole(ctx, "noc", "", nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("duplicate role", err)
	}

	u, err := st.CreateUser(ctx, store.NewUser{Username: "Alice", Name: "Alice A", RoleID: admin.ID})
	if err != nil || u.Role != access.RoleAdministrator || u.Source != store.SourceLocal {
		t.Fatal(u, err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "alice", RoleID: admin.ID}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("duplicate user", err)
	}
	if err := st.SetPasswordRef(ctx, u.ID, "openbao://flow/users/1#password_hash"); err != nil {
		t.Fatal(err)
	}
	if got, err := st.UserByUsername(ctx, "ALICE"); err != nil || got.ID != u.ID || got.PasswordRef == "" {
		t.Fatal(got, err)
	}
	if _, err := st.UserByUsername(ctx, "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if n, _ := st.CountEnabledAdmins(ctx); n != 1 {
		t.Fatal("admins", n)
	}
	if perms, _ := st.Permissions(ctx, u.ID); len(perms) != len(access.BuiltinRoles()[0].Permissions) {
		t.Fatal(perms)
	}
	if err := st.DeleteRole(ctx, custom.ID); err != nil {
		t.Fatal(err)
	}
	bob, err := st.UpsertDirectoryUser(ctx, "bob", "Bob", "bob@example.com", viewer.ID)
	if err != nil || bob.Source != store.SourceLDAP || bob.Role != access.RoleViewer {
		t.Fatal(bob, err)
	}
	if _, err := st.UpsertDirectoryUser(ctx, "alice", "x", "", viewer.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("local user taken over", err)
	}
	dis := true
	if bob, err = st.UpdateUser(ctx, bob.ID, store.UserUpdate{Disabled: &dis}); err != nil || !bob.Disabled {
		t.Fatal(bob, err)
	}
	if err := st.SetGroupRoles(ctx, []store.GroupRole{{GroupDN: "cn=noc,dc=x", RoleID: viewer.ID}}); err != nil {
		t.Fatal(err)
	}
	if g, _ := st.GroupRoles(ctx); len(g) != 1 || g[0].Role != access.RoleViewer {
		t.Fatal(g)
	}

	// sessions
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.CreateSession(ctx, store.Session{IDHash: "h1", UserID: u.ID, Created: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if ss, err := st.GetSession(ctx, "h1"); err != nil || ss.UserID != u.ID {
		t.Fatal(ss, err)
	}
	if n, err := st.PurgeSessions(ctx, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if err := st.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "h1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}

	// settings
	var v struct{ A int }
	if found, err := st.Setting(ctx, "x", &v); found || err != nil {
		t.Fatal(found, err)
	}
	if err := st.PutSetting(ctx, "x", map[string]int{"A": 3}); err != nil {
		t.Fatal(err)
	}
	if found, err := st.Setting(ctx, "x", &v); !found || err != nil || v.A != 3 {
		t.Fatal(found, err, v)
	}

	// saved views
	sv, err := st.CreateSavedView(ctx, u.ID, "Top AS", false, json.RawMessage(`{"dimensions":["SrcAS"]}`))
	if err != nil || sv.Owner != "Alice" {
		t.Fatal(sv, err)
	}
	if list, _ := st.SavedViews(ctx, bob.ID); len(list) != 0 {
		t.Fatal("private view visible", list)
	}
	if _, err := st.UpdateSavedView(ctx, sv.ID, "Top AS", true, sv.Request); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.SavedViews(ctx, bob.ID); len(list) != 1 {
		t.Fatal("shared view hidden", list)
	}
	if err := st.DeleteSavedView(ctx, sv.ID); err != nil {
		t.Fatal(err)
	}

	// classifiers
	if err := st.SetClassifiers(ctx, map[string][]string{"exporter": {`a`, `b`}, "interface": {}}); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.Classifiers(ctx); len(c["exporter"]) != 2 || c["exporter"][1] != "b" || len(c["interface"]) != 0 {
		t.Fatal(c)
	}
	if err := st.SetClassifiers(ctx, map[string][]string{"bogus": {}}); err == nil {
		t.Fatal("unknown kind")
	}

	// inventory db
	inv, err := st.InventoryDB(ctx)
	if err != nil || inv.Enabled || inv.Interval != 15*time.Minute || inv.LastSync != nil {
		t.Fatal(inv, err)
	}
	if err := st.SetInventoryDB(ctx, store.InventoryDB{Enabled: true, URL: "https://inv", TokenRef: "openbao://flow/inventory-db#token", Interval: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordInventorySync(ctx, store.SyncResult{At: now, OK: true, SyncStats: store.SyncStats{Devices: 3}}); err != nil {
		t.Fatal(err)
	}
	inv, _ = st.InventoryDB(ctx)
	if !inv.Enabled || inv.Interval != 5*time.Minute || inv.LastSync == nil || inv.LastSync.Devices != 3 || !inv.LastSync.OK {
		t.Fatal(inv)
	}

	// sampling overrides
	if err := st.SetSamplingOverrides(ctx, []store.SamplingOverride{{Exporter: netip.MustParsePrefix("192.0.2.1/32"), Rate: 1000}}); err != nil {
		t.Fatal(err)
	}
	if o, _ := st.SamplingOverrides(ctx); len(o) != 1 || o[0].Rate != 1000 || o[0].Exporter.String() != "192.0.2.1/32" {
		t.Fatal(o)
	}

	// audit
	if err := st.Audit(ctx, "alice", "user.create", "bob", "127.0.0.1", map[string]string{"role": "Viewer"}); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.AuditLog(ctx, 10, 0); len(a) != 1 || a[0].Action != "user.create" {
		t.Fatal(a)
	}

	// deleting a user deletes their views and sessions
	if err := st.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if empty, _ := st.IsEmpty(ctx); empty {
		t.Fatal("not empty")
	}
}
