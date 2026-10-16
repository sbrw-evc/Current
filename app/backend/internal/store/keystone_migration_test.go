package store_test

import (
	"context"
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/store"
	"github.com/sbrw-evc/current/app/backend/internal/store/storetest"
)

// TestSPAMigration upgrades a database of the version with its own sign-in:
// identity data goes, users keep their IDs, roles get their idents and tokens
// their owner.
func TestSPAMigration(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := store.MigrateTo(ctx, st, 6); err != nil {
		t.Fatal(err)
	}
	db := st.Pool()
	for _, q := range []string{
		`INSERT INTO roles (id, name, builtin) VALUES (1, 'Administrator', true), (2, 'Viewer', true), (3, 'On-call engineer', false),
			(4, 'Дежурный', false), (5, 'on call engineer', false)`,
		`INSERT INTO users (id, username, source, password_ref, role_id) VALUES (10, 'admin', 'local', 'openbao://flow/users/10#password_hash', 1),
			(11, 'jdoe', 'ldap', '', 3), (12, 'eve', 'entra', '', 2), (13, 'g@example.com', 'google', '', 2)`,
		`UPDATE users SET external_id = 'google-sub' WHERE id = 13`,
		`INSERT INTO passkeys (user_id, credential_id, public_key, user_handle) VALUES (10, '\x01', '\x02', '\x03')`,
		`INSERT INTO group_roles (group_dn, role_id) VALUES ('cn=noc,dc=example,dc=com', 3)`,
		`INSERT INTO service_accounts (id, name, role_id) VALUES (1, 'grafana', 2)`,
		`INSERT INTO api_tokens (service_account_id, name, token_hash, created_by) VALUES (1, 't1', 'h1', 'Admin'), (1, 't2', 'h2', 'nobody')`,
		`INSERT INTO settings (key, value) VALUES ('password_policy', '{}'), ('ldap', '{}'), ('general', '{"language":"en"}')`,
		`INSERT INTO sessions (id_hash, user_id) VALUES ('s1', 10)`,
	} {
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatal(err)
	}
	// Role 5 has the slug of role 3; role 4 has none in Latin letters.
	idents := map[int64]string{1: "admin", 2: "viewer", 3: "on-call-engineer", 4: "role-4", 5: "role-5"}
	roles, _ := st.ListRoles(ctx)
	for _, r := range roles {
		if want := idents[r.ID]; r.Ident != want {
			t.Errorf("role %d %q: ident %q, want %q", r.ID, r.Name, r.Ident, want)
		}
	}
	users, _ := st.ListUsers(ctx)
	if len(users) != 4 {
		t.Fatal(users)
	}
	for _, u := range users {
		if u.Source != store.SourceLegacy || u.ExternalID != "" || u.Disabled {
			t.Errorf("%+v", u)
		}
	}
	var n int
	for _, q := range []string{
		`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('passkeys', 'group_roles')`,
		`SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name IN ('password_ref', 'password_changed_at')`,
		`SELECT count(*) FROM settings WHERE key IN ('password_policy', 'ldap')`,
	} {
		if err := db.QueryRow(ctx, q).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d %v", q, n, err)
		}
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM settings WHERE key = 'general'`).Scan(&n); err != nil || n != 1 {
		t.Error("general settings lost", n, err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil || n != 1 {
		t.Error("sessions lost", n, err)
	}
	var owner *int64
	if err := db.QueryRow(ctx, `SELECT created_by_id FROM api_tokens WHERE name = 't1'`).Scan(&owner); err != nil || owner == nil || *owner != 10 {
		t.Error("token owner", owner, err)
	}
	if err := db.QueryRow(ctx, `SELECT created_by_id FROM api_tokens WHERE name = 't2'`).Scan(&owner); err != nil || owner != nil {
		t.Error("token of an unknown person", owner, err)
	}
	// The legacy admin is bound by the user name on their first Keystone sign-in.
	viewer, _ := st.RoleByIdent(ctx, "viewer")
	u, how, err := st.UpsertSPAUser(ctx, store.SPAUser{ExternalID: "usr_admin", Username: "ADMIN", RoleID: viewer.ID})
	if err != nil || how != store.SPABound || u.ID != 10 {
		t.Fatal(u, how, err)
	}

	// And back: the previous version still works with the accounts.
	if err := store.MigrateTo(ctx, st, -6); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE source = 'local'`).Scan(&n); err != nil || n != 4 {
		t.Fatal("down migration", n, err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}
