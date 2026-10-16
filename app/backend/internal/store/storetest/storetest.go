// Package storetest gives tests a migrated store in a fresh PostgreSQL
// database that is dropped when the test ends.
//
// The server is FLOW_TEST_POSTGRES (a DSN of a database the user can create
// databases from), by default postgres://postgres:postgres@localhost:5432/postgres.
// FLOW_TEST_POSTGRES=off skips the tests.
package storetest

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/current/app/backend/internal/store"
)

const defaultDSN = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

// AdminDSN returns the DSN of the test server, skipping t when tests with PostgreSQL are off.
func AdminDSN(t testing.TB) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv("FLOW_TEST_POSTGRES"))
	switch strings.ToLower(v) {
	case "off", "false", "0", "no":
		t.Skip("FLOW_TEST_POSTGRES=off")
	case "", "on", "true", "1", "yes":
		return defaultDSN
	}
	return v
}

// NewDatabase creates an empty database and returns its DSN; it is dropped on cleanup.
func NewDatabase(t testing.TB) string {
	t.Helper()
	admin := AdminDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("PostgreSQL for tests (FLOW_TEST_POSTGRES, or =off to skip): %v", err)
	}
	defer conn.Close(ctx)
	name := "flow_test_" + strings.ToLower(rand.Text()[:12])
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Logf("drop %s: %v", name, err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
	})
	u, err := url.Parse(admin)
	if err != nil || u.Scheme == "" {
		// key=value DSN
		return admin + " dbname=" + name
	}
	u.Path = "/" + name
	return u.String()
}

// New returns a migrated store with the built-in roles in a fresh database.
func New(t testing.TB) *store.Store {
	t.Helper()
	dsn := NewDatabase(t)
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(fmt.Errorf("migrate: %w", err))
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

// OwnedDB is a fresh database owned by a fresh login role with a random password.
type OwnedDB struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

// DSN of the database.
func (o OwnedDB) DSN() string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(o.User, o.Password), Host: fmt.Sprintf("%s:%d", o.Host, o.Port),
		Path: "/" + o.Database, RawQuery: "sslmode=disable"}
	return u.String()
}

// NewOwnedDatabase creates a role and a database it owns; both are dropped on cleanup.
func NewOwnedDatabase(t testing.TB) OwnedDB {
	t.Helper()
	admin := AdminDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("PostgreSQL for tests (FLOW_TEST_POSTGRES, or =off to skip): %v", err)
	}
	defer conn.Close(ctx)
	suffix := strings.ToLower(rand.Text()[:12])
	o := OwnedDB{Host: cfg.Host, Port: int(cfg.Port), Database: "flow_test_" + suffix, User: "flow_test_" + suffix, Password: "pw-" + rand.Text()}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", o.User, o.Password)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s OWNER %s", o.Database, o.User)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+o.Database+" WITH (FORCE)")
		_, _ = c.Exec(ctx, "DROP ROLE IF EXISTS "+o.User)
	})
	return o
}
