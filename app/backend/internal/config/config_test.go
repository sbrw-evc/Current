package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadEnvDefaults(t *testing.T) {
	e, err := LoadEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if e.Addr != ":8080" || e.NetFlowAddr != ":2055" || e.SFlowAddr != ":6343" || e.Role != RoleAll ||
		e.StartupWait != 2*time.Minute || e.NATSURL != "" || e.SecureCookies {
		t.Fatalf("%+v", e)
	}
}

func TestLoadEnvValues(t *testing.T) {
	env := map[string]string{"FLOW_ROLE": "collector", "FLOW_SECURE_COOKIES": "true",
		"FLOW_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1", "FLOW_STARTUP_WAIT": "5s", "FLOW_NATS_URL": "nats://nats:4222"}
	e, err := LoadEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if e.Role != RoleCollector || !e.SecureCookies || len(e.TrustedProxies) != 2 || e.StartupWait != 5*time.Second ||
		e.NATSURL != "nats://nats:4222" {
		t.Fatalf("%+v", e)
	}
	if e.Role.NeedsConfig() || !RoleAll.Runs(RoleEnricher) || RoleAPI.Runs(RoleCollector) {
		t.Fatal("role logic")
	}
	if _, err := LoadEnv(func(k string) string { return map[string]string{"FLOW_ROLE": "x"}[k] }); err == nil {
		t.Fatal("bad role accepted")
	}
}

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, found, err := Read(dir); found || err != nil {
		t.Fatal(found, err)
	}
	now := time.Now().UTC()
	in := File{Postgres: Postgres{DSN: "openbao://flow/postgres#dsn"}, ClickHouse: ClickHouse{Addr: "ch", Database: "flow"}, CompletedAt: &now}
	if err := Write(dir, in); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, FileName))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	out, found, err := Read(dir)
	if err != nil || !found || out.Postgres.DSN != in.Postgres.DSN || out.ClickHouse.Addr != "ch" {
		t.Fatal(out, found, err)
	}
	if dsn, err := (File{Postgres: Postgres{DSN: "postgres://x"}}).PostgresDSN(nil); err != nil || dsn != "postgres://x" {
		t.Fatal(dsn, err)
	}
	if _, err := out.PostgresDSN(nil); err == nil {
		t.Fatal("ref without OpenBao must fail")
	}
}

func TestClickHouseNormalize(t *testing.T) {
	c, err := ClickHouse{Addr: "ch1, ch2:9001"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if a := c.Addrs(); len(a) != 2 || a[0] != "ch1:9000" || a[1] != "ch2:9001" || c.Database != "flow" || c.Username != "default" {
		t.Fatal(c, a)
	}
	if _, err := (ClickHouse{Addr: "x", Database: "a;drop"}).Normalize(); err == nil {
		t.Fatal("bad database accepted")
	}
	if _, err := (OpenBao{Addr: "http://bao:8200", Token: "t"}).Normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgres(t *testing.T) {
	p, err := Postgres{Host: "pg", Username: "flow"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if dsn := p.BuildDSN("p@ss"); dsn != "postgres://flow:p%40ss@pg:5432/flow?sslmode=prefer" {
		t.Fatal(dsn)
	}
	f := File{Postgres: Postgres{Host: "pg", Port: 5432, Database: "flow", Username: "flow", SSLMode: "disable", Password: "x"}}
	if dsn, err := f.PostgresDSN(nil); err != nil || dsn != "postgres://flow:x@pg:5432/flow?sslmode=disable" {
		t.Fatal(dsn, err)
	}
	if _, err := (Postgres{Host: "pg", Username: "u", SSLMode: "bogus"}).Normalize(); err == nil {
		t.Fatal("bad sslmode")
	}
}
