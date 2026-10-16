package setup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/spa/spatest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

// clickhouseForTest returns the test ClickHouse (FLOW_TEST_CLICKHOUSE, default
// localhost:9000 user default without password; "off" skips) with a fresh
// database name dropped on cleanup.
func clickhouseForTest(t *testing.T) config.ClickHouse {
	t.Helper()
	addr := strings.TrimSpace(os.Getenv("FLOW_TEST_CLICKHOUSE"))
	switch strings.ToLower(addr) {
	case "off", "false", "0", "no":
		t.Skip("FLOW_TEST_CLICKHOUSE=off")
	case "":
		addr = "localhost:9000"
	}
	ch := config.ClickHouse{Addr: addr, Username: os.Getenv("FLOW_TEST_CLICKHOUSE_USER"), Password: os.Getenv("FLOW_TEST_CLICKHOUSE_PASSWORD"),
		Database: "flow_setup_test_" + strings.ToLower(rand.Text()[:10])}
	ch, _ = ch.Normalize()
	t.Cleanup(func() {
		conn, err := ch.Open(context.Background(), ch.Password, "")
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.Exec(context.Background(), "DROP DATABASE IF EXISTS `"+ch.Database+"`")
	})
	return ch
}

func post(t *testing.T, h http.Handler, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out == nil {
		out = map[string]any{"_raw": rec.Body.String()}
	}
	return rec.Code, out
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// fakeInventory answers the device list for token "inv-token".
func fakeInventory(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dcim/devices/" || r.Header.Get("xc-token") != "inv-token-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"count": 42, "results": []}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// fakeUmbrella accepts the test event with Bearer "umb-token-secret".
func fakeUmbrella(t *testing.T, got *map[string]any) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer umb-token-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, got)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestCodeAndDefaults(t *testing.T) {
	env := map[string]string{"FLOW_SETUP_DEFAULTS_POSTGRES_HOST": "postgres", "FLOW_SETUP_DEFAULTS_POSTGRES_PASSWORD_REF": "plain-password-ignored",
		"FLOW_SETUP_DEFAULTS_CLICKHOUSE_ADDR": "clickhouse:9000", "FLOW_SETUP_DEFAULTS_CLICKHOUSE_PASSWORD_REF": "openbao://flow/clickhouse#password",
		"FLOW_SETUP_DEFAULTS_OPENBAO_ADDR": "http://openbao:8200", "FLOW_SETUP_DEFAULTS_OPENBAO_ROLE_ID_FILE": "/run/openbao/role_id",
		"FLOW_SETUP_DEFAULTS_OPENBAO_SECRET_ID_FILE": "/run/openbao/secret_id"}
	d := DefaultsFromEnv(func(k string) string { return env[k] })
	if d.Postgres.Password != "" || d.ClickHouse.Password == "" || d.OpenBao.Auth != config.AuthAppRole || d.Collector.NetFlowAddr != ":2055" {
		t.Fatalf("%+v", d)
	}
	h := New(Options{DataDir: t.TempDir(), Token: "right", Defaults: d}, nil).Handler()
	code, body := get(t, h, "/api/setup")
	if code != 200 || !strings.Contains(body, `"required":true`) || !strings.Contains(body, `"password_set":true`) ||
		!strings.Contains(body, `"role_id_set":true`) || strings.Contains(body, "/run/openbao") || strings.Contains(body, "openbao://") {
		t.Fatal(code, body)
	}
	if code, out := post(t, h, "/api/setup/check-code", map[string]string{"setup_code": "right"}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	for i := 0; i < maxFailures; i++ {
		if code, out := post(t, h, "/api/setup/check-code", map[string]string{"setup_code": "wrong"}); code != 401 || out["error"] != "setup_code_invalid" {
			t.Fatal(code, out)
		}
	}
	if code, out := post(t, h, "/api/setup/check-code", map[string]string{"setup_code": "right"}); code != 429 {
		t.Fatal("no lockout", code, out)
	}
	if code, _ := get(t, h, "/api/auth/me"); code != http.StatusServiceUnavailable {
		t.Fatal(code)
	}
}

func TestStepChecks(t *testing.T) {
	fake, _ := secretstest.New(t)
	db := storetest.NewOwnedDatabase(t)
	ch := clickhouseForTest(t)
	inv := fakeInventory(t)
	var event map[string]any
	umb := fakeUmbrella(t, &event)
	h := New(Options{DataDir: t.TempDir(), Token: "code"}, nil).Handler()
	step := func(name string, body map[string]any) (bool, map[string]any) {
		t.Helper()
		body["setup_code"] = "code"
		code, out := post(t, h, "/api/setup/test/"+name, body)
		if code != 200 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		return out["ok"] == true, out
	}
	if ok, out := step("openbao", map[string]any{"addr": fake.Server.URL, "auth": "approle", "role_id": secretstest.RoleID, "secret_id": secretstest.SecretID}); !ok {
		t.Fatal(out)
	}
	if ok, _ := step("openbao", map[string]any{"addr": fake.Server.URL, "auth": "approle", "role_id": "bad", "secret_id": "bad"}); ok {
		t.Fatal("bad AppRole accepted")
	}
	if code, _ := post(t, h, "/api/setup/test/openbao", map[string]any{"setup_code": "code", "role_id_file": "/etc/passwd"}); code != 400 {
		t.Fatal("file paths must not be accepted from the API", code)
	}
	ok, out := step("postgres", map[string]any{"host": db.Host, "port": db.Port, "database": db.Database, "username": db.User, "password": db.Password, "sslmode": "disable"})
	if !ok || out["details"].(map[string]any)["has_state"] != false {
		t.Fatal(out)
	}
	if ok, _ := step("postgres", map[string]any{"host": db.Host, "port": db.Port, "database": db.Database, "username": db.User, "password": "wrong", "sslmode": "disable"}); ok {
		t.Fatal("wrong password accepted: the test PostgreSQL must check passwords on TCP (scram-sha-256 or md5 in pg_hba.conf, not trust)")
	}
	if ok, out := step("clickhouse", map[string]any{"addr": ch.Addr, "database": ch.Database, "username": ch.Username, "password": ch.Password}); !ok || out["details"].(map[string]any)["version"] == "" {
		if ok {
			t.Fatal(out)
		}
		t.Fatal("this test needs ClickHouse at FLOW_TEST_CLICKHOUSE (default localhost:9000):", out)
	}
	if ok, _ := step("clickhouse", map[string]any{"addr": "127.0.0.1:1"}); ok {
		t.Fatal("closed port accepted")
	}
	if ok, _ := step("nats", map[string]any{"url": ""}); !ok {
		t.Fatal("in-process bus")
	}
	if ok, _ := step("nats", map[string]any{"url": "nats://user:pw@nats:4222"}); ok {
		t.Fatal("credentials in the URL accepted")
	}
	if ok, out := step("inventory", map[string]any{"url": inv.URL, "token": "inv-token-secret"}); !ok || out["details"].(map[string]any)["devices"] != float64(42) {
		t.Fatal(out)
	}
	if ok, _ := step("inventory", map[string]any{"url": inv.URL, "token": "wrong"}); ok {
		t.Fatal("wrong inventory token accepted")
	}
	if ok, out := step("umbrella", map[string]any{"ingest_url": umb.URL + "/api/ingest/network-flow", "token": "umb-token-secret"}); !ok || event["signal"] != "flow.setup.test" {
		t.Fatal(out, event)
	}
	if ok, _ := step("umbrella", map[string]any{"ingest_url": umb.URL + "/api/ingest/network-flow", "token": "wrong"}); ok {
		t.Fatal("wrong umbrella token accepted")
	}
	if ok, _ := step("geoip", map[string]any{"databases": []string{"/nonexistent.mmdb"}}); ok {
		t.Fatal("missing GeoIP file accepted")
	}
	if code, _ := post(t, h, "/api/setup/test/bogus", map[string]any{"setup_code": "code"}); code != 404 {
		t.Fatal(code)
	}
	if code, _ := post(t, h, "/api/setup/test/postgres", map[string]any{"setup_code": "wrong"}); code != 401 {
		t.Fatal(code)
	}
}

// scanForSecrets fails when any PostgreSQL row or flow.json contains one of the values.
func scanForSecrets(t *testing.T, st *store.Store, dir string, values ...string) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.Pool().Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	var all strings.Builder
	for _, tbl := range tables {
		r, err := st.Pool().Query(ctx, `SELECT t::text FROM "`+tbl+`" t`)
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			var s string
			_ = r.Scan(&s)
			all.WriteString(tbl + ": " + s + "\n")
		}
		r.Close()
	}
	b, _ := os.ReadFile(filepath.Join(dir, config.FileName))
	all.WriteString("flow.json: " + string(b))
	for _, v := range values {
		if v != "" && strings.Contains(all.String(), v) {
			t.Errorf("plaintext secret %q found:\n%s", v, all.String())
		}
	}
}

func TestSPAStep(t *testing.T) {
	sp := spatest.New(t)
	h := New(Options{DataDir: t.TempDir(), Token: "code", Defaults: DefaultsFromEnv(func(k string) string {
		return map[string]string{"SPA_CONNECTION_KEY_FILE": "/run/secrets/spa"}[k]
	})}, nil).Handler()
	if code, body := get(t, h, "/api/setup"); code != 200 || !strings.Contains(body, `"spa":{"from_env":true}`) {
		t.Fatal(code, body)
	}
	step := func(body map[string]any) map[string]any {
		t.Helper()
		body["setup_code"] = "code"
		code, out := post(t, h, "/api/setup/test/spa", body)
		if code != 200 {
			t.Fatal(code, out)
		}
		return out
	}
	if out := step(map[string]any{"connection_key": sp.ConnectionKey(), "public_url": "https://flow.example"}); out["ok"] != true ||
		out["details"].(map[string]any)["redirect_uri"] != "https://flow.example/api/auth/spa/callback" ||
		out["details"].(map[string]any)["application"] != "Umbrella Flow" {
		t.Fatal(out)
	}
	if out := step(map[string]any{"connection_key": "umbid1.old-key"}); out["ok"] == true || !strings.Contains(out["error"].(string), "spa1.") {
		t.Fatal("a key of another kind accepted", out)
	}
	k := sp.Key
	k.ClientSecret = "wrong"
	if out := step(map[string]any{"connection_key": k.String()}); out["ok"] == true || !strings.Contains(out["error"].(string), "client secret") {
		t.Fatal("a wrong client secret accepted", out)
	}
	k = sp.Key
	k.Token = "wrong"
	if out := step(map[string]any{"connection_key": k.String()}); out["ok"] == true || !strings.Contains(out["error"].(string), "federation token") {
		t.Fatal("a wrong token accepted", out)
	}
}

func TestCompleteDockerStyle(t *testing.T) {
	fake, _ := secretstest.New(t)
	db := storetest.NewOwnedDatabase(t)
	ch := clickhouseForTest(t)
	inv := fakeInventory(t)
	var event map[string]any
	umb := fakeUmbrella(t, &event)
	sp := spatest.New(t)
	// openbao-init seeded the PostgreSQL password; the AppRole credentials are files.
	fake.Set("flow/bootstrap/postgres", map[string]any{"password": db.Password})
	secretsDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(secretsDir, "role_id"), []byte(secretstest.RoleID+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(secretsDir, "secret_id"), []byte(secretstest.SecretID+"\n"), 0o644)
	env := map[string]string{
		"FLOW_SETUP_DEFAULTS_OPENBAO_ADDR": fake.Server.URL, "FLOW_SETUP_DEFAULTS_OPENBAO_ROLE_ID_FILE": filepath.Join(secretsDir, "role_id"),
		"FLOW_SETUP_DEFAULTS_OPENBAO_SECRET_ID_FILE": filepath.Join(secretsDir, "secret_id"),
		"FLOW_SETUP_DEFAULTS_POSTGRES_HOST":          db.Host, "FLOW_SETUP_DEFAULTS_POSTGRES_PORT": itoa(db.Port),
		"FLOW_SETUP_DEFAULTS_POSTGRES_DATABASE": db.Database, "FLOW_SETUP_DEFAULTS_POSTGRES_USERNAME": db.User,
		"FLOW_SETUP_DEFAULTS_POSTGRES_SSLMODE": "disable", "FLOW_SETUP_DEFAULTS_POSTGRES_PASSWORD_REF": "openbao://flow/bootstrap/postgres#password",
		"FLOW_SETUP_DEFAULTS_CLICKHOUSE_ADDR": ch.Addr, "FLOW_SETUP_DEFAULTS_CLICKHOUSE_DATABASE": ch.Database,
	}
	dir := t.TempDir()
	token, _ := Token(dir, "")
	var got *Result
	h := New(Options{DataDir: dir, Token: token, Defaults: DefaultsFromEnv(func(k string) string { return env[k] })},
		func(r Result) { got = &r }).Handler()

	// a step check resolves the seeded password through the default OpenBao
	if code, out := post(t, h, "/api/setup/test/postgres", map[string]any{"setup_code": token}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}

	in := map[string]any{"setup_code": token, "language": "ru", "theme": "dark", "timezone": "Europe/Moscow", "public_url": "https://flow.example",
		"inventory": map[string]any{"enabled": true, "url": inv.URL, "token": "inv-token-secret", "interval": "10m"},
		"umbrella":  map[string]any{"enabled": true, "ingest_url": umb.URL + "/api/ingest/network-flow", "token": "umb-token-secret"},
		"spa":       map[string]any{"connection_key": "spa1.garbage"}}
	if code, out := post(t, h, "/api/setup", in); code != 400 || out["error"] != "spa_unavailable" {
		t.Fatal(code, out)
	}
	in["spa"] = map[string]any{"connection_key": sp.ConnectionKey()}
	in["timezone"] = "Mars/Olympus"
	if code, out := post(t, h, "/api/setup", in); code != 400 || out["error"] != "general_invalid" {
		t.Fatal(code, out)
	}
	in["timezone"] = "Europe/Moscow"
	in["umbrella"].(map[string]any)["token"] = "wrong"
	if code, out := post(t, h, "/api/setup", in); code != 400 || out["error"] != "umbrella_unavailable" {
		t.Fatal(code, out)
	}
	in["umbrella"].(map[string]any)["token"] = "umb-token-secret"
	if code, out := post(t, h, "/api/setup", in); code != 200 {
		if out["error"] == "clickhouse_unavailable" {
			t.Fatal("this test needs ClickHouse at FLOW_TEST_CLICKHOUSE (default localhost:9000):", code, out)
		}
		t.Fatal(code, out)
	}
	if got == nil || got.Store == nil || got.Vault == nil {
		t.Fatal("done not called")
	}
	defer got.Store.Close()
	ctx := context.Background()

	if _, err := os.Stat(filepath.Join(dir, config.SetupTokenFile)); !os.IsNotExist(err) {
		t.Fatal("setup token kept")
	}
	if code, _ := get(t, h, "/api/setup"); code != 404 {
		t.Fatal("setup still open", code)
	}
	f, found, err := config.Read(dir)
	if err != nil || !found || f.Postgres.Password != "openbao://flow/bootstrap/postgres#password" || f.OpenBao.RoleIDFile == "" || f.OpenBao.RoleID != "" {
		t.Fatalf("%+v %v %v", f, found, err)
	}
	if dsn, err := f.PostgresDSN(got.Vault); err != nil || !strings.Contains(dsn, db.Database) {
		t.Fatal(dsn, err)
	}
	if fake.Get("flow/inventory-db")["token"] != "inv-token-secret" || fake.Get("flow/umbrella")["token"] != "umb-token-secret" {
		t.Fatal("integration tokens not in OpenBao")
	}
	if fake.Get("flow/keys")["session"] == nil {
		t.Fatal("session keys not created")
	}
	// No first administrator: people come from SPA, whose key is in OpenBao.
	if n, _ := got.Store.CountUsers(ctx); n != 0 {
		t.Fatal("users created by the setup", n)
	}
	if fake.Get("flow/spa")["connection_key"] != sp.ConnectionKey() {
		t.Fatal("SPA connection key not in OpenBao")
	}
	if r, err := got.Store.RoleByIdent(ctx, "admin"); err != nil || r.Name != access.RoleAdministrator {
		t.Fatal(r, err)
	}
	var g General
	if found, _ := got.Store.Setting(ctx, SettingGeneral, &g); !found || g.Theme != "dark" || g.Timezone != "Europe/Moscow" {
		t.Fatal(g)
	}
	invCfg, _ := got.Store.InventoryDB(ctx)
	if !invCfg.Enabled || invCfg.TokenRef != "openbao://flow/inventory-db#token" {
		t.Fatal(invCfg)
	}
	conn, _ := f.ClickHouse.Open(ctx, "", "")
	var n uint64
	_ = conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = 'flows'", ch.Database).Scan(&n)
	conn.Close()
	if n != 1 {
		t.Fatal("ClickHouse schema not created")
	}

	scanForSecrets(t, got.Store, dir, db.Password, sp.Key.ClientSecret, sp.Key.Token, "inv-token-secret", "umb-token-secret",
		secretstest.RoleID, secretstest.SecretID, fake.Get("flow/keys")["session"].(string))

	// attach to the existing state: refused without attach_existing
	dir2 := t.TempDir()
	var got2 *Result
	h2 := New(Options{DataDir: dir2, Token: "code2", Defaults: DefaultsFromEnv(func(k string) string { return env[k] })},
		func(r Result) { got2 = &r }).Handler()
	if code, out := post(t, h2, "/api/setup/test/postgres", map[string]any{"setup_code": "code2"}); code != 200 ||
		out["details"].(map[string]any)["has_state"] != true {
		t.Fatal(code, out)
	}
	if code, out := post(t, h2, "/api/setup", map[string]any{"setup_code": "code2"}); code != 409 || out["error"] != "postgres_has_state" {
		t.Fatal(code, out)
	}
	if code, out := post(t, h2, "/api/setup", map[string]any{"setup_code": "code2", "postgres": map[string]any{"attach_existing": true}}); code != 200 {
		t.Fatal(code, out)
	}
	defer got2.Store.Close()
	if found, _ := got2.Store.Setting(ctx, SettingGeneral, &g); !found || g.Theme != "dark" {
		t.Fatal("settings changed by attaching", g)
	}
}

func TestCompleteRequiresOpenBao(t *testing.T) {
	fake, _ := secretstest.New(t)
	db := storetest.NewOwnedDatabase(t)
	ch := clickhouseForTest(t)
	h := New(Options{DataDir: t.TempDir(), Token: "c"}, nil).Handler()
	body := map[string]any{"setup_code": "c",
		"openbao":    map[string]any{"addr": fake.Server.URL, "auth": "approle", "role_id": secretstest.RoleID, "secret_id": secretstest.SecretID},
		"postgres":   map[string]any{"host": db.Host, "port": db.Port, "database": db.Database, "username": db.User, "password": db.Password, "sslmode": "disable"},
		"clickhouse": map[string]any{"addr": ch.Addr, "database": ch.Database}}
	body["openbao"] = map[string]any{"addr": fake.Server.URL, "auth": "approle", "role_id": "x", "secret_id": "y"}
	if code, out := post(t, h, "/api/setup", body); code != 400 || out["error"] != "openbao_unavailable" {
		t.Fatal(code, out)
	}
	delete(body, "openbao")
	if code, out := post(t, h, "/api/setup", body); code != 400 || out["error"] != "openbao_invalid" {
		t.Fatal("OpenBao must be required", code, out)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
