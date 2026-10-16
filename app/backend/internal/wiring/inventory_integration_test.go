package wiring_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/access"
	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/auth"
	"github.com/sbrw-evc/current/app/backend/internal/flow"
	"github.com/sbrw-evc/current/app/backend/internal/keystone"
	"github.com/sbrw-evc/current/app/backend/internal/keystone/keystonetest"
	"github.com/sbrw-evc/current/app/backend/internal/query"
	"github.com/sbrw-evc/current/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/current/app/backend/internal/setup"
	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse/chtest"
	"github.com/sbrw-evc/current/app/backend/internal/store"
	"github.com/sbrw-evc/current/app/backend/internal/store/storetest"
	"github.com/sbrw-evc/current/app/backend/internal/wiring"
)

// fakeInventoryDB serves internal/inventory/testdata (devices edge-01 / core-01,
// edge-01 xe-0/0/0 = interface 2 on circuit TEL-123 = circuit 1 with a
// 1 Gbit/s commit, IPAM address 10.1.0.50) to the read token, and records
// POST /api/v1/ipam/ip-addresses/ made with the editor token.
type fakeInventoryDB struct {
	srv     *httptest.Server
	mu      sync.Mutex
	created []map[string]any
	reject  bool
}

func newFakeInventoryDB(t *testing.T) *fakeInventoryDB {
	f := &fakeInventoryDB{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
		if r.Method == http.MethodPost && p == "ipam/ip-addresses" {
			if r.Header.Get("xc-token") != "edit-tok" {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"FORBIDDEN","message":"no write access"}`))
				return
			}
			if f.reject {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"BAD_REQUEST","message":"duplicate address"}`))
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.created = append(f.created, body)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"id": 77, "address": body["address"], "display": body["address"], "secret": "x"})
			return
		}
		if r.Header.Get("xc-token") != "read-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, err := os.ReadFile("../inventory/testdata/" + strings.ReplaceAll(p, "/", "_") + ".json")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var pg struct {
			Results []json.RawMessage `json:"results"`
		}
		_ = json.Unmarshal(b, &pg)
		json.NewEncoder(w).Encode(map[string]any{"count": len(pg.Results), "next": nil, "previous": nil, "results": pg.Results})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type integrationEnv struct {
	t        *testing.T
	srv      *httptest.Server
	st       *store.Store
	inv      *fakeInventoryDB
	ii       *wiring.InventoryIntegration
	month    time.Time // start of the month of the fixed clock
	now      time.Time
	keystone *keystonetest.Keystone
}

// newIntegrationEnv: flows of edge-01 (inventory-db:dcim.device:1) every
// minute of the first hour of the month, the clock one hour after the start
// of the month:
//
//	transit in:  xe-0/0/0 (TEL-123) → xe-0/0/1, 203.0.113.5 → 10.1.0.50, 1.5 Gbit/s
//	transit out: xe-0/0/1 → xe-0/0/0 (TEL-123), 10.1.0.77 → 203.0.113.5, 200 Mbit/s
func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	long := 400 * 24 * time.Hour // nothing expires whatever the date
	cfg := chstore.Config{Database: db, RawTTL: long, TTL1m: long, TTL5m: long, TTL1h: long}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	w, err := chstore.NewWriter(conn, cfg, chstore.WriterConfig{BatchSize: 1000, MaxDelay: 50 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	month := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
	now := month.Add(time.Hour)
	exp := netip.MustParseAddr("192.0.2.1")
	var fs []*flow.Flow
	for m := 0; m < 60; m++ {
		at := month.Add(time.Duration(m)*time.Minute + 10*time.Second)
		fs = append(fs,
			&flow.Flow{TimeReceived: at, SamplingRate: 1, ExporterAddress: exp, ExporterName: "edge-01", ExporterRef: "inventory-db:dcim.device:1",
				InIf: 501, InIfName: "xe-0/0/0", InIfSpeed: 10_000_000_000, InIfCircuit: "TEL-123", InIfBoundary: "external",
				OutIf: 502, OutIfName: "xe-0/0/1", OutIfSpeed: 10_000_000_000,
				SrcAddr: netip.MustParseAddr("203.0.113.5"), DstAddr: netip.MustParseAddr("10.1.0.50"), DstNetVRF: "prod",
				Proto: 6, Bytes: 11_250_000_000, Packets: 1000},
			&flow.Flow{TimeReceived: at, SamplingRate: 1, ExporterAddress: exp, ExporterName: "edge-01", ExporterRef: "inventory-db:dcim.device:1",
				InIf: 502, InIfName: "xe-0/0/1", InIfSpeed: 10_000_000_000,
				OutIf: 501, OutIfName: "xe-0/0/0", OutIfSpeed: 10_000_000_000, OutIfCircuit: "TEL-123", OutIfBoundary: "external",
				SrcAddr: netip.MustParseAddr("10.1.0.77"), DstAddr: netip.MustParseAddr("203.0.113.5"), SrcNetVRF: "prod",
				Proto: 6, Bytes: 1_500_000_000, Packets: 1000},
		)
	}
	if err := w.Put(ctx, fs); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := w.Close(cctx); err != nil {
		t.Fatal(err)
	}

	st := storetest.New(t)
	_, vault := secretstest.New(t)
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	inv := newFakeInventoryDB(t)
	readRef, err := vault.PutRef(ctx, "inventory-db", "token", "read-tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetInventoryDB(ctx, store.InventoryDB{Enabled: true, URL: inv.srv.URL, TokenRef: readRef, Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSetting(ctx, setup.SettingGeneral, setup.General{PublicURL: "https://flow.example"}); err != nil {
		t.Fatal(err)
	}
	sp := keystonetest.New(t)
	for _, u := range []struct{ name, role string }{{"admin", access.RoleAdministrator}, {"viewer", access.RoleViewer}} {
		role, err := st.RoleByName(ctx, u.role)
		if err != nil {
			t.Fatal(err)
		}
		sp.Users = append(sp.Users, keystone.User{ID: "usr_" + u.name, Username: u.name, Name: u.name, Roles: []string{role.Ident}})
	}
	q := query.New(conn, query.Config{Storage: cfg, Now: func() time.Time { return now }})
	// No local Inventory loop (api role): the snapshot is loaded on demand.
	ii := wiring.NewInventoryIntegration(q, st, vault, nil, nil)
	a := app.New(app.Options{Version: "test", SPAKey: sp.ConnectionKey()}, app.Deps{Store: st, Vault: vault, InventoryIntegration: ii})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return &integrationEnv{t: t, srv: srv, st: st, inv: inv, ii: ii, month: month, now: now, keystone: sp}
}

type session struct {
	e    *integrationEnv
	c    *http.Client
	csrf string
}

func (e *integrationEnv) login(user string) *session {
	jar, _ := cookiejar.New(nil)
	s := &session{e: e, c: &http.Client{Jar: jar}}
	// Sign in through the fake Keystone: start → authorize → callback.
	e.keystone.SignedIn = "usr_" + user
	res, err := s.c.Get(e.srv.URL + "/api/auth/spa/start")
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	code, out := s.do("GET", "/api/auth/me", nil)
	if code != 200 {
		e.t.Fatalf("login %s: %d %v", user, code, out)
	}
	s.csrf = out["csrf"].(string)
	return s
}

func (s *session) do(method, path string, body any) (int, map[string]any) {
	s.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, s.e.srv.URL+path, rd)
	if s.csrf != "" {
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		s.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

func approx(t *testing.T, what string, got any, want float64) {
	t.Helper()
	g, ok := got.(float64)
	if !ok || math.Abs(g-want) > 1e-6*math.Max(1, math.Abs(want)) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestInventoryIntegrationStatus(t *testing.T) {
	e := newIntegrationEnv(t)
	admin := e.login("admin")
	const inBps, outBps = 1_500_000_000.0, 200_000_000.0 // 11.25e9 B and 1.5e9 B per minute

	status := func(typ, ids string) map[string]any {
		t.Helper()
		code, out := admin.do("GET", "/api/integrations/inventory-db/status?object_type="+typ+"&ids="+ids+"&window=24h", nil)
		if code != 200 || out["window"] != "24h" {
			t.Fatalf("%s %s: %d %v", typ, ids, code, out)
		}
		return out["results"].(map[string]any)
	}

	t.Run("interface with a circuit", func(t *testing.T) {
		res := status("dcim.interface", "2,3,999")
		if _, ok := res["999"]; ok || len(res) != 2 {
			t.Fatalf("unknown ids must be omitted: %v", res)
		}
		r := res["2"].(map[string]any)
		approx(t, "in_bps", r["in_bps"], inBps)
		approx(t, "out_bps", r["out_bps"], outBps)
		approx(t, "speed_bps", r["speed_bps"], 10_000_000_000)
		approx(t, "utilization_in", r["utilization_in"], 0.15)
		approx(t, "utilization_out", r["utilization_out"], 0.02)
		approx(t, "p95_month_bps", r["p95_month_bps"], inBps)
		approx(t, "commit_bps", r["commit_bps"], 1_000_000_000)
		if r["over_commit"] != true {
			t.Errorf("over_commit = %v", r["over_commit"])
		}
		if r["last_seen"] != e.month.Add(59*time.Minute).Format(time.RFC3339) {
			t.Errorf("last_seen = %v", r["last_seen"])
		}
		sp := r["sparkline"].(map[string]any)
		ts, in, out := sp["t"].([]any), sp["in"].([]any), sp["out"].([]any)
		if len(ts) != 48 || len(in) != 48 || len(out) != 48 {
			t.Fatalf("sparkline sizes %d %d %d", len(ts), len(in), len(out))
		}
		if ts[47] != e.month.Add(30*time.Minute).Format(time.RFC3339) || ts[0] != e.now.Add(-24*time.Hour).Format(time.RFC3339) {
			t.Errorf("sparkline t %v … %v", ts[0], ts[47])
		}
		approx(t, "sparkline in[46]", in[46], inBps)
		approx(t, "sparkline in[47]", in[47], inBps)
		approx(t, "sparkline out[47]", out[47], outBps)
		approx(t, "sparkline in[45]", in[45], 0)

		u, err := url.Parse(r["flow_url"].(string))
		if err != nil || u.Host != "flow.example" || u.Path != "/visualize" {
			t.Fatalf("flow_url %v", r["flow_url"])
		}
		raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("q"))
		if err != nil {
			t.Fatal(err)
		}
		var st struct {
			R any    `json:"r"`
			F string `json:"f"`
			G string `json:"g"`
		}
		if err := json.Unmarshal(raw, &st); err != nil || st.R != "24h" || st.G != "stacked" ||
			st.F != "ExporterRef = 'inventory-db:dcim.device:1' AND (InIfName = 'xe-0/0/0' OR OutIfName = 'xe-0/0/0')" {
			t.Errorf("flow_url state %s", raw)
		}

		// No circuit: no p95 / commit members.
		r3 := res["3"].(map[string]any)
		approx(t, "xe-0/0/1 in", r3["in_bps"], outBps)
		approx(t, "xe-0/0/1 out", r3["out_bps"], inBps)
		for _, k := range []string{"p95_month_bps", "commit_bps", "over_commit"} {
			if _, ok := r3[k]; ok {
				t.Errorf("%s present for an interface without a circuit", k)
			}
		}
	})

	t.Run("device", func(t *testing.T) {
		res := status("dcim.device", "1,2,999")
		if len(res) != 2 {
			t.Fatalf("results %v", res)
		}
		r := res["1"].(map[string]any)
		approx(t, "in_bps", r["in_bps"], inBps+outBps)
		approx(t, "out_bps", r["out_bps"], inBps+outBps)
		if r["speed_bps"] != nil || r["utilization_in"] != nil || r["utilization_out"] != nil {
			t.Errorf("device speed should be unknown: %v", r)
		}
		if _, ok := r["p95_month_bps"]; ok {
			t.Error("p95 for a device")
		}
		// core-01 has no flows: present with zeros and no last_seen.
		r2 := res["2"].(map[string]any)
		if r2["in_bps"] != 0.0 || r2["last_seen"] != nil {
			t.Errorf("core-01 = %v", r2)
		}
	})

	t.Run("circuit", func(t *testing.T) {
		res := status("circuits.circuit", "1,5")
		if len(res) != 1 {
			t.Fatalf("results %v", res)
		}
		r := res["1"].(map[string]any)
		approx(t, "in_bps", r["in_bps"], inBps)
		approx(t, "out_bps", r["out_bps"], outBps)
		approx(t, "speed_bps", r["speed_bps"], 10_000_000_000)
		approx(t, "p95_month_bps", r["p95_month_bps"], inBps)
		approx(t, "commit_bps", r["commit_bps"], 1_000_000_000)
		if r["over_commit"] != true {
			t.Errorf("over_commit = %v", r["over_commit"])
		}
	})

	t.Run("validation and permissions", func(t *testing.T) {
		for _, q := range []string{"object_type=dcim.site&ids=1", "object_type=dcim.device&ids=", "object_type=dcim.device&ids=a",
			"object_type=dcim.device&ids=1&window=1m", "object_type=dcim.device&ids=1&window=x"} {
			if code, out := admin.do("GET", "/api/integrations/inventory-db/status?"+q, nil); code != 400 {
				t.Errorf("%s: %d %v", q, code, out)
			}
		}
		viewer := e.login("viewer")
		if code, _ := viewer.do("GET", "/api/integrations/inventory-db/status?object_type=dcim.device&ids=1", nil); code != 403 {
			t.Errorf("viewer: %d", code)
		}
	})
}

func TestInventoryIntegrationPrefixAddresses(t *testing.T) {
	e := newIntegrationEnv(t)
	admin := e.login("admin")
	code, out := admin.do("GET", "/api/integrations/inventory-db/prefix-addresses?prefix=10.1.0.0/24&window=24h", nil)
	if code != 200 || out["prefix"] != "10.1.0.0/24" {
		t.Fatalf("%d %v", code, out)
	}
	res := out["results"].([]any)
	if len(res) != 2 {
		t.Fatalf("results %v", res)
	}
	a, b := res[0].(map[string]any), res[1].(map[string]any)
	if a["address"] != "10.1.0.50" || a["in_ipam"] != true || a["flows"] != 60.0 || a["bytes"] != 60*11_250_000_000.0 ||
		a["last_seen"] != e.month.Add(59*time.Minute+10*time.Second).Format(time.RFC3339) {
		t.Errorf("first %v", a)
	}
	if b["address"] != "10.1.0.77" || b["in_ipam"] != false || b["bytes"] != 60*1_500_000_000.0 {
		t.Errorf("second %v", b)
	}
	for q, n := range map[string]int{"prefix=10.1.0.0/24&vrf=prod": 2, "prefix=10.1.0.0/24&vrf=other": 0, "prefix=10.1.0.77": 1,
		"prefix=203.0.113.0/24": 1, "prefix=2001:db8::/32": 0} {
		code, out := admin.do("GET", "/api/integrations/inventory-db/prefix-addresses?"+q, nil)
		if code != 200 || len(out["results"].([]any)) != n {
			t.Errorf("%s: %d %v", q, code, out)
		}
	}
	if code, _ := admin.do("GET", "/api/integrations/inventory-db/prefix-addresses?prefix=nope", nil); code != 400 {
		t.Errorf("bad prefix: %d", code)
	}
}

func TestInventoryIntegrationHookAndCreate(t *testing.T) {
	wiring.HookSyncDelay, wiring.HookSyncGap = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { wiring.HookSyncDelay, wiring.HookSyncGap = 5*time.Second, 30*time.Second })
	e := newIntegrationEnv(t)
	admin := e.login("admin")
	ctx := context.Background()

	code, out := admin.do("GET", "/api/inventory-db/integration", nil)
	if code != 200 || out["hook_secret_set"] != false || out["write_token_set"] != false ||
		out["hook_url"] != "https://flow.example/api/integrations/inventory-db/hook" || out["inventory_url"] != e.inv.srv.URL {
		t.Fatalf("%d %v", code, out)
	}
	// Without the editor token the action is refused.
	if code, out := admin.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "10.1.0.77"}); code != 409 ||
		out["error"] != "write_token_required" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = admin.do("PUT", "/api/inventory-db/integration", map[string]string{"hook_secret": "s3cret", "write_token": "edit-tok"})
	if code != 200 || out["hook_secret_set"] != true || out["write_token_set"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if strings.Contains(fmt.Sprint(out), "edit-tok") || strings.Contains(fmt.Sprint(out), "s3cret") {
		t.Fatal("secret returned")
	}
	viewer := e.login("viewer")
	if code, _ := viewer.do("PUT", "/api/inventory-db/integration", map[string]string{"write_token": "x"}); code != 403 {
		t.Fatalf("viewer: %d", code)
	}

	// Create in Ledger.
	code, out = admin.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "10.1.0.77"})
	if code != 201 || out["address"] != "10.1.0.77" || out["object"].(map[string]any)["id"] != 77.0 {
		t.Fatalf("%d %v", code, out)
	}
	if _, leaked := out["object"].(map[string]any)["secret"]; leaked {
		t.Error("unexpected fields passed through")
	}
	e.inv.mu.Lock()
	got := e.inv.created
	e.inv.mu.Unlock()
	if len(got) != 1 || got[0]["address"] != "10.1.0.77/32" || got[0]["status"] != "active" ||
		got[0]["description"] != "Discovered by Current" || len(got[0]["tags"].([]any)) != 0 {
		t.Fatalf("created %v", got)
	}
	if code, out := admin.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "2001:db8::5"}); code != 201 ||
		e.inv.created[1]["address"] != "2001:db8::5/128" {
		t.Fatalf("v6: %d %v", code, out)
	}
	e.inv.reject = true
	if code, out := admin.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "10.1.0.78"}); code != 409 ||
		out["error"] != "inventory_rejected" || !strings.Contains(out["message"].(string), "duplicate address") {
		t.Fatalf("rejected: %d %v", code, out)
	}
	if code, _ := admin.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "nope"}); code != 400 {
		t.Fatalf("bad address: %d", code)
	}
	if code, _ := viewer.do("POST", "/api/inventory-db/unknown/create", map[string]string{"address": "10.1.0.79"}); code != 403 {
		t.Fatalf("viewer create: %d", code)
	}

	// The hook: signed with the stored secret → 202 and, after the debounce,
	// a sync request the Inventory loops of other processes follow.
	var before struct{ At time.Time }
	_, _ = e.st.Setting(ctx, wiring.SettingInventorySyncRequest, &before)
	body := []byte(`{"integration_id":"int_1","events":[{"event":"object.updated","object_type":"dcim.interface","id":2}],"sent_at":"2026-10-12T10:46:00Z"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	m := hmac.New(sha256.New, []byte("s3cret"))
	m.Write([]byte(ts + "."))
	m.Write(body)
	post := func(sig string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/integrations/inventory-db/hook", bytes.NewReader(body))
		req.Header.Set("x-inventory-timestamp", ts)
		req.Header.Set("x-inventory-signature", sig)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("v1=deadbeef"); code != 401 {
		t.Fatalf("bad signature: %d", code)
	}
	if code := post("v1=" + hex.EncodeToString(m.Sum(nil))); code != 202 {
		t.Fatalf("hook: %d", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var req struct{ At time.Time }
		if found, _ := e.st.Setting(ctx, wiring.SettingInventorySyncRequest, &req); found && req.At.After(before.At) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no sync request recorded after the hook")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
