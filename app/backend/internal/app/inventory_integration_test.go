package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

func signInventory(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerifyInventorySignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"integration_id":"int_1","events":[]}`)
	ts := strconv.FormatInt(now.Unix(), 10)
	good := signInventory("s3cret", ts, body)
	old := strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10)
	future := strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10)
	cases := []struct {
		name, secret, ts, sig string
		body                  []byte
		ok                    bool
	}{
		{"valid", "s3cret", ts, good, body, true},
		{"valid, 4 minutes old", "s3cret", strconv.FormatInt(now.Add(-4*time.Minute).Unix(), 10),
			signInventory("s3cret", strconv.FormatInt(now.Add(-4*time.Minute).Unix(), 10), body), body, true},
		{"rotation: old secret first", "s3cret", ts, signInventory("old", ts, body) + "," + good, body, true},
		{"rotation: new secret first", "s3cret", ts, good + ", " + signInventory("old", ts, body), body, true},
		{"rotation: neither", "s3cret", ts, signInventory("a", ts, body) + "," + signInventory("b", ts, body), body, false},
		{"old timestamp", "s3cret", old, signInventory("s3cret", old, body), body, false},
		{"future timestamp", "s3cret", future, signInventory("s3cret", future, body), body, false},
		{"bad signature", "s3cret", ts, "v1=00ff", body, false},
		{"not hex", "s3cret", ts, "v1=zz", body, false},
		{"no scheme", "s3cret", ts, good[3:], body, false},
		{"body changed", "s3cret", ts, good, []byte(`{"integration_id":"int_2","events":[]}`), false},
		{"timestamp changed", "s3cret", strconv.FormatInt(now.Unix()-1, 10), good, body, false},
		{"missing timestamp", "s3cret", "", good, body, false},
		{"missing signature", "s3cret", ts, "", body, false},
		{"no secret", "", ts, signInventory("", ts, body), body, false},
	}
	for _, c := range cases {
		err := VerifyInventorySignature(c.secret, c.ts, c.sig, c.body, now)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func TestParseWindow(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "90m": 90 * time.Minute, "7d": 7 * 24 * time.Hour} {
		if d, err := ParseWindow(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	for _, in := range []string{"", "0d", "-1h", "x", "1y"} {
		if _, err := ParseWindow(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// fakeInventoryIntegration counts RequestSync calls.
type fakeInventoryIntegration struct{ syncs atomic.Int32 }

func (f *fakeInventoryIntegration) Status(_ context.Context, typ string, ids []int, _ time.Duration, window string) (any, error) {
	return map[string]any{"window": window, "type": typ, "ids": ids}, nil
}

func (f *fakeInventoryIntegration) PrefixAddresses(_ context.Context, p netip.Prefix, vrf string, _ time.Duration) (any, error) {
	return map[string]any{"prefix": p.String(), "vrf": vrf}, nil
}

func (f *fakeInventoryIntegration) RequestSync() { f.syncs.Add(1) }

func (f *fakeInventoryIntegration) CreateAddress(context.Context, string, string, netip.Addr) (any, error) {
	return map[string]any{}, nil
}

func TestInventoryHook(t *testing.T) {
	st := storetest.New(t)
	fake, vault := secretstest.New(t)
	ctx := context.Background()
	ii := &fakeInventoryIntegration{}
	a := New(Options{Version: "test"}, Deps{Store: st, Vault: vault, InventoryIntegration: ii})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	body := []byte(`{"integration_id":"int_1","events":[{"event":"object.updated","object_type":"dcim.interface","id":12}],"sent_at":"2026-10-12T10:46:00Z"}`)
	post := func(ts, sig string, b []byte) int {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/integrations/inventory-db/hook", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if ts != "" {
			req.Header.Set("x-inventory-timestamp", ts)
		}
		if sig != "" {
			req.Header.Set("x-inventory-signature", sig)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)

	// No secret configured: every request is refused.
	if code := post(now, signInventory("s3cret", now, body), body); code != 401 {
		t.Fatalf("without a secret: %d", code)
	}
	ref, err := vault.PutRef(ctx, inventoryHookSecretPath, inventoryHookSecretKey, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetInventoryIntegration(ctx, store.InventoryIntegration{HookSecretRef: ref}); err != nil {
		t.Fatal(err)
	}
	if fake.Get("flow/" + inventoryHookSecretPath)["secret"] != "s3cret" {
		t.Fatal("secret not in OpenBao")
	}
	if code := post(now, signInventory("s3cret", now, body), body); code != 202 {
		t.Fatalf("valid: %d", code)
	}
	if code := post(now, signInventory("old", now, body)+","+signInventory("s3cret", now, body), body); code != 202 {
		t.Fatalf("rotation: %d", code)
	}
	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	for name, code := range map[string]int{
		"old":       post(old, signInventory("s3cret", old, body), body),
		"bad":       post(now, signInventory("wrong", now, body), body),
		"unsigned":  post("", "", body),
		"tampered":  post(now, signInventory("s3cret", now, body), append([]byte(" "), body...)),
		"no header": post(now, "", body),
	} {
		if code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if n := ii.syncs.Load(); n != 2 {
		t.Fatalf("RequestSync called %d times", n)
	}
	// A valid signature over a body that is not JSON is a 400, no sync.
	if code := post(now, signInventory("s3cret", now, []byte("nope")), []byte("nope")); code != 400 {
		t.Fatalf("not JSON: %d", code)
	}
	// Status needs integrations.inventory:read.
	resp, err := http.Get(srv.URL + "/api/integrations/inventory-db/status?object_type=dcim.device&ids=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status without auth: %d", resp.StatusCode)
	}
}
