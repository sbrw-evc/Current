package app

import (
	"slices"
	"strings"
	"testing"
)

func TestExtensionSettings(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	admin.login("admin", "admin-password")
	viewer := e.client()
	viewer.login("viewer", "viewer-password")

	// Reverse DNS: disabled defaults, validation, reload.
	code, out := admin.do("GET", "/api/settings/rdns", nil)
	s, _ := out["settings"].(map[string]any)
	if code != 200 || s["enabled"] != false || s["workers"] != 8.0 || s["scope"] != "all" {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/settings/rdns", map[string]any{"enabled": true, "scope": "nowhere"}); code != 400 || out["error"] != "rdns_invalid" {
		t.Fatal(code, out)
	}
	code, out = admin.do("PUT", "/api/settings/rdns", map[string]any{"enabled": true, "servers": []string{" 192.0.2.53 "}, "rate_limit": 50})
	if s := out["settings"].(map[string]any); code != 200 || s["enabled"] != true || s["servers"].([]any)[0] != "192.0.2.53" || s["rate_limit"] != 50.0 {
		t.Fatal(code, out)
	}
	if code, _ := viewer.do("GET", "/api/settings/rdns", nil); code != 403 {
		t.Fatal("viewer reads rdns settings", code)
	}

	// Threat intelligence: default public lists, edit, refresh request.
	code, out = admin.do("GET", "/api/settings/threat", nil)
	ts := out["settings"].(map[string]any)
	if code != 200 || ts["enabled"] != true || len(ts["lists"].([]any)) != 5 || len(out["default_lists"].([]any)) != 5 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/settings/threat", map[string]any{"enabled": true, "refresh_minutes": 10}); code != 400 || out["error"] != "threat_invalid" {
		t.Fatal(code, out)
	}
	code, out = admin.do("PUT", "/api/settings/threat", map[string]any{"enabled": true, "refresh_minutes": 120, "exclude": []string{"203.0.113.0/24"},
		"lists": []map[string]any{{"name": "local", "url": "https://lists.example/local.txt", "enabled": true}}})
	if ts := out["settings"].(map[string]any); code != 200 || len(ts["lists"].([]any)) != 1 || ts["refresh_minutes"] != 120.0 {
		t.Fatal(code, out)
	}
	if code, out := admin.do("POST", "/api/settings/threat/refresh", nil); code != 202 || out["requested_at"] == nil {
		t.Fatal(code, out)
	}
	_, out = admin.do("GET", "/api/settings/threat", nil)
	if out["settings"].(map[string]any)["refresh_requested_at"] == nil {
		t.Fatal(out)
	}

	// Cloud flow logs: tokens in OpenBao only, never returned.
	code, out = admin.do("GET", "/api/settings/flowlogs", nil)
	if code != 200 || out["available"] != false || out["aws"].(map[string]any)["token_set"] != false ||
		out["gcp"].(map[string]any)["endpoint"] != "/api/ingest/flowlogs/gcp" {
		t.Fatal(code, out)
	}
	if code, out := admin.do("PUT", "/api/settings/flowlogs", map[string]any{"aws": map[string]any{"enabled": true}}); code != 400 {
		t.Fatal("enabled without a token", code, out)
	}
	if code, out := admin.do("PUT", "/api/settings/flowlogs", map[string]any{"aws": map[string]any{"enabled": true, "token": "short"}}); code != 400 {
		t.Fatal("short token", code, out)
	}
	secret := "firehose-access-key-0123456789"
	code, out = admin.do("PUT", "/api/settings/flowlogs", map[string]any{"aws": map[string]any{"enabled": true, "token": secret},
		"gcp": map[string]any{"enabled": true, "token": "gcp-push-token-0123456789"}})
	if code != 200 || out["aws"].(map[string]any)["token_set"] != true || out["azure"].(map[string]any)["enabled"] != false {
		t.Fatal(code, out)
	}
	if strings.Contains(toJSON(out), secret) {
		t.Fatal("token returned by the API")
	}
	found := false
	for _, p := range e.fake.Paths() {
		if strings.Contains(p, "flowlogs") {
			d := toJSON(e.fake.Get(p))
			found = strings.Contains(d, secret) && strings.Contains(d, "gcp-push-token")
		}
	}
	if !found {
		t.Fatalf("tokens not in OpenBao: %v", e.fake.Paths())
	}
	var raw map[string]any
	if _, err := e.st.Setting(t.Context(), "flowlogs", &raw); err != nil || strings.Contains(toJSON(raw), secret) {
		t.Fatal("token stored in PostgreSQL", raw, err)
	}
	// Removing the token disables nothing implicitly but must be explicit.
	if code, _ := admin.do("PUT", "/api/settings/flowlogs", map[string]any{"gcp": map[string]any{"enabled": false, "token": ""}}); code != 200 {
		t.Fatal(code)
	}
	_, out = admin.do("GET", "/api/settings/flowlogs", nil)
	if out["gcp"].(map[string]any)["token_set"] != false || out["aws"].(map[string]any)["token_set"] != true {
		t.Fatal(out)
	}
	// With a public URL the absolute ingest URL is given for the cloud side.
	if code, out := admin.do("GET", "/api/settings/flowlogs", nil); code != 200 || out["aws"].(map[string]any)["url"] != "" {
		t.Fatal(code, out)
	}
	_ = e.st.PutSetting(t.Context(), "general", map[string]any{"language": "en", "theme": "system", "timezone": "UTC", "public_url": "https://flow.example/"})
	if _, out := admin.do("GET", "/api/settings/flowlogs", nil); out["azure"].(map[string]any)["url"] != "https://flow.example/api/ingest/flowlogs/azure" {
		t.Fatal(out)
	}

	// Ingest without a bus in this process: 501, no session needed.
	if code, out := e.client().do("POST", "/api/ingest/flowlogs/aws", map[string]any{}); code != 501 {
		t.Fatal(code, out)
	}

	for _, w := range []string{"rdns", "threat", "flowlogs"} {
		if !slices.Contains(*e.rel, w) {
			t.Errorf("reload %s not sent: %v", w, *e.rel)
		}
	}
}
