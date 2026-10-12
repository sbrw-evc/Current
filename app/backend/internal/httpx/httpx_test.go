package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusOf(t *testing.T) {
	if s, c := StatusOf(errors.New("x")); s != 500 || c != "internal" {
		t.Fatal(s, c)
	}
	if s, c := StatusOf(fmt.Errorf("wrap: %w", BadRequest("invalid_filter", "bad"))); s != 400 || c != "invalid_filter" {
		t.Fatal(s, c)
	}
	rec := httptest.NewRecorder()
	Err(rec, NotFound("nope"))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"error":"not_found","message":"nope"`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.1.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.2.2.2")
	if ip := ClientIP(r, trusted); ip != "203.0.113.5" {
		t.Fatal(ip)
	}
	r.RemoteAddr = "198.51.100.1:1"
	if ip := ClientIP(r, trusted); ip != "198.51.100.1" {
		t.Fatal(ip)
	}
}

func TestWeb(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa</html>"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("js"), 0o644)
	h := Secure(Web(dir))
	for path, want := range map[string]string{"/": "spa", "/visualize": "spa", "/assets/app.js": "js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Error("no security headers")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/nothing", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not_found") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/missing.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatal(rec.Code)
	}
}
