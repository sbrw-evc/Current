package geoip

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/geoip/geoiptest"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func writeCity(t *testing.T, path, city string) {
	t.Helper()
	err := geoiptest.Write(path, "GeoLite2-City", []geoiptest.Network{
		{Prefix: pfx("1.0.0.0/8"), Data: map[string]any{"country": map[string]any{"iso_code": "AU"}}},
		{Prefix: pfx("1.1.1.0/24"), Data: map[string]any{
			"country": map[string]any{"iso_code": "US", "names": map[string]any{"en": "United States"}},
			"city":    map[string]any{"geoname_id": uint32(1), "names": map[string]any{"en": city, "ru": "x"}},
		}},
		{Prefix: pfx("2a00::/16"), Data: map[string]any{"registered_country": map[string]any{"iso_code": "DE"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaxMind(t *testing.T) {
	dir := t.TempDir()
	city, asn := filepath.Join(dir, "city.mmdb"), filepath.Join(dir, "asn.mmdb")
	writeCity(t, city, "Los Angeles")
	if err := geoiptest.Write(asn, "GeoLite2-ASN", []geoiptest.Network{
		{Prefix: pfx("1.1.1.0/24"), Data: map[string]any{"autonomous_system_number": uint32(13335), "autonomous_system_organization": "CLOUDFLARENET"}},
		{Prefix: pfx("2a00:1450::/32"), Data: map[string]any{"autonomous_system_number": uint32(15169), "autonomous_system_organization": "GOOGLE"}},
	}); err != nil {
		t.Fatal(err)
	}
	db, err := Open(Config{Databases: []string{city, asn}})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Info{
		"1.1.1.1":          {Country: "US", City: "Los Angeles", ASN: 13335, ASName: "CLOUDFLARENET"},
		"::ffff:1.1.1.1":   {Country: "US", City: "Los Angeles", ASN: 13335, ASName: "CLOUDFLARENET"},
		"1.2.3.4":          {Country: "AU"},
		"2a00:1450:4001::": {Country: "DE", ASN: 15169, ASName: "GOOGLE"},
		"8.8.8.8":          {},
	}
	for a, want := range cases {
		if got := db.Lookup(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s = %+v, want %+v", a, got, want)
		}
	}
	if got := db.Lookup(netip.Addr{}); got != (Info{}) {
		t.Errorf("invalid addr = %+v", got)
	}
	if n := len(db.Databases()); n != 2 {
		t.Fatalf("databases = %d", n)
	}
}

func TestIPinfoLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipinfo_lite.mmdb")
	if err := geoiptest.Write(path, "ipinfo lite.mmdb", []geoiptest.Network{
		{Prefix: pfx("8.8.8.0/24"), Data: map[string]any{"country": "United States", "country_code": "US", "continent": "North America",
			"continent_code": "NA", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com"}},
		{Prefix: pfx("2001:4860::/32"), Data: map[string]any{"country": "United States", "country_code": "us", "asn": "AS15169", "as_name": "Google LLC"}},
	}); err != nil {
		t.Fatal(err)
	}
	// Unknown database type: schema detected by probing.
	path2 := filepath.Join(t.TempDir(), "custom.mmdb")
	if err := geoiptest.Write(path2, "custom", []geoiptest.Network{
		{Prefix: pfx("8.8.8.0/24"), Data: map[string]any{"country_code": "US", "asn": "AS15169", "as_name": "Google LLC"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path2} {
		db, err := Open(Config{Databases: []string{p}})
		if err != nil {
			t.Fatal(err)
		}
		want := Info{Country: "US", ASN: 15169, ASName: "Google LLC"}
		if got := db.Lookup(netip.MustParseAddr("8.8.8.8")); got != want {
			t.Errorf("%s: 8.8.8.8 = %+v", p, got)
		}
	}
	db, _ := Open(Config{Databases: []string{path}})
	if got := db.Lookup(netip.MustParseAddr("2001:4860::8888")); got.Country != "US" || got.ASN != 15169 {
		t.Errorf("v6 = %+v", got)
	}
}

func TestParseASN(t *testing.T) {
	for s, want := range map[string]uint32{"AS123": 123, "as65000": 65000, "42": 42, "": 0, "ASx": 0, "AS4294967295": 4294967295} {
		if got := ParseASN(s); got != want {
			t.Errorf("ParseASN(%q) = %d", s, got)
		}
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	writeCity(t, path, "Los Angeles")
	db, err := Open(Config{Databases: []string{path}, CheckInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := db.Reload(); changed || err != nil {
		t.Fatalf("reload without change = %v, %v", changed, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go db.Run(ctx)

	writeCity(t, path, "San Francisco")
	future := time.Now().Add(time.Second)
	os.Chtimes(path, future, future)
	deadline := time.Now().Add(5 * time.Second)
	for db.Lookup(netip.MustParseAddr("1.1.1.1")).City != "San Francisco" {
		if time.Now().After(deadline) {
			t.Fatal("not reloaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A broken file keeps the previous version.
	os.WriteFile(path, []byte("garbage"), 0o644)
	future = future.Add(time.Second)
	os.Chtimes(path, future, future)
	if _, err := db.Reload(); err == nil {
		t.Fatal("want error")
	}
	if db.Lookup(netip.MustParseAddr("1.1.1.1")).City != "San Francisco" {
		t.Fatal("lost previous database")
	}
	if _, err := Open(Config{Databases: []string{filepath.Join(t.TempDir(), "missing.mmdb")}}); err == nil {
		t.Fatal("want error for missing file")
	}
}

func BenchmarkLookup(b *testing.B) {
	path := filepath.Join(b.TempDir(), "city.mmdb")
	geoiptest.Write(path, "GeoLite2-City", []geoiptest.Network{
		{Prefix: pfx("1.1.1.0/24"), Data: map[string]any{
			"country": map[string]any{"iso_code": "US"}, "city": map[string]any{"names": map[string]any{"en": "Los Angeles"}}}},
	})
	db, _ := Open(Config{Databases: []string{path}})
	a := netip.MustParseAddr("1.1.1.1")
	for b.Loop() {
		db.Lookup(a)
	}
}
