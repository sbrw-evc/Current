package keystone

import (
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	k := Key{Issuer: "https://spa.example.com/", ClientID: "app_1", ClientSecret: "s", Token: "t"}
	got, err := ParseKey("  " + k.String() + "\n")
	if err != nil || got.Issuer != "https://spa.example.com" || got.ClientID != "app_1" || got.Token != "t" {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", "umbid1." + strings.TrimPrefix(k.String(), KeyPrefix), "spa1.!!!", Key{Issuer: "ftp://x", ClientID: "a", ClientSecret: "b", Token: "c"}.String(),
		Key{Issuer: "https://x", ClientID: "a", ClientSecret: "b"}.String()} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSignOutURL(t *testing.T) {
	if u := SignOutURL("https://spa/oauth2/logout", "app_1", "https://flow/"); u != "https://spa/oauth2/logout?client_id=app_1&post_logout_redirect_uri=https%3A%2F%2Fflow%2F" {
		t.Fatal(u)
	}
	if SignOutURL("", "a", "b") != "" || !strings.Contains(SignOutURL("https://spa/out?x=1", "a", ""), "?x=1&client_id=a") {
		t.Fatal("sign-out URL")
	}
	if !RoleIDRe.MatchString("on-call:l2") || RoleIDRe.MatchString("Admin") || RoleIDRe.MatchString("") {
		t.Fatal("role IDs")
	}
}
