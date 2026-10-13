package app

import (
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/gnmi"
)

func TestMergeGNMIProfile(t *testing.T) {
	str := func(s string) *string { return &s }
	stored := map[string]gnmi.Profile{"pa": {ID: "pa", Name: "core", Username: "flow", TLS: true,
		PasswordRef: "openbao://flow/gnmi/pa/password#value", CARef: "openbao://flow/gnmi/pa/ca#value"}}
	changes := func(ch []secretChange) map[string]string {
		m := map[string]string{}
		for _, c := range ch {
			m[c.path] = c.value
		}
		return m
	}

	// An existing profile without new secrets keeps its references.
	p, ch, err := mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{ID: "pa", Name: "core", Username: "flow", TLS: true}}, stored)
	if err != nil || p.PasswordRef == "" || p.CARef == "" || p.ID != "pa" {
		t.Fatalf("keep: %+v %v", p, err)
	}
	for _, c := range ch {
		if c.value != "" {
			t.Fatalf("unexpected write %+v", c)
		}
	}
	// A new profile gets an id and needs a password with a user name.
	if _, _, err := mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{Name: "new", Username: "u"}}, stored); err == nil {
		t.Fatal("user without password accepted")
	}
	p, ch, err = mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{ID: "forged", Name: "new", Username: "u"}, Password: str("pw")}, stored)
	if err != nil || p.ID == "forged" || p.ID == "" || changes(ch)[gnmi.SecretPath(p.ID, "password")] != "pw" {
		t.Fatalf("new: %+v %+v %v", p, ch, err)
	}
	// No user name, no password; no TLS, no CA.
	p, ch, err = mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{ID: "pa", Name: "core"}}, stored)
	if err != nil || p.PasswordRef != "" || p.CARef != "" {
		t.Fatalf("plain: %+v %v", p, err)
	}
	m := changes(ch)
	if v, ok := m[gnmi.SecretPath("pa", "password")]; !ok || v != "" {
		t.Fatalf("password not removed: %+v", ch)
	}
	if v, ok := m[gnmi.SecretPath("pa", "ca")]; !ok || v != "" {
		t.Fatalf("CA not removed: %+v", ch)
	}
	// A CA must be PEM.
	if _, _, err := mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{ID: "pa", Name: "core", TLS: true}, CAPEM: str("nope")}, stored); err == nil {
		t.Fatal("bad CA accepted")
	}
}
