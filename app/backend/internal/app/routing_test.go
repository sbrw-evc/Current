package app

import (
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/snmp"
)

func TestMergeSNMPProfile(t *testing.T) {
	str := func(s string) *string { return &s }
	stored := map[string]snmp.Profile{"pa": {ID: "pa", Name: "core", Version: snmp.Version2c, CommunityRef: "openbao://flow/snmp/pa/community#value"}}

	// Existing v2c profile without a new community keeps its reference.
	p, ch, err := mergeProfile(snmpProfileInput{Profile: snmp.Profile{ID: "pa", Name: "core", Version: snmp.Version2c}}, stored)
	if err != nil || p.CommunityRef == "" || p.ID != "pa" {
		t.Fatalf("keep: %+v %v", p, err)
	}
	for _, c := range ch {
		if c.value != "" {
			t.Fatalf("unexpected write %+v", c)
		}
	}
	// A new profile gets an id and needs its community.
	if _, _, err := mergeProfile(snmpProfileInput{Profile: snmp.Profile{Name: "new", Version: snmp.Version2c}}, stored); err == nil {
		t.Fatal("v2c without community accepted")
	}
	p, ch, err = mergeProfile(snmpProfileInput{Profile: snmp.Profile{ID: "forged", Name: "new", Version: snmp.Version2c}, Community: str("public")}, stored)
	if err != nil || p.ID == "forged" || p.ID == "" || len(ch) == 0 || ch[0].value != "public" || ch[0].path != snmp.SecretPath(p.ID, "community") {
		t.Fatalf("new: %+v %+v %v", p, ch, err)
	}
	// Switching to v3 authPriv needs both passwords and drops the community.
	if _, _, err := mergeProfile(snmpProfileInput{Profile: snmp.Profile{ID: "pa", Name: "core", Version: snmp.Version3, Username: "u"},
		AuthPassword: str("a")}, stored); err == nil {
		t.Fatal("authPriv without privacy password accepted")
	}
	p, ch, err = mergeProfile(snmpProfileInput{Profile: snmp.Profile{ID: "pa", Name: "core", Version: snmp.Version3, Username: "u",
		SecurityLevel: snmp.AuthNoPriv}, AuthPassword: str("a")}, stored)
	if err != nil || p.CommunityRef != "" {
		t.Fatalf("v3: %+v %v", p, err)
	}
	paths := map[string]string{}
	for _, c := range ch {
		paths[c.path] = c.value
	}
	if paths[snmp.SecretPath("pa", "auth")] != "a" {
		t.Fatalf("changes %+v", ch)
	}
	if v, ok := paths[snmp.SecretPath("pa", "community")]; !ok || v != "" {
		t.Fatalf("community not removed: %+v", ch)
	}
}
