package directory

import "testing"

func TestNormalize(t *testing.T) {
	c, err := Config{URL: "ldap://dc.example.com", BindDN: "cn=svc,dc=example,dc=com", BaseDN: "OU=Users,DC=example,DC=com"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != KindAD || c.UsernameAttr != "sAMAccountName" {
		t.Fatal(c)
	}
	for _, bad := range []Config{
		{URL: "http://x", BindDN: "cn=a", BaseDN: "dc=x"},
		{URL: "ldaps://x", StartTLS: true, BindDN: "cn=a", BaseDN: "dc=x"},
		{URL: "ldap://x", BindDN: "cn=a", BaseDN: "dc=x", UserFilter: "(uid=x)"},
		{URL: "ldap://x", BaseDN: "dc=x"},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if r := groupRoot("ou=users,dc=example,dc=com"); r != "dc=example,dc=com" {
		t.Fatal(r)
	}
	if NormalizeDN("CN=NOC, OU=Groups,DC=Example,DC=com") != "cn=noc,ou=groups,dc=example,dc=com" {
		t.Fatal(NormalizeDN("CN=NOC, OU=Groups,DC=Example,DC=com"))
	}
	if _, err := Authenticate(c, "x", "user", ""); err != ErrInvalidCredentials {
		t.Fatal(err)
	}
}
