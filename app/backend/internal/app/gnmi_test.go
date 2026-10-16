package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/gnmi"
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
	// Mutual TLS: the client certificate and key go together and must match.
	cert, key := clientCert(t)
	_, otherKey := clientCert(t)
	tlsIn := func(c, k *string) gnmiProfileInput {
		return gnmiProfileInput{Profile: gnmi.Profile{ID: "pa", Name: "core", TLS: true}, CertPEM: c, KeyPEM: k}
	}
	p, ch, err = mergeGNMIProfile(tlsIn(str(cert), str(key)), stored)
	if err != nil || changes(ch)[gnmi.SecretPath("pa", "cert")] != strings.TrimSpace(cert) || changes(ch)[gnmi.SecretPath("pa", "key")] != strings.TrimSpace(key) {
		t.Fatalf("client certificate: %+v %v", ch, err)
	}
	for _, bad := range []gnmiProfileInput{tlsIn(str(cert), nil), tlsIn(nil, str(key)), tlsIn(str(cert), str("")), tlsIn(str(cert), str(otherKey))} {
		if _, _, err := mergeGNMIProfile(bad, stored); err == nil {
			t.Errorf("bad client certificate accepted: %+v", bad)
		}
	}
	withCert := map[string]gnmi.Profile{"pa": {ID: "pa", Name: "core", TLS: true,
		CertRef: "openbao://flow/gnmi/pa/cert#value", KeyRef: "openbao://flow/gnmi/pa/key#value"}}
	if p, _, err = mergeGNMIProfile(tlsIn(nil, nil), withCert); err != nil || p.CertRef == "" || p.KeyRef == "" {
		t.Fatalf("kept client certificate: %+v %v", p, err)
	}
	// Removal: putGNMI deletes both secrets and clears the references.
	if _, ch, err = mergeGNMIProfile(tlsIn(str(""), str("")), withCert); err != nil {
		t.Fatal(err)
	}
	for _, what := range []string{"cert", "key"} {
		if v, ok := changes(ch)[gnmi.SecretPath("pa", what)]; !ok || v != "" {
			t.Fatalf("%s not removed: %+v", what, ch)
		}
	}
	// TLS off drops the client certificate too.
	p, ch, err = mergeGNMIProfile(gnmiProfileInput{Profile: gnmi.Profile{ID: "pa", Name: "core"}}, withCert)
	if _, ok := changes(ch)[gnmi.SecretPath("pa", "cert")]; err != nil || !ok || p.CertRef != "" {
		t.Fatalf("plain with client certificate: %+v %+v %v", p, ch, err)
	}
}

// clientCert returns a self-signed client certificate and its key (PEM).
func clientCert(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "flow"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}
