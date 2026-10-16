package secrets_test

import (
	"context"
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/secrets/secretstest"
)

func TestPutResolveDelete(t *testing.T) {
	fake, c := secretstest.New(t)
	ctx := context.Background()
	if c.Mount() != "flow" {
		t.Fatalf("mount %q", c.Mount())
	}
	ref, err := c.PutRef(ctx, "inventory-db", "token", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "openbao://flow/inventory-db#token" {
		t.Fatalf("ref %q", ref)
	}
	if fake.Get("flow/inventory-db")["token"] != "s3cret" {
		t.Fatal("not stored")
	}
	v, err := secrets.Value(c, ref)
	if err != nil || v != "s3cret" {
		t.Fatalf("resolve: %q %v", v, err)
	}
	if v, _ := secrets.Value(nil, "plain"); v != "plain" {
		t.Fatal("plain value must pass through")
	}
	if err := c.Delete(ctx, "inventory-db"); err != nil {
		t.Fatal(err)
	}
	if fake.Get("flow/inventory-db") != nil {
		t.Fatal("not deleted")
	}
	if rep := c.Verify(ctx); !rep.OK {
		t.Fatalf("verify: %+v", rep)
	}
}

func TestParseRef(t *testing.T) {
	m, p, k, err := secrets.ParseRef("openbao://flow/a/b#key")
	if err != nil || m != "flow" || p != "a/b" || k != "key" {
		t.Fatal(m, p, k, err)
	}
	if _, _, _, err := secrets.ParseRef("openbao://flow/../x"); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, _, k, _ := secrets.ParseRef("openbao://flow/x"); k != "value" {
		t.Fatal("default key")
	}
}
