package secrets_test

import (
	"context"
	"slices"
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/secrets/secretstest"
)

func TestCopyToAndReconfigure(t *testing.T) {
	ctx := context.Background()
	srcFake, src := secretstest.New(t)
	dstFake, _ := secretstest.New(t)
	srcFake.Set("flow/postgres", map[string]any{"password": "pg"})
	srcFake.Set("flow/users/1", map[string]any{"password_hash": "h1"})
	srcFake.Set("flow/users/2", map[string]any{"password_hash": "h2"})
	srcFake.Set("other/x", map[string]any{"v": "not ours"})

	paths, err := src.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"postgres", "users/1", "users/2"}) {
		t.Fatalf("list %v", paths)
	}

	dst, err := secrets.New(secrets.Config{Addr: dstFake.Server.URL, Mount: "flow2", RoleID: secretstest.RoleID, SecretID: secretstest.SecretID})
	if err != nil {
		t.Fatal(err)
	}
	if err := dst.CheckKV2(ctx); err != nil {
		t.Fatal(err)
	}
	copied, err := src.CopyTo(ctx, dst)
	if err != nil || len(copied) != 3 {
		t.Fatalf("copy %v %v", copied, err)
	}
	if dstFake.Get("flow2/users/2")["password_hash"] != "h2" || dstFake.Get("flow2/postgres")["password"] != "pg" {
		t.Fatal("not copied")
	}
	if dstFake.Get("flow2/x") != nil || dstFake.Get("other/x") != nil {
		t.Fatal("copied a secret outside the mount")
	}

	// Switch the source client in place to the target: holders follow.
	if v, _ := src.Resolve("openbao://flow/postgres#password"); v != "pg" {
		t.Fatal("before switch")
	}
	if err := src.Reconfigure(dst.Config()); err != nil {
		t.Fatal(err)
	}
	if src.Mount() != "flow2" || src.Config().Addr != dstFake.Server.URL {
		t.Fatalf("not switched: %+v", src.Config())
	}
	if v, err := src.Resolve("openbao://flow2/postgres#password"); err != nil || v != "pg" {
		t.Fatalf("after switch: %q %v", v, err)
	}
	if dstFake.Logins == 0 {
		t.Fatal("no sign-in to the new server")
	}
	st := src.Status(ctx)
	if !st.TokenOK || st.Renewal.Mode != "renew" || st.Renewal.Logins == 0 || st.Renewal.NextAt == nil {
		t.Fatalf("status %+v", st)
	}

	if r, ok := secrets.MoveRef("openbao://flow/users/1#password_hash", "flow", "flow2"); !ok || r != "openbao://flow2/users/1#password_hash" {
		t.Fatal(r)
	}
	if _, ok := secrets.MoveRef("openbao://other/a#b", "flow", "flow2"); ok {
		t.Fatal("moved a reference of another mount")
	}
}
