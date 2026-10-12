package entra_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/entra"
	"github.com/sbrw-evc/network/app/backend/internal/entra/entratest"
)

func config() entra.Config {
	return entra.Config{Enabled: true, Cloud: entratest.Cloud, TenantID: entratest.TenantID, ClientID: entratest.ClientID,
		RedirectURL: "https://flow.example" + entra.CallbackPath}
}

// signIn runs the browser part: AuthURL → the provider redirects back with a code.
func signIn(t *testing.T, c entra.Config) (string, entra.Request) {
	t.Helper()
	ctx := context.Background()
	m, err := entra.Discover(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	req := entra.NewRequest()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(entra.AuthURL(c, m, req))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != entra.CallbackPath || loc.Query().Get("state") != req.State {
		t.Fatalf("redirect %v", loc)
	}
	return loc.Query().Get("code"), req
}

func TestNormalize(t *testing.T) {
	entratest.Start(t) // registers the test cloud
	c := config()
	if _, err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*entra.Config){
		func(c *entra.Config) { c.TenantID = "common" },
		func(c *entra.Config) { c.ClientID = "app" },
		func(c *entra.Config) { c.RedirectURL = "https://flow.example/callback" },
		func(c *entra.Config) { c.Cloud = "mars" },
	} {
		c := config()
		bad(&c)
		if _, err := c.Normalize(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestSignIn(t *testing.T) {
	srv := entratest.Start(t)
	ctx := context.Background()
	groups := []string{"AAAAAAAA-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"}
	srv.User = entratest.User{ObjectID: "0f0f0f0f-1111-2222-3333-444444444444", Username: "Ivanov@Corp.example", Name: "Ivan Ivanov", Groups: groups}
	c := config()
	c.ReadGroups = true

	p, err := entra.Test(ctx, c, entratest.Secret)
	if err != nil || !p.Credentials || p.TenantID != entratest.TenantID {
		t.Fatalf("test: %+v %v", p, err)
	}
	if _, err := entra.Test(ctx, c, "wrong"); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("wrong secret: %v", err)
	}

	code, req := signIn(t, c)
	acc, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if acc.Username != "ivanov@corp.example" || acc.Name != "Ivan Ivanov" || acc.DN != srv.User.ObjectID {
		t.Fatalf("account %+v", acc)
	}
	// Groups through Graph, one per page.
	if !slices.Equal(acc.Groups, []string{"aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"}) {
		t.Fatalf("groups %v", acc.Groups)
	}

	// A code is redeemed once; a wrong verifier or nonce is refused.
	if _, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now()); err == nil {
		t.Fatal("code reused")
	}
	code, req = signIn(t, c)
	req.Verifier = "other"
	if _, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now()); err == nil {
		t.Fatal("PKCE verifier not checked")
	}
	code, req = signIn(t, c)
	srv.Nonce = "replayed"
	if _, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now()); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce: %v", err)
	}
	code, req = signIn(t, c)
	if _, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now().Add(3*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry: %v", err)
	}
	// Groups in the token: no Graph call needed.
	srv.User.GroupsInToken = true
	code, req = signIn(t, c)
	if acc, err := entra.SignIn(ctx, c, entratest.Secret, code, req, time.Now()); err != nil || len(acc.Groups) != 2 {
		t.Fatalf("groups in token: %+v %v", acc, err)
	}
}
