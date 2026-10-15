package app

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/spa"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// legacyUser is an account made before Flow moved to SPA.
func legacyUser(t *testing.T, st *store.Store, name string, roleID int64) store.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), store.NewUser{Username: name, Name: name, RoleID: roleID})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// spaUser is a person of the fake SPA with role IDs of Flow's catalogue.
func spaUser(name string, roles ...string) spa.User {
	id := "usr_" + strings.ToLower(name)
	return spa.User{ID: id, Username: name, Name: name, Email: strings.ToLower(name) + "@example.com", Roles: roles}
}

func noFollow(c *client) *http.Client {
	return &http.Client{Jar: c.http.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// signIn runs the sign-in through the fake SPA as the person named user
// (start → authorize → callback). It returns the sso_error the sign-in page
// gets ("" when signed in) and keeps the CSRF token of the new session.
func (c *client) signIn(user, query string) string {
	t := c.e.t
	t.Helper()
	sp := c.e.spa
	sp.SignedIn = "usr_" + strings.ToLower(user)
	for _, u := range sp.Users {
		if strings.EqualFold(u.Username, user) {
			sp.SignedIn = u.ID
		}
	}
	nf := noFollow(c)
	res, err := nf.Get(c.e.srv.URL + spa.StartPath + query)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, sp.Server.URL+"/oauth2/authorize?") {
		return ssoError(t, res.StatusCode, loc)
	}
	if res, err = nf.Get(loc); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	back := res.Header.Get("Location")
	if !strings.HasPrefix(back, c.e.srv.URL+spa.CallbackPath+"?") {
		t.Fatalf("SPA sent the browser to %q", back)
	}
	if res, err = nf.Get(back); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc = res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther || strings.HasPrefix(loc, "/login") {
		return ssoError(t, res.StatusCode, loc)
	}
	code, out := c.do("GET", "/api/auth/me", nil)
	if code != 200 {
		t.Fatalf("no session after the callback: %d %v", code, out)
	}
	c.csrf = out["csrf"].(string)
	return ""
}

func ssoError(t *testing.T, status int, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Path != "/login" || u.Query().Get("sso_error") == "" {
		t.Fatalf("unexpected answer %d → %q", status, loc)
	}
	return u.Query().Get("sso_error")
}
