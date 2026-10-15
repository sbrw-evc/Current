package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// People sign in through SPA (spa.go); this file has the session side:
// who is signed in and signing out.

// userView is the user as /api/auth/me returns it.
type userView struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	Source      string   `json:"source"`
	Role        string   `json:"role"`
	RoleIdent   string   `json:"role_ident"`
	Permissions []string `json:"permissions"`
}

func viewOf(u store.User, perms access.Set) userView {
	return userView{ID: u.ID, Username: u.Username, Name: u.Name, Email: u.Email, Source: u.Source, Role: u.Role,
		RoleIdent: u.RoleIdent, Permissions: perms.List()}
}

// accountURL is where the person changes their password and passkeys (SPA).
func (a *App) accountURL(ctx context.Context) string {
	st, err := a.spaStatus(ctx)
	if err != nil {
		return ""
	}
	return st.AccountURL
}

// logout ends the session; the console then goes to SPA's sign-out
// (redirect), which ends the SPA session and returns to Flow.
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	// No CSRF check: signing out is harmless, and the cookie is SameSite=Lax.
	if ss, err := a.sessions.Get(r.Context(), r); err == nil && ss != nil {
		if u, err := a.st.UserByID(r.Context(), ss.UserID); err == nil {
			_ = a.st.Audit(r.Context(), u.Username, "auth.logout", "", httpx.ClientIP(r, a.opt.TrustedProxies), nil)
		}
	}
	if err := a.sessions.Delete(r.Context(), w, r); err != nil {
		slog.Warn("session not deleted", "err", err)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": a.spaSignOut(r)})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, p *Principal) {
	httpx.JSON(w, http.StatusOK, map[string]any{"user": viewOf(p.User, p.Perms), "csrf": p.Session.CSRF, "account_url": a.accountURL(r.Context())})
}

func (a *App) catalog(w http.ResponseWriter, r *http.Request, p *Principal) {
	httpx.JSON(w, http.StatusOK, map[string]any{"groups": access.Groups(), "pages": access.Pages()})
}

type columnView struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Dimension bool   `json:"dimension"`
	Rollup    bool   `json:"rollup"`
	Reverse   string `json:"reverse,omitempty"`
	Metric    bool   `json:"metric"`
}

func (a *App) schema(w http.ResponseWriter, r *http.Request, p *Principal) {
	cols := make([]columnView, 0, len(schema.Columns))
	for _, c := range schema.Columns {
		cols = append(cols, columnView{Name: c.Name, Kind: string(c.Kind), Dimension: c.Dimension, Rollup: c.Rollup, Reverse: c.Reverse, Metric: c.Metric})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"columns": cols})
}
