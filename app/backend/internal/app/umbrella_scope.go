package app

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/umbrella"
)

// Visibility scopes from Umbrella (docs/integrations.md §3.2).
//
// For a user whose role has the permission scope:umbrella (and is not the
// built-in Administrator), guard puts a query.ScopeFunc into the request
// context. ClickHouse queries made with that context go through
// query.ScopedConn, which restricts every flow table to the user's CIs; the
// scope is fetched from Umbrella on first use and cached for 60 s per user.
// If Umbrella cannot be asked, queries fail closed with 503
// scope_unavailable.

// umbrellaState is the App's Umbrella API state (zero value ready).
type umbrellaState struct {
	once   sync.Once
	scopes *umbrella.ScopeCache
	// HTTP is used for Umbrella calls (tests); nil = default client.
	HTTP *http.Client
	// dependency discovery
	runMu   sync.Mutex
	running bool
}

func (a *App) scopeCache() *umbrella.ScopeCache {
	a.umb.once.Do(func() {
		a.umb.scopes = umbrella.NewScopeCache(func(ctx context.Context, username string) (*umbrella.ScopeReply, error) {
			c, err := a.umbrellaClient(ctx)
			if err != nil {
				return nil, err
			}
			return c.Scope(ctx, username)
		})
	})
	return a.umb.scopes
}

// scopeRestricted reports whether the principal's traffic is restricted to
// their Umbrella scope.
func scopeRestricted(p *Principal) bool {
	if p == nil || !p.Perms.Has(access.ScopeUmbrella) {
		return false
	}
	return p.User.Role != access.RoleAdministrator
}

// scopeRequest returns r with the principal's scope resolver in its context
// when the principal is restricted (called by guard for every request).
func (a *App) scopeRequest(r *http.Request, p *Principal) *http.Request {
	if !scopeRestricted(p) {
		return r
	}
	username := p.User.Username
	return r.WithContext(query.WithScopeFunc(r.Context(), func(ctx context.Context) (*query.Scope, error) {
		reply, _, err := a.scopeCache().Get(ctx, username)
		if err != nil {
			return nil, &query.ScopeError{Err: err}
		}
		return umbrella.QueryScope(reply), nil
	}))
}

// withScope wraps a guarded handler so that it runs with scopeRequest
// (sessions and API tokens alike).
func (a *App) withScope(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, p *Principal) {
		next(w, a.scopeRequest(r, p), p)
	}
}

// scopeView is GET /api/umbrella/scope: the caller's visibility scope, for
// the console's banner.
type scopeView struct {
	Restricted bool       `json:"restricted"`
	OK         bool       `json:"ok"`
	Error      string     `json:"error,omitempty"`
	Configured bool       `json:"configured"`
	Known      bool       `json:"known"`
	Mode       string     `json:"mode,omitempty"`
	CIs        int        `json:"cis"`
	Services   int        `json:"services"`
	Refs       int        `json:"refs"`
	Addresses  int        `json:"addresses"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

func (a *App) myScope(w http.ResponseWriter, r *http.Request, p *Principal) {
	v := scopeView{Restricted: scopeRestricted(p), OK: true}
	ctx := r.Context()
	s, _ := a.loadUmbrellaAPI(ctx)
	v.Configured = s.URL != "" && s.TokenRef != ""
	if !v.Restricted {
		httpx.JSON(w, http.StatusOK, v)
		return
	}
	reply, at, err := a.scopeCache().Get(ctx, p.User.Username)
	v.CheckedAt = &at
	if err != nil {
		v.OK = false
		v.Error = (&query.ScopeError{Err: err}).Error()
		httpx.JSON(w, http.StatusOK, v)
		return
	}
	fillScopeView(&v, reply)
	httpx.JSON(w, http.StatusOK, v)
}

func fillScopeView(v *scopeView, reply *umbrella.ScopeReply) {
	if reply == nil {
		return
	}
	v.Known, v.Mode = reply.Known, reply.Mode
	v.CIs, v.Services = len(reply.CIs), len(reply.Services)
	if s := umbrella.QueryScope(reply); s != nil {
		v.Refs, v.Addresses = len(s.Refs), len(s.Prefixes)
	}
	if !reply.Known {
		v.Mode = ""
	}
}
