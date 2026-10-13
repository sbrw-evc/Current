// Package app is the HTTP application of Umbrella Flow in normal mode (after
// the setup wizard): the router with session authentication, CSRF and
// permission checks, the platform handlers (auth, users, roles, saved views,
// classifiers, Inventory DB connection, status) and thin handlers that call
// the traffic packages through the interfaces in deps.go.
package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Options of the HTTP application.
type Options struct {
	Version        string
	Commit         string
	BuiltAt        string
	Role           string // FLOW_ROLE, shown in /api/status
	SecureCookies  bool
	TrustedProxies []netip.Prefix
	Web            http.Handler // the SPA (httpx.Web)
	// ScheduleInventory runs Inventory DB synchronization on its interval
	// in Run (when Deps.Inventory is set).
	ScheduleInventory bool
	// DataDir holds flow.json; moving the secrets to another OpenBao rewrites
	// it (openbao_migrate.go). Empty = that move is not available.
	DataDir string
}

// App is the HTTP application.
type App struct {
	opt       Options
	deps      Deps
	st        *store.Store
	sessions  *auth.Sessions
	passwords *auth.Passwords
	limiter   *auth.Limiter
	syncMu    sync.Mutex
	cfgMu     sync.RWMutex  // guards deps.Config (replaced by an OpenBao move)
	umb       umbrellaState // Umbrella scopes and dependency discovery (umbrella_*.go)
}

// New builds the application. deps.Store and deps.Vault are required: every
// secret (password hashes, session keys, tokens) lives in OpenBao.
func New(opt Options, deps Deps) *App {
	if opt.Web == nil {
		opt.Web = httpx.Web("")
	}
	if deps.Gatherer == nil {
		deps.Gatherer = prometheus.DefaultGatherer
	}
	if deps.Store == nil || deps.Vault == nil {
		panic("app: Store and Vault are required")
	}
	return &App{opt: opt, deps: deps, st: deps.Store, sessions: auth.NewSessions(deps.Store, auth.NewKeys(deps.Vault), opt.SecureCookies),
		passwords: auth.NewPasswords(deps.Vault), limiter: auth.NewLimiter()}
}

// config returns flow.json as the App knows it. An OpenBao move replaces it
// while requests run, so every read goes through cfgMu.
func (a *App) config() config.File {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.deps.Config
}

// setConfig replaces flow.json as the App knows it.
func (a *App) setConfig(f config.File) {
	a.cfgMu.Lock()
	a.deps.Config = f
	a.cfgMu.Unlock()
}

// Run does the background work until ctx ends: purging expired sessions and,
// when enabled, the Inventory DB schedule.
func (a *App) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { a.sessions.Run(ctx) })
	if a.opt.ScheduleInventory && a.deps.Inventory != nil {
		wg.Go(func() { a.runInventorySchedule(ctx) })
	}
	wg.Go(func() { a.runDependencySchedule(ctx) })
	wg.Wait()
}

var (
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "flow", Subsystem: "http", Name: "requests_total", Help: "HTTP requests by route pattern and status code.",
	}, []string{"route", "code"})
	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "flow", Subsystem: "http", Name: "request_duration_seconds", Help: "HTTP request duration by route pattern.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	}, []string{"route"})
	registerOnce sync.Once
)

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func instrument(next http.Handler) http.Handler {
	registerOnce.Do(func() {
		prometheus.DefaultRegisterer.MustRegister(httpRequests, httpDuration)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" || route == "/" {
			route = "other"
		}
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		httpRequests.WithLabelValues(route, strconv.Itoa(sw.code)).Inc()
		httpDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

// Handler returns the router.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	h := mux.HandleFunc

	// service
	h("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.deps.Gatherer, promhttp.HandlerOpts{}))
	h("GET /api/version", a.version)
	// /api/setup* answer 404 after the setup (the /api/ fallback).

	// sign-in
	h("POST /api/auth/login", a.login)
	h("POST /api/auth/logout", a.logout)
	h("GET /api/auth/me", a.guard(nil, a.me))
	h("POST /api/auth/password", a.guard(nil, a.changeOwnPassword))
	h("GET /api/access/catalog", a.guard(nil, a.catalog))
	h("GET /api/schema", a.guard(nil, a.schema))

	// traffic (other packages through Deps)
	h("POST /api/visualize", a.guard(perms(access.VisualizeView), a.visualize))
	h("POST /api/filter/validate", a.guard(perms(access.VisualizeView, access.FlowsView), a.filterValidate))
	h("POST /api/filter/complete", a.guard(perms(access.VisualizeView, access.FlowsView), a.filterComplete))
	h("POST /api/flows/search", a.guard(perms(access.FlowsView), a.flowsSearch))
	h("GET /api/exporters", a.guard(perms(access.ExportersView), a.exporters))
	h("GET /api/widgets/summary", a.guard(perms(access.VisualizeView), a.widgetSummary))
	h("GET /api/widgets/top/{what}", a.guard(perms(access.VisualizeView), a.widgetTop))
	h("GET /api/widgets/graph", a.guard(perms(access.VisualizeView), a.widgetGraph))
	h("GET /api/widgets/last-flow", a.guard(perms(access.VisualizeView), a.widgetLastFlow))

	// detector
	h("GET /api/detector/rules", a.guard(perms(access.DetectorView), a.getDetectorRules))
	h("PUT /api/detector/rules", a.guard(perms(access.DetectorEdit), a.putDetectorRules))
	h("POST /api/detector/rules/add-defaults", a.guard(perms(access.DetectorEdit), a.addDetectorDefaults))
	h("GET /api/detector/rules/defaults", a.guard(perms(access.DetectorView), a.getDetectorDefaults))
	h("GET /api/detector/status", a.guard(perms(access.DetectorView), a.detectorStatus))

	// saved views
	h("GET /api/saved-views", a.guard(perms(access.VisualizeView), a.listViews))
	h("POST /api/saved-views", a.guard(perms(access.VisualizeView), a.createView))
	h("PUT /api/saved-views/{id}", a.guard(perms(access.VisualizeView), a.updateView))
	h("DELETE /api/saved-views/{id}", a.guard(perms(access.VisualizeView), a.deleteView))

	// sampling overrides
	h("GET /api/sampling-overrides", a.guard(perms(access.ExportersView), a.getSampling))
	h("PUT /api/sampling-overrides", a.guard(perms(access.ExportersEdit), a.putSampling))

	// Inventory DB
	h("GET /api/inventory-db", a.guard(perms(access.InventoryView), a.getInventory))
	h("PUT /api/inventory-db", a.guard(perms(access.InventoryEdit), a.putInventory))
	h("POST /api/inventory-db/test", a.guard(perms(access.InventoryEdit), a.testInventory))
	h("POST /api/inventory-db/sync", a.guard(perms(access.InventorySync), a.syncInventory))
	h("GET /api/inventory-db/unknown", a.guard(perms(access.InventoryView), a.unknownInventory))
	a.inventoryIntegrationRoutes(h) // integrations.inventory, hook, "Create in Inventory DB"

	// classifiers
	h("GET /api/classifiers", a.guard(perms(access.ClassifiersView), a.getClassifiers))
	h("PUT /api/classifiers", a.guard(perms(access.ClassifiersEdit), a.putClassifiers))
	h("POST /api/classifiers/preview", a.guard(perms(access.ClassifiersView), a.previewClassifiers))

	// users, roles, directory
	h("GET /api/users", a.guard(perms(access.UsersView), a.listUsers))
	h("POST /api/users", a.guard(perms(access.UsersEdit), a.createUser))
	h("PUT /api/users/{id}", a.guard(perms(access.UsersEdit), a.updateUser))
	h("DELETE /api/users/{id}", a.guard(perms(access.UsersEdit), a.deleteUser))
	h("PUT /api/users/{id}/password", a.guard(perms(access.UsersEdit), a.setUserPassword))
	h("GET /api/roles", a.guard(perms(access.RolesView, access.UsersView), a.listRoles))
	h("POST /api/roles", a.guard(perms(access.RolesEdit), a.createRole))
	h("PUT /api/roles/{id}", a.guard(perms(access.RolesEdit), a.updateRole))
	h("DELETE /api/roles/{id}", a.guard(perms(access.RolesEdit), a.deleteRole))
	h("GET /api/settings/ldap", a.guard(perms(access.UsersView), a.getLDAP))
	h("PUT /api/settings/ldap", a.guard(perms(access.UsersEdit), a.putLDAP))
	h("POST /api/settings/ldap/test", a.guard(perms(access.UsersEdit), a.testLDAP))

	// Umbrella API: visibility scope, connection, dependency discovery (umbrella_routes.go)
	a.umbrellaRoutes(h)

	// general settings, Umbrella, OpenBao
	h("GET /api/settings/general", a.guard(perms(access.GeneralView), a.getGeneral))
	h("PUT /api/settings/general", a.guard(perms(access.GeneralEdit), a.putGeneral))
	h("POST /api/settings/geoip/test", a.guard(perms(access.GeneralEdit), a.testGeoIP))
	h("GET /api/settings/umbrella", a.guard(perms(access.UmbrellaView), a.getUmbrella))
	h("PUT /api/settings/umbrella", a.guard(perms(access.UmbrellaEdit), a.putUmbrella))
	h("POST /api/settings/umbrella/test", a.guard(perms(access.UmbrellaEdit), a.testUmbrella))
	h("GET /api/settings/openbao", a.guard(perms(access.OpenBaoView), a.getOpenBao))
	h("POST /api/settings/openbao/test", a.guard(perms(access.OpenBaoTest), a.testOpenBao))

	// API tokens, Entra ID sign-in, moving the secrets to another OpenBao
	// (routes in tokens.go, entra.go, openbao_migrate.go)
	a.tokenRoutes(h)
	a.entraRoutes(h)
	a.openbaoMigrateRoutes(h)

	// gNMI / SNMP poller and BMP receiver settings (routing.go, gnmi.go)
	a.routingRoutes(h)

	// status
	h("GET /api/status", a.guard(perms(access.StatusView), a.status))
	h("GET /api/audit", a.guard(perms(access.StatusView), a.listAudit))

	// reverse DNS, threat intelligence, cloud flow logs (extensions.go)
	a.extensionRoutes(h)

	h("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotFound, "not_found", "no such API endpoint")
	})
	mux.Handle("/", a.opt.Web)
	return httpx.Secure(instrument(mux))
}

// ServiceHandler serves /healthz and /metrics only, for roles without the API
// (collector, enricher, detector).
func ServiceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotFound, "not_found", "this role serves only /healthz and /metrics")
	})
	return mux
}

func (a *App) version(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]string{"version": a.opt.Version, "commit": a.opt.Commit, "built_at": a.opt.BuiltAt})
}

// Principal is the signed-in user of a request.
type Principal struct {
	User    store.User
	Perms   access.Set
	Session *auth.Session
	Remote  string
}

type handler func(w http.ResponseWriter, r *http.Request, p *Principal)

func perms(p ...string) []string { return p }

// guard authenticates the request (a session cookie, or an API token in
// "Authorization: Bearer"), checks CSRF on state-changing methods of
// sessions and requires one of anyOf (nil = any signed-in user).
func (a *App) guard(anyOf []string, next handler) http.HandlerFunc {
	next = a.withScope(next) // Umbrella visibility scope for restricted users (umbrella_scope.go)
	return func(w http.ResponseWriter, r *http.Request) {
		if token, ok := auth.BearerToken(r); ok { // API token: no session, no CSRF (tokens.go)
			a.tokenGuard(w, r, token, anyOf, next)
			return
		}
		ctx := r.Context()
		ss, err := a.sessions.Get(ctx, r)
		if err != nil {
			slog.Error("session lookup failed", "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "storage_unavailable", "the configuration database is not available")
			return
		}
		if ss == nil {
			httpx.Error(w, http.StatusUnauthorized, "unauthorized", "sign in first")
			return
		}
		u, err := a.st.UserByID(ctx, ss.UserID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
			_ = a.sessions.Delete(ctx, w, r)
			httpx.Error(w, http.StatusUnauthorized, "unauthorized", "sign in first")
			return
		}
		if err != nil {
			httpx.Err(w, err)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(auth.CSRFHeader)), []byte(ss.CSRF)) != 1 {
				httpx.Error(w, http.StatusForbidden, "csrf", "missing or wrong "+auth.CSRFHeader+" header")
				return
			}
		}
		list, err := a.st.Permissions(ctx, u.ID)
		if err != nil {
			httpx.Err(w, err)
			return
		}
		p := &Principal{User: u, Perms: access.NewSet(list), Session: ss, Remote: httpx.ClientIP(r, a.opt.TrustedProxies)}
		if len(anyOf) > 0 && !p.Perms.Any(anyOf...) {
			httpx.Error(w, http.StatusForbidden, "forbidden", "you do not have the permission "+anyOf[0])
			return
		}
		next(w, r, p)
	}
}

// audit records an action; failures are logged.
func (a *App) audit(ctx context.Context, p *Principal, action, target string, detail any) {
	actor, remote := "", ""
	if p != nil {
		actor, remote = p.User.Username, p.Remote
	}
	if err := a.st.Audit(ctx, actor, action, target, remote, detail); err != nil {
		slog.Warn("audit entry not written", "action", action, "err", err)
	}
}

func (a *App) reload(ctx context.Context, what string) {
	for _, r := range a.deps.Reloaders {
		if err := r.Reload(ctx, what); err != nil {
			slog.Warn("reload failed", "what", what, "err", err)
		}
	}
}

// putSecret stores a secret in OpenBao and returns its openbao:// reference.
func (a *App) putSecret(ctx context.Context, path, key, value string) (string, error) {
	return a.deps.Vault.PutRef(ctx, path, key, value)
}

// deleteSecret removes a secret written by putSecret.
func (a *App) deleteSecret(ctx context.Context, path string) {
	if err := a.deps.Vault.Delete(ctx, path); err != nil {
		slog.Warn("secret not deleted", "path", path, "err", err)
	}
}

// secret resolves an openbao:// reference (30 s cache in the client, so a
// rotation in OpenBao needs no restart). Plain values are refused.
func (a *App) secret(ref string) (string, error) {
	if ref != "" && !secrets.IsRef(ref) {
		return "", errors.New("a secret is stored outside OpenBao: set it again")
	}
	return secrets.Value(a.deps.Vault, ref)
}

func notImplemented(w http.ResponseWriter, what string) {
	httpx.Error(w, http.StatusNotImplemented, "not_implemented", what+" is not available in this build or role")
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid id")
		return 0, false
	}
	return id, true
}

// storeErr maps store errors to replies.
func storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, store.ErrBuiltin):
		httpx.Error(w, http.StatusConflict, "builtin_role", "built-in roles cannot be changed or deleted")
	case errors.Is(err, store.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	default:
		httpx.Err(w, err)
	}
}
