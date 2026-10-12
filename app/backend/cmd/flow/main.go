// Command flow is Umbrella Flow: one binary for every role of the pipeline
// (FLOW_ROLE = all | collector | enricher | api | detector).
//
// On the first start of the all / api role, without <data>/flow.json, it
// serves the setup wizard; the setup code is written to the log and to
// <data>/setup-token. After the wizard (or on later starts) it opens OpenBao,
// PostgreSQL (migrations applied) and ClickHouse and serves the API and the
// web console.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/demoexporter"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.builtAt=...".
var (
	version = "dev"
	commit  string
	builtAt string
)

func fail(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

// switchHandler serves the current handler: the setup wizard first, then the application.
type switchHandler struct{ cur atomic.Pointer[http.Handler] }

func (s *switchHandler) Set(h http.Handler) { s.cur.Store(&h) }

func (s *switchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := s.cur.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Retry-After", "2")
	httpx.Error(w, http.StatusServiceUnavailable, "starting", "Flow is starting")
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	// Subcommands: `flow demo …` runs the demo exporter; `flow <role>` is FLOW_ROLE=<role>.
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		os.Exit(demo(os.Args[2:]))
	}
	if len(os.Args) > 1 {
		if r, err := config.ParseRole(os.Args[1]); err == nil && !strings.HasPrefix(os.Args[1], "-") {
			_ = os.Setenv("FLOW_ROLE", string(r))
			os.Args = append(os.Args[:1], os.Args[2:]...)
		}
	}
	env, err := config.LoadEnv(nil)
	if err != nil {
		fail("environment", err)
	}
	addr := flag.String("addr", env.Addr, "HTTP listen address (FLOW_ADDR)")
	web := flag.String("web", env.WebDir, "built web UI directory (FLOW_WEB_DIR)")
	dataDir := flag.String("data", env.DataDir, "directory for flow.json and setup-token (FLOW_DATA_DIR)")
	roleFlag := flag.String("role", string(env.Role), "all | collector | enricher | api | detector (FLOW_ROLE)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz of the running server and exit 0 when it answers")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *healthcheck {
		os.Exit(probe(*addr))
	}
	role, err := config.ParseRole(*roleFlag)
	if err != nil {
		fail("role", err)
	}
	env.Role, env.Addr, env.WebDir, env.DataDir = role, *addr, *web, *dataDir
	if env.DataDir == "" {
		fail("data directory", errors.New("FLOW_DATA_DIR must not be empty"))
	}
	if err := os.MkdirAll(env.DataDir, 0o700); err != nil {
		fail("data directory", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := &switchHandler{}
	var bg sync.WaitGroup
	serveAPI := role.Runs(config.RoleAPI)

	webHandler := http.Handler(nil)
	if serveAPI {
		webDir := env.WebDir
		if fi, err := os.Stat(webDir); err != nil || !fi.IsDir() {
			slog.Warn("web UI not found, serving the API only", "dir", webDir)
			webDir = ""
		}
		webHandler = httpx.Web(webDir)
	}

	// ---- collector role: needs no configuration, only NATS (FLOW_NATS_URL).
	// In role all the collector starts with the rest of the pipeline in launch,
	// once flow.json tells which bus to use.
	if role == config.RoleCollector {
		pl, err := runCollectorOnly(ctx, env, func(string, app.StatusReporter) {})
		if err != nil {
			fail("collector", err)
		}
		bg.Go(func() { pl.Run(ctx) })
		slog.Info("collector started", "netflow", env.NetFlowAddr, "sflow", env.SFlowAddr, "nats", env.NATSURL != "")
	}

	// launch starts everything that needs flow.json once it is available.
	launch := func(cfg config.File, vault *secrets.Client, st *store.Store) {
		chConn, err := openClickHouse(cfg, vault)
		if err != nil {
			slog.Warn("ClickHouse not opened", "err", err)
		}
		bg.Go(func() { vault.Run(ctx) })

		deps := app.Deps{Config: cfg, Store: st, Vault: vault, Components: map[string]app.StatusReporter{}}
		if chConn != nil {
			deps.ClickHouse = chConn
		}

		// Pipeline: collector (role all) → bus → enricher (Inventory DB, GeoIP,
		// classifiers, applications) → ClickHouse writer; detector → Umbrella.
		parts, err := startPipeline(ctx, role, env, cfg, vault, st, chConn, &deps, func(f func()) { bg.Go(f) })
		if err != nil {
			fail("pipeline", err)
		}
		if !serveAPI {
			slog.Info("flow ready", "role", role, "clickhouse", cfg.ClickHouse.Addr)
			return
		}
		apiDeps(cfg, st, chConn, parts, &deps)
		a := app.New(app.Options{Version: version, Commit: commit, BuiltAt: builtAt, Role: string(role),
			SecureCookies: env.SecureCookies, TrustedProxies: env.TrustedProxies, Web: webHandler,
			// Inventory DB synchronization is scheduled by the enricher /
			// detector processes (wiring.Inventory), not by the API.
			ScheduleInventory: false, DataDir: env.DataDir}, deps)
		bg.Go(func() { a.Run(ctx) })
		handler.Set(a.Handler())
		slog.Info("flow ready", "role", role, "postgres", "ok", "clickhouse", cfg.ClickHouse.Addr, "openbao", cfg.OpenBao.Addr)
	}

	switch {
	case !role.NeedsConfig():
		handler.Set(serviceMux())
	case !serveAPI:
		// enricher / detector: wait for the wizard of the api role to write flow.json.
		handler.Set(serviceMux())
		bg.Go(func() {
			cfg, ok := waitConfig(ctx, env.DataDir)
			if !ok {
				return
			}
			vault, st, err := open(ctx, cfg, env.StartupWait)
			if err != nil {
				fail("startup", err)
			}
			launch(cfg, vault, st)
		})
	default:
		cfg, found, err := config.Read(env.DataDir)
		if err != nil {
			fail("configuration", err)
		}
		if found && cfg.CompletedAt != nil {
			vault, st, err := open(ctx, cfg, env.StartupWait)
			if err != nil {
				fail("startup", err)
			}
			launch(cfg, vault, st)
		} else {
			token, err := setup.Token(env.DataDir, env.SetupToken)
			if err != nil {
				fail("setup code", err)
			}
			mod := setup.New(setup.Options{DataDir: env.DataDir, Token: token, Version: version, Commit: commit, BuiltAt: builtAt,
				Web: webHandler, TrustedProxies: env.TrustedProxies, Defaults: setup.DefaultsFromEnv(nil)},
				func(r setup.Result) { launch(r.Config, r.Vault, r.Store) })
			handler.Set(mod.Handler())
			slog.Warn("first start: open the web UI and finish the setup wizard", "setup_code", token,
				"file", filepath.Join(env.DataDir, config.SetupTokenFile))
		}
	}

	srv := &http.Server{Addr: env.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("flow started", "version", version, "role", role, "addr", env.Addr, "data_dir", env.DataDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail("server failed", err)
	}
	stop()
	bg.Wait()
	slog.Info("flow stopped")
}

// demo runs the demo exporter: `flow demo -target flow:2055`.
func demo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1:2055", "collector host[:netflow port]; sFlow goes to port 6343 of the same host")
	_ = fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := demoexporter.Run(ctx, demoexporter.DefaultConfig(*target)); err != nil {
		slog.Error("demo exporter", "err", err)
		return 1
	}
	return 0
}

// serviceMux serves /healthz and /metrics for roles without the API.
func serviceMux() http.Handler {
	return app.ServiceHandler()
}

// waitConfig polls for a completed flow.json until ctx ends.
func waitConfig(ctx context.Context, dir string) (config.File, bool) {
	logged := false
	for {
		cfg, found, err := config.Read(dir)
		if err != nil {
			fail("configuration", err)
		}
		if found && cfg.CompletedAt != nil {
			return cfg, true
		}
		if !logged {
			slog.Info("waiting for flow.json: finish the setup wizard of the api role (shared data volume)", "dir", dir)
			logged = true
		}
		select {
		case <-ctx.Done():
			return cfg, false
		case <-time.After(5 * time.Second):
		}
	}
}

// open connects OpenBao and PostgreSQL, waiting up to wait for them, and
// applies the migrations. OpenBao is required: every secret lives there.
func open(ctx context.Context, cfg config.File, wait time.Duration) (*secrets.Client, *store.Store, error) {
	vault, err := cfg.OpenBao.Client()
	if err != nil {
		return nil, nil, err
	}
	if vault == nil {
		return nil, nil, errors.New("flow.json has no OpenBao connection: remove flow.json and run the setup wizard again")
	}
	if err := vault.Ready(ctx, wait); err != nil {
		return nil, nil, fmt.Errorf("OpenBao %s: %w", cfg.OpenBao.Addr, err)
	}
	if err := auth.NewKeys(vault).Ensure(ctx); err != nil {
		return nil, nil, err
	}
	dsn, err := cfg.PostgresDSN(vault)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(wait)
	var st *store.Store
	for {
		st, err = store.Open(ctx, dsn)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, nil, err
		}
		slog.Info("waiting for PostgreSQL", "err", err)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := st.EnsureBuiltinRoles(ctx); err != nil {
		st.Close()
		return nil, nil, err
	}
	return vault, st, nil
}

// openClickHouse opens the connection pool (it dials on first use).
func openClickHouse(cfg config.File, vault *secrets.Client) (driver.Conn, error) {
	if cfg.ClickHouse.Addr == "" {
		return nil, errors.New("ClickHouse is not configured")
	}
	password, err := cfg.ClickHousePassword(vault)
	if err != nil {
		return nil, err
	}
	return clickhouse.Open(cfg.ClickHouse.Options(password, cfg.ClickHouse.Database))
}

func probe(addr string) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
