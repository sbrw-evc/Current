package wiring

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/rdns"
)

// SettingStore reads and writes JSON settings; *store.Store implements it.
type SettingStore interface {
	Setting(ctx context.Context, key string, out any) (bool, error)
	PutSetting(ctx context.Context, key string, v any) error
}

// LoadRDNSSettings returns the stored reverse DNS settings (defaults, disabled,
// when none were saved).
func LoadRDNSSettings(ctx context.Context, st SettingStore) (rdns.Settings, error) {
	var s rdns.Settings
	if st != nil {
		if _, err := st.Setting(ctx, rdns.SettingKey, &s); err != nil {
			return rdns.Settings{}.WithDefaults(), err
		}
	}
	return s.WithDefaults(), nil
}

// RDNS is the reverse DNS resolver of an enricher process. It follows the
// settings in PostgreSQL (Reload "rdns" in the same process, polling every
// minute otherwise).
type RDNS struct {
	R   *rdns.Resolver
	st  SettingStore
	log *slog.Logger

	mu  sync.Mutex
	key string
}

// NewRDNS returns the resolver, disabled until Run loads the settings.
func NewRDNS(st SettingStore, reg prometheus.Registerer, log *slog.Logger) (*RDNS, error) {
	if log == nil {
		log = slog.Default()
	}
	r, err := rdns.New(rdns.Settings{}, rdns.Config{Metrics: reg})
	if err != nil {
		return nil, err
	}
	return &RDNS{R: r, st: st, log: log.With("component", "rdns")}, nil
}

func (x *RDNS) refresh(ctx context.Context) {
	s, err := LoadRDNSSettings(ctx, x.st)
	if err != nil {
		x.log.Warn("reverse DNS settings not loaded", "err", err)
		return
	}
	key, _ := json.Marshal(s)
	x.mu.Lock()
	defer x.mu.Unlock()
	if string(key) == x.key {
		return
	}
	if err := x.R.Configure(s); err != nil {
		x.log.Warn("reverse DNS settings rejected", "err", err)
		return
	}
	x.key = string(key)
	x.log.Info("reverse DNS settings applied", "enabled", s.Enabled, "servers", len(s.Servers), "scope", s.Scope)
}

// Run resolves in the background until ctx is done.
func (x *RDNS) Run(ctx context.Context) {
	x.refresh(ctx)
	go x.R.Run(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			x.refresh(ctx)
		}
	}
}

// Reload implements app.Reloader (what = rdns.SettingKey).
func (x *RDNS) Reload(ctx context.Context, what string) error {
	if what == rdns.SettingKey {
		x.refresh(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (x *RDNS) Status(context.Context) any { return x.R.Stats() }
