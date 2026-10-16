package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/collector"
	"github.com/sbrw-evc/current/app/backend/internal/gnmi"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/store"
)

// GNMI runs the gNMI poller with the settings from PostgreSQL (key "gnmi")
// and the credentials from OpenBao. It lives with the enricher, which uses it
// as an interface name source after the collector's option data and before
// SNMP.
type GNMI struct {
	P     *gnmi.Poller
	st    *store.Store
	vault *secrets.Client
	log   *slog.Logger

	mu      sync.Mutex
	applied string
}

// NewGNMI builds the (disabled) poller; Run applies the settings.
func NewGNMI(st *store.Store, vault *secrets.Client, reg prometheus.Registerer, log *slog.Logger) (*GNMI, error) {
	if log == nil {
		log = slog.Default()
	}
	p, err := gnmi.New(reg, log)
	if err != nil {
		return nil, err
	}
	return &GNMI{P: p, st: st, vault: vault, log: log.With("component", "gnmi")}, nil
}

// UseCollector polls the exporters known to a collector of this process.
func (s *GNMI) UseCollector(c *collector.Collector) {
	if c == nil {
		return
	}
	s.P.Exporters = func() []netip.Addr {
		exps := c.Exporters()
		out := make([]netip.Addr, 0, len(exps))
		for _, e := range exps {
			out = append(out, e.Address)
		}
		return out
	}
}

func (s *GNMI) resolve(ref string) (string, error) {
	if s.vault == nil {
		return "", errors.New("OpenBao is not configured")
	}
	return secrets.Value(s.vault, ref)
}

// Refresh re-reads the settings and applies them when they changed.
func (s *GNMI) Refresh(ctx context.Context) error {
	if s.st == nil {
		return nil
	}
	var set gnmi.Settings
	found, err := s.st.Setting(ctx, app.SettingGNMI, &set)
	if err != nil {
		return err
	}
	if !found {
		set.PollExporters = true
	}
	key, _ := json.Marshal(set)
	s.mu.Lock()
	defer s.mu.Unlock()
	if string(key) == s.applied {
		return nil
	}
	if err := s.P.Apply(set, s.resolve); err != nil {
		return err
	}
	s.applied = string(key)
	if found {
		s.log.Info("gNMI settings applied", "enabled", set.Enabled, "profiles", len(set.Profiles), "devices", len(set.Devices))
	}
	return nil
}

// Run polls until ctx ends, re-reading the settings every minute.
func (s *GNMI) Run(ctx context.Context) {
	if err := s.Refresh(ctx); err != nil {
		s.log.Warn("gNMI settings not loaded", "err", err)
	}
	go s.P.Run(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil {
				s.log.Warn("gNMI settings not loaded", "err", err)
			}
		}
	}
}

// Reload implements app.Reloader.
func (s *GNMI) Reload(ctx context.Context, what string) error {
	if what == app.ReloadGNMI {
		return s.Refresh(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (s *GNMI) Status(context.Context) any {
	set := s.P.Settings()
	devs := s.P.Status()
	failing := 0
	for _, d := range devs {
		if d.Error != "" {
			failing++
		}
	}
	if len(devs) > 500 {
		devs = devs[:500]
	}
	return map[string]any{"enabled": set.Enabled, "devices": devs, "failing": failing}
}
