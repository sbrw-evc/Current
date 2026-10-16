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
	"github.com/sbrw-evc/current/app/backend/internal/devices"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/snmp"
	"github.com/sbrw-evc/current/app/backend/internal/store"
)

// SNMP runs the SNMP poller with the settings from PostgreSQL (key "snmp")
// and the credentials from OpenBao. It lives with the enricher, which uses it
// as its last interface name source.
type SNMP struct {
	P     *snmp.Poller
	st    *store.Store
	vault *secrets.Client
	log   *slog.Logger

	// Extra adds credential profiles of other parts of Current (the SNMP
	// credentials of managed network devices, devices.SNMPProfiles) ahead of
	// the configured ones; nil = none.
	Extra func(ctx context.Context) ([]snmp.Profile, error)

	mu      sync.Mutex
	applied string
}

// NewSNMP builds the (disabled) poller; Run applies the settings.
func NewSNMP(st *store.Store, vault *secrets.Client, reg prometheus.Registerer, log *slog.Logger) (*SNMP, error) {
	if log == nil {
		log = slog.Default()
	}
	p, err := snmp.New(reg, log)
	if err != nil {
		return nil, err
	}
	return &SNMP{P: p, st: st, vault: vault, log: log.With("component", "snmp")}, nil
}

// UseCollector polls the exporters known to a collector of this process.
func (s *SNMP) UseCollector(c *collector.Collector) {
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

func (s *SNMP) resolve(ref string) (string, error) {
	if s.vault == nil {
		return "", errors.New("OpenBao is not configured")
	}
	return secrets.Value(s.vault, ref)
}

// Refresh re-reads the settings and applies them when they changed.
func (s *SNMP) Refresh(ctx context.Context) error {
	if s.st == nil {
		return nil
	}
	var set snmp.Settings
	found, err := s.st.Setting(ctx, app.SettingSNMP, &set)
	if err != nil {
		return err
	}
	if !found {
		set.PollExporters = true
	}
	if s.Extra != nil {
		extra, err := s.Extra(ctx)
		if err != nil {
			s.log.Warn("device SNMP credentials not loaded", "err", err)
		}
		set = devices.MergeSNMP(set, extra)
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
		s.log.Info("SNMP settings applied", "enabled", set.Enabled, "profiles", len(set.Profiles), "devices", len(set.Devices))
	}
	return nil
}

// Run polls until ctx ends, re-reading the settings every minute.
func (s *SNMP) Run(ctx context.Context) {
	if err := s.Refresh(ctx); err != nil {
		s.log.Warn("SNMP settings not loaded", "err", err)
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
				s.log.Warn("SNMP settings not loaded", "err", err)
			}
		}
	}
}

// Reload implements app.Reloader.
func (s *SNMP) Reload(ctx context.Context, what string) error {
	if what == app.ReloadSNMP {
		return s.Refresh(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (s *SNMP) Status(context.Context) any {
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
