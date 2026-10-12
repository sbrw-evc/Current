package wiring

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/threat"
)

// LoadThreatSettings returns the stored threat intelligence settings, or
// the defaults (public lists enabled) when none were saved.
func LoadThreatSettings(ctx context.Context, st SettingStore) (threat.Settings, error) {
	s := threat.Default()
	if st != nil {
		var stored threat.Settings
		found, err := st.Setting(ctx, threat.SettingKey, &stored)
		if err != nil {
			return s, err
		}
		if found {
			s = stored
		}
	}
	return s.WithDefaults(), nil
}

// LoadThreatStatus returns the status of the last refresh written by the
// downloading process (zero when none yet).
func LoadThreatStatus(ctx context.Context, st SettingStore) (threat.Status, error) {
	s := threat.Status{Lists: []threat.ListStatus{}}
	if st == nil {
		return s, nil
	}
	_, err := st.Setting(ctx, threat.StatusKey, &s)
	if s.Lists == nil {
		s.Lists = []threat.ListStatus{}
	}
	return s, err
}

// Threat downloads the threat lists in an enricher process and follows the
// settings (Reload "threat" in the same process, polling every minute
// otherwise). Each refresh result is stored in PostgreSQL for the API.
type Threat struct {
	U   *threat.Updater
	st  SettingStore
	log *slog.Logger

	mu  sync.Mutex
	key string
}

// NewThreat returns the updater, empty until Run loads the settings.
func NewThreat(st SettingStore, reg prometheus.Registerer, log *slog.Logger) (*Threat, error) {
	if log == nil {
		log = slog.Default()
	}
	t := &Threat{st: st, log: log.With("component", "threat")}
	u, err := threat.New(threat.Settings{}, threat.Config{Metrics: reg, OnStatus: t.store})
	if err != nil {
		return nil, err
	}
	t.U = u
	return t, nil
}

func (t *Threat) store(ctx context.Context, s threat.Status) {
	for _, l := range s.Lists {
		if l.Enabled && l.Error != "" {
			t.log.Warn("threat list not updated", "list", l.Name, "err", l.Error)
		}
	}
	if t.st == nil {
		return
	}
	if err := t.st.PutSetting(context.WithoutCancel(ctx), threat.StatusKey, s); err != nil {
		t.log.Warn("threat list status not stored", "err", err)
	}
}

func (t *Threat) refresh(ctx context.Context) {
	s, err := LoadThreatSettings(ctx, t.st)
	if err != nil {
		t.log.Warn("threat settings not loaded", "err", err)
		return
	}
	key, _ := json.Marshal(s)
	t.mu.Lock()
	defer t.mu.Unlock()
	if string(key) == t.key {
		return
	}
	if err := t.U.Configure(s); err != nil {
		t.log.Warn("threat settings rejected", "err", err)
		return
	}
	t.key = string(key)
	t.log.Info("threat settings applied", "enabled", s.Enabled, "lists", len(s.Lists))
}

// Run downloads and refreshes the lists until ctx is done.
func (t *Threat) Run(ctx context.Context) {
	t.refresh(ctx)
	go t.U.Run(ctx)
	tk := time.NewTicker(time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.refresh(ctx)
		}
	}
}

// Reload implements app.Reloader (what = threat.SettingKey).
func (t *Threat) Reload(ctx context.Context, what string) error {
	if what == threat.SettingKey {
		t.refresh(ctx)
	}
	return nil
}

// Status implements app.StatusReporter.
func (t *Threat) Status(context.Context) any { return t.U.Status() }
