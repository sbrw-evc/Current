package wiring

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/detector"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// DeviceEvents is the Umbrella sender of the device down / up events when
// the detector (and its sender) does not run in the API process: the same
// connector settings (key "umbrella"), the same event format.
type DeviceEvents struct {
	Sender *detector.Sender
	st     *store.Store
	vault  *secrets.Client
	log    *slog.Logger

	mu       sync.Mutex
	key      string
	tokenRef string
}

// NewDeviceEvents returns the sender; Run follows the settings.
func NewDeviceEvents(st *store.Store, vault *secrets.Client, log *slog.Logger) *DeviceEvents {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "device-events")
	return &DeviceEvents{Sender: detector.NewSender(detector.SenderConfig{Logger: log}), st: st, vault: vault, log: log}
}

func (e *DeviceEvents) token(context.Context) (string, error) {
	e.mu.Lock()
	ref := e.tokenRef
	e.mu.Unlock()
	if ref == "" {
		return "", nil
	}
	return secrets.Value(e.vault, ref)
}

// Refresh re-reads the Umbrella settings.
func (e *DeviceEvents) Refresh(ctx context.Context) error {
	var u setup.UmbrellaSettings
	if _, err := e.st.Setting(ctx, setup.SettingUmbrella, &u); err != nil {
		return err
	}
	key, _ := json.Marshal(u)
	e.mu.Lock()
	changed := string(key) != e.key
	e.key, e.tokenRef = string(key), u.TokenRef
	e.mu.Unlock()
	if changed {
		url := ""
		if u.Enabled {
			url = u.IngestURL
		}
		e.Sender.SetTarget(url, e.token)
	}
	return nil
}

// Reload implements app.Reloader.
func (e *DeviceEvents) Reload(ctx context.Context, what string) error {
	if what == app.ReloadUmbrella {
		return e.Refresh(ctx)
	}
	return nil
}

// Run follows the settings and retries the outbox every minute.
func (e *DeviceEvents) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := e.Refresh(ctx); err != nil && ctx.Err() == nil {
			e.log.Warn("Umbrella settings not loaded", "err", err)
		}
		if len(e.Sender.Pending()) > 0 && e.Sender.Status().Configured {
			if err := e.Sender.Flush(ctx); err != nil && ctx.Err() == nil {
				e.log.Warn("device events not delivered", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Status implements app.StatusReporter.
func (e *DeviceEvents) Status(context.Context) any { return e.Sender.Status() }
