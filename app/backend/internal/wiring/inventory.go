package wiring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/app"
	"github.com/sbrw-evc/current/app/backend/internal/inventory"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/store"
)

// SettingInventorySyncRequest is the settings key the API of another process
// writes when a synchronization is requested ({"at": time}); the Inventory
// loops of the enricher and detector processes follow it.
const SettingInventorySyncRequest = "inventory_sync_request"

type syncRequest struct {
	At time.Time `json:"at"`
}

// swapFetcher is an inventory.Fetcher whose client changes with the settings.
type swapFetcher struct {
	c atomic.Pointer[inventory.Client]
}

func (f *swapFetcher) Fetch(ctx context.Context) (*inventory.Snapshot, error) {
	c := f.c.Load()
	if c == nil {
		return nil, errors.New("the Ledger connection is not configured")
	}
	return c.Fetch(ctx)
}

// Inventory keeps the Ledger snapshot of this process up to date: it
// follows the connection stored in PostgreSQL (token resolved from OpenBao on
// each sync, never stored or logged), syncs on its interval, at once when the
// settings change (Reload, or seen by polling in other processes) and when a
// sync was run from the API of another process.
type Inventory struct {
	Syncer *inventory.Syncer

	st    *store.Store
	vault secrets.Resolver
	fetch *swapFetcher
	log   *slog.Logger
	wake  chan struct{}

	mu     sync.Mutex
	lastAt time.Time // end of our last sync
	cfgKey string
}

// NewInventory returns the syncer loop; vault may be nil (plain tokens only).
func NewInventory(st *store.Store, vault secrets.Resolver, log *slog.Logger, onSwap func(*inventory.Snapshot)) *Inventory {
	if log == nil {
		log = slog.Default()
	}
	f := &swapFetcher{}
	return &Inventory{
		Syncer: inventory.NewSyncer(f, inventory.SyncerConfig{Logger: log, OnSwap: onSwap}),
		st:     st, vault: vault, fetch: f, log: log.With("component", "inventory"),
		wake: make(chan struct{}, 1),
	}
}

// Current implements enrich.InventorySource.
func (i *Inventory) Current() *inventory.Snapshot { return i.Syncer.Snapshot() }

// SyncWith syncs now with the given connection.
func (i *Inventory) SyncWith(ctx context.Context, url, token string) (inventory.Stats, error) {
	c, err := inventory.NewClient(inventory.Config{URL: url, Token: token})
	if err != nil {
		return inventory.Stats{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.fetch.c.Store(c)
	st, err := i.Syncer.Sync(ctx)
	i.lastAt = time.Now().UTC()
	return st, err
}

// Reload implements app.Reloader.
func (i *Inventory) Reload(_ context.Context, what string) error {
	if what == app.ReloadInventory {
		select {
		case i.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Run follows the stored settings until ctx is done.
func (i *Inventory) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := i.tick(ctx); err != nil && ctx.Err() == nil {
			i.log.Warn("Ledger sync failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-i.wake:
		}
	}
}

func (i *Inventory) tick(ctx context.Context) error {
	c, err := i.st.InventoryDB(ctx)
	if err != nil {
		return err
	}
	if !c.Enabled || c.URL == "" {
		return nil
	}
	key := c.URL + "\x00" + c.TokenRef + "\x00" + c.UpdatedAt.String()
	interval := c.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	i.mu.Lock()
	i.mu.Unlock()
	var req syncRequest
	if _, err := i.st.Setting(ctx, SettingInventorySyncRequest, &req); err != nil {
		return err
	}
	i.mu.Lock()
	due := key != i.cfgKey || time.Since(i.lastAt) >= interval || req.At.After(i.lastAt)
	i.mu.Unlock()
	if !due {
		return nil
	}
	token, err := secrets.Value(i.vault, c.TokenRef)
	if err != nil {
		return fmt.Errorf("Ledger token: %w", err)
	}
	stats, err := i.SyncWith(ctx, c.URL, token)
	i.mu.Lock()
	i.cfgKey = key
	i.mu.Unlock()
	res := store.SyncResult{At: time.Now().UTC(), OK: err == nil, SyncStats: syncStats(stats)}
	if err != nil {
		res.Error = err.Error()
	}
	if rerr := i.st.RecordInventorySync(context.WithoutCancel(ctx), res); rerr != nil {
		i.log.Warn("inventory sync result not recorded", "err", rerr)
	}
	return err
}

// Status implements app.StatusReporter.
func (i *Inventory) Status(context.Context) any {
	s := i.Syncer.LastStats()
	return map[string]any{"last_sync": s, "snapshot_at": i.Syncer.Snapshot().At()}
}

func syncStats(s inventory.Stats) store.SyncStats {
	return store.SyncStats{Devices: s.Devices + s.VMs, Interfaces: s.Interfaces, Prefixes: s.Prefixes, Circuits: s.Circuits}
}

// InventoryAPI implements app.InventorySyncer.
type InventoryAPI struct {
	// Local is the snapshot loop of this process (role all); nil in the api
	// role, where Sync fetches to check the connection and count the objects,
	// and asks the enricher / detector processes to follow (within a minute).
	Local *Inventory
	// Store is where the sync request is recorded (api role).
	Store *store.Store
	// Unknown comes from the enricher of this process; nil gives empty lists.
	Unknown func() any
}

// Test implements app.InventorySyncer.
func (a *InventoryAPI) Test(ctx context.Context, cfg app.InventoryConfig) error {
	c, err := inventory.NewClient(inventory.Config{URL: cfg.URL, Token: cfg.Token})
	if err != nil {
		return err
	}
	return c.Ping(ctx)
}

// Sync implements app.InventorySyncer.
func (a *InventoryAPI) Sync(ctx context.Context, cfg app.InventoryConfig) (store.SyncStats, error) {
	if a.Local != nil {
		st, err := a.Local.SyncWith(ctx, cfg.URL, cfg.Token)
		return syncStats(st), err
	}
	c, err := inventory.NewClient(inventory.Config{URL: cfg.URL, Token: cfg.Token})
	if err != nil {
		return store.SyncStats{}, err
	}
	snap, err := c.Fetch(ctx)
	if err != nil {
		return store.SyncStats{}, err
	}
	if a.Store != nil {
		if err := a.Store.PutSetting(ctx, SettingInventorySyncRequest, syncRequest{At: time.Now().UTC()}); err != nil {
			return syncStats(snap.Stats()), err
		}
	}
	return syncStats(snap.Stats()), nil
}

// UnknownList implements app.InventorySyncer (method Unknown).
func (a *InventoryAPI) unknown() any {
	if a.Unknown == nil {
		return map[string]any{"exporters": []any{}, "addresses": []any{}}
	}
	return a.Unknown()
}

// inventoryAPI adapts InventoryAPI to app.InventorySyncer (Unknown is a field).
type inventoryAPI struct{ *InventoryAPI }

func (a inventoryAPI) Unknown(context.Context) (any, error) { return a.unknown(), nil }

// Syncer returns the app.InventorySyncer.
func (a *InventoryAPI) Syncer() app.InventorySyncer { return inventoryAPI{a} }
