package inventory

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Fetcher builds snapshots; *Client implements it.
type Fetcher interface {
	Fetch(ctx context.Context) (*Snapshot, error)
}

// Syncer keeps the current snapshot behind an atomic pointer and refreshes
// it on an interval. A failed sync keeps the previous snapshot.
type Syncer struct {
	fetcher  Fetcher
	interval time.Duration
	log      *slog.Logger

	cur     atomic.Pointer[Snapshot]
	last    atomic.Pointer[Stats]
	mu      sync.Mutex // serialises syncs
	trigger chan struct{}
	onSwap  []func(*Snapshot)
}

// SyncerConfig configures a Syncer.
type SyncerConfig struct {
	// Interval between full syncs (default 15 min).
	Interval time.Duration
	Logger   *slog.Logger
	// OnSwap is called after a new snapshot is installed (e.g. to clear
	// enrichment caches).
	OnSwap func(*Snapshot)
}

// NewSyncer returns a syncer that starts with an empty snapshot.
func NewSyncer(f Fetcher, cfg SyncerConfig) *Syncer {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Syncer{fetcher: f, interval: cfg.Interval, log: cfg.Logger, trigger: make(chan struct{}, 1)}
	if cfg.OnSwap != nil {
		s.onSwap = append(s.onSwap, cfg.OnSwap)
	}
	s.cur.Store(Empty())
	return s
}

// Snapshot returns the current snapshot (never nil).
func (s *Syncer) Snapshot() *Snapshot { return s.cur.Load() }

// Current is an alias of Snapshot, so *Syncer satisfies enrich.InventorySource.
func (s *Syncer) Current() *Snapshot { return s.cur.Load() }

// LastStats returns the stats of the last sync attempt (zero before the first).
func (s *Syncer) LastStats() Stats {
	if p := s.last.Load(); p != nil {
		return *p
	}
	return Stats{}
}

// Sync runs a full sync now.
func (s *Syncer) Sync(ctx context.Context) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	snap, err := s.fetcher.Fetch(ctx)
	var st Stats
	if err != nil {
		st = Stats{At: start, OK: false, Error: err.Error(), Duration: time.Since(start)}
		s.last.Store(&st)
		s.log.Warn("inventory sync failed", "error", err)
		return st, err
	}
	st = snap.Stats()
	st.At, st.Duration = start, time.Since(start)
	s.cur.Store(snap)
	s.last.Store(&st)
	for _, f := range s.onSwap {
		f(snap)
	}
	s.log.Info("inventory synced", "devices", st.Devices, "interfaces", st.Interfaces, "prefixes", st.Prefixes,
		"circuits", st.Circuits, "duration", st.Duration)
	return st, nil
}

// Invalidate asks the running loop for an early sync (e.g. on a Ledger
// webhook). It never blocks.
func (s *Syncer) Invalidate() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run syncs immediately and then every interval until ctx is done.
func (s *Syncer) Run(ctx context.Context) {
	const debounce = 5 * time.Second
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.trigger:
			// Coalesce bursts of change events.
			select {
			case <-ctx.Done():
				return
			case <-time.After(debounce):
			}
		}
		s.Sync(ctx) //nolint:errcheck // logged and kept in LastStats
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(s.interval)
	}
}
