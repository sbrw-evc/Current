package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/app"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/detector"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/inventory"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// PGState is a detector.StateStore in PostgreSQL (table detector_state).
type PGState struct{ St *store.Store }

// Load implements detector.StateStore.
func (p PGState) Load(ctx context.Context) (*detector.Snapshot, error) {
	b, err := p.St.DetectorState(ctx)
	if err != nil {
		return nil, err
	}
	return detector.UnmarshalSnapshot(b)
}

// Save implements detector.StateStore.
func (p PGState) Save(ctx context.Context, s *detector.Snapshot) error {
	b, err := detector.MarshalSnapshot(s)
	if err != nil {
		return err
	}
	return p.St.SetDetectorState(ctx, b)
}

// StoredRules returns the rules saved in PostgreSQL, nil when never saved
// (the detector then uses detector.DefaultRules).
func StoredRules(ctx context.Context, st *store.Store) ([]detector.Rule, time.Time, error) {
	list, found, at, err := st.DetectorRules(ctx)
	if err != nil || !found {
		return nil, at, err
	}
	rules := make([]detector.Rule, 0, len(list))
	for _, r := range list {
		var rule detector.Rule
		if err := json.Unmarshal(r.Rule, &rule); err != nil {
			return nil, at, fmt.Errorf("detector rule %s: %w", r.ID, err)
		}
		rules = append(rules, rule)
	}
	return rules, at, nil
}

// CommitFromInventory returns the circuit commit rate (bits per second) of an
// interface from the Inventory DB snapshot: the device by its source_ref (or
// by the exporter address), then the interface by name.
func CommitFromInventory(src func() *inventory.Snapshot) detector.CommitFunc {
	return func(k detector.IfaceKey) (uint64, bool) {
		snap := src()
		if snap == nil {
			return 0, false
		}
		var dev *inventory.Device
		if id, ok := strings.CutPrefix(k.ExporterRef, inventory.RefDevice); ok {
			if n, err := strconv.Atoi(id); err == nil {
				dev, _ = snap.Device(n)
			}
		}
		if dev == nil && k.Exporter.IsValid() {
			dev, _ = snap.Exporter(k.Exporter)
		}
		if dev == nil || dev.Kind == inventory.KindVM {
			return 0, false
		}
		it, ok := snap.InterfaceByName(dev.ID, k.Interface)
		if !ok || it.CommitRate == 0 {
			return 0, false
		}
		return it.CommitRate, true
	}
}

// ExportersFromCollector adapts the collector registry for the detector.
func ExportersFromCollector(c *collector.Collector) detector.ExporterFunc {
	return func() []detector.ExporterSeen {
		reg := c.Exporters()
		out := make([]detector.ExporterSeen, 0, len(reg))
		for _, e := range reg {
			out = append(out, detector.ExporterSeen{Address: e.Address, LastSeen: e.LastSeen})
		}
		return out
	}
}

// DetectorConfig are the dependencies of the detector component.
type DetectorConfig struct {
	Conn      driver.Conn
	Storage   chstore.Config
	Store     *store.Store
	Vault     secrets.Resolver           // Umbrella token
	Collector *collector.Collector       // same process only
	Inventory func() *inventory.Snapshot // nil disables link_commit
	Metrics   prometheus.Registerer
	Log       *slog.Logger
}

// Detector runs internal/detector with rules from PostgreSQL and the Umbrella
// connection from the settings key umbrella (token from OpenBao on each send).
type Detector struct {
	D      *detector.Detector
	Sender *detector.Sender

	st    *store.Store
	vault secrets.Resolver
	log   *slog.Logger

	mu       sync.Mutex
	tokenRef string
	umbrella string // JSON of the applied settings
	rulesAt  time.Time
}

// NewDetector builds the detector.
func NewDetector(ctx context.Context, cfg DetectorConfig) (*Detector, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	d := &Detector{st: cfg.Store, vault: cfg.Vault, log: log.With("component", "detector")}
	d.Sender = detector.NewSender(detector.SenderConfig{Logger: d.log})
	if err := d.reloadUmbrella(ctx); err != nil {
		d.log.Warn("Umbrella settings not loaded", "err", err)
	}
	rules, at, err := StoredRules(ctx, cfg.Store)
	if err != nil {
		return nil, err
	}
	d.rulesAt = at
	var general setup.General
	_, _ = cfg.Store.Setting(ctx, setup.SettingGeneral, &general)
	dc := detector.Config{Conn: cfg.Conn, Storage: cfg.Storage, Rules: rules, Sender: d.Sender,
		State: PGState{cfg.Store}, PublicURL: general.PublicURL, Logger: d.log, Metrics: cfg.Metrics}
	if cfg.Collector != nil {
		dc.Exporters = ExportersFromCollector(cfg.Collector)
	}
	if cfg.Inventory != nil {
		dc.Commit = CommitFromInventory(cfg.Inventory)
	}
	if d.D, err = detector.New(dc); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Detector) token(context.Context) (string, error) {
	d.mu.Lock()
	ref := d.tokenRef
	d.mu.Unlock()
	if ref == "" {
		return "", nil
	}
	return secrets.Value(d.vault, ref)
}

func (d *Detector) reloadUmbrella(ctx context.Context) error {
	var u setup.UmbrellaSettings
	if _, err := d.st.Setting(ctx, setup.SettingUmbrella, &u); err != nil {
		return err
	}
	key, _ := json.Marshal(u)
	d.mu.Lock()
	changed := string(key) != d.umbrella
	d.umbrella, d.tokenRef = string(key), u.TokenRef
	d.mu.Unlock()
	if !changed {
		return nil
	}
	url := ""
	if u.Enabled {
		url = u.IngestURL
	}
	d.Sender.SetTarget(url, d.token)
	d.log.Info("Umbrella target set", "configured", url != "")
	return nil
}

func (d *Detector) reloadRules(ctx context.Context, force bool) error {
	rules, at, err := StoredRules(ctx, d.st)
	if err != nil {
		return err
	}
	d.mu.Lock()
	same := at.Equal(d.rulesAt)
	d.rulesAt = at
	d.mu.Unlock()
	if same && !force {
		return nil
	}
	if rules == nil {
		rules = detector.DefaultRules()
	}
	return d.D.SetRules(rules)
}

// Reload implements app.Reloader.
func (d *Detector) Reload(ctx context.Context, what string) error {
	switch what {
	case app.ReloadUmbrella:
		return d.reloadUmbrella(ctx)
	case app.ReloadDetector:
		return d.reloadRules(ctx, true)
	}
	return nil
}

// Run evaluates the rules and polls the settings every minute (changes made
// by an API in another process) until ctx is done.
func (d *Detector) Run(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := d.reloadUmbrella(ctx); err != nil && ctx.Err() == nil {
					d.log.Warn("Umbrella settings not reloaded", "err", err)
				}
				if err := d.reloadRules(ctx, false); err != nil && ctx.Err() == nil {
					d.log.Warn("detector rules not reloaded", "err", err)
				}
			}
		}
	}()
	if err := d.D.Run(ctx); err != nil && ctx.Err() == nil {
		d.log.Error("detector stopped", "err", err)
	}
}

// Status implements app.StatusReporter (a summary; the full status is GET
// /api/detector/status).
func (d *Detector) Status(context.Context) any {
	s := d.D.Status()
	firing, pending := 0, 0
	errs := 0
	for _, r := range s.Rules {
		firing += r.Firing
		pending += r.Pending
		if r.Error != "" {
			errs++
		}
	}
	return map[string]any{"rules": len(s.Rules), "rule_errors": errs, "firing": firing, "pending": pending,
		"queued": s.Queued, "sender": s.Sender}
}

// DetectorAPI implements app.DetectorService. Local is the detector of this
// process; without it (api role) the status is read from the state the
// detector process persists in PostgreSQL.
type DetectorAPI struct {
	Local *Detector
	Store *store.Store
}

// DefaultRules implements app.DetectorService.
func (a *DetectorAPI) DefaultRules() []json.RawMessage {
	var out []json.RawMessage
	for _, r := range detector.DefaultRules() {
		b, _ := json.Marshal(r)
		out = append(out, b)
	}
	return out
}

// ValidateRule implements app.DetectorService.
func (a *DetectorAPI) ValidateRule(raw json.RawMessage) (string, error) {
	var r detector.Rule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return "", httpx.BadRequest("invalid_rule", "rule: "+err.Error())
	}
	if err := detector.ValidateRule(r); err != nil {
		return r.ID, httpx.BadRequest("invalid_rule", "rule "+r.ID+": "+err.Error())
	}
	return r.ID, nil
}

// Status implements app.DetectorService.
func (a *DetectorAPI) Status(ctx context.Context) (any, error) {
	if a.Local != nil {
		return a.Local.D.Status(), nil
	}
	rules, _, err := StoredRules(ctx, a.Store)
	if err != nil {
		return nil, err
	}
	if rules == nil {
		rules = detector.DefaultRules()
	}
	out := detector.Status{Rules: []detector.RuleStatus{}, Alerts: []detector.AlertState{}}
	for _, r := range rules {
		out.Rules = append(out.Rules, detector.RuleStatus{Rule: r.WithDefaults()})
	}
	b, err := a.Store.DetectorState(ctx)
	if err != nil {
		return nil, err
	}
	snap, err := detector.UnmarshalSnapshot(b)
	if err != nil {
		return nil, err
	}
	if snap != nil {
		out.Alerts = append(out.Alerts, snap.Alerts...)
		out.Queued = len(snap.Outbox)
	}
	return struct {
		detector.Status
		Remote bool `json:"remote"`
	}{out, true}, nil
}

// SendTest implements app.DetectorService.
func (a *DetectorAPI) SendTest(ctx context.Context, url, token string) (any, error) {
	return detector.SendTest(ctx, nil, url, func(context.Context) (string, error) { return token, nil }, "umbrella-flow")
}

var _ app.DetectorService = (*DetectorAPI)(nil)
