package detector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/filter"
	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
)

// Config of the detector.
type Config struct {
	Conn    driver.Conn
	Storage chstore.Config // same as the migrations
	// Rules to evaluate; nil means DefaultRules(). Invalid rules make New fail.
	Rules []Rule
	// Sender receives the events (usually *Sender); nil drops them (they
	// are still visible in Status).
	Sender Sink
	// Exporters gives the last-seen time per exporter (collector registry);
	// nil: derived from the flows in ClickHouse.
	Exporters ExporterSource
	// Commit gives circuit commit rates (Ledger); nil disables link_commit.
	Commit CommitSource
	// State persists alert states and the outbox; nil: in memory only.
	State StateStore
	// PublicURL of Current for links.flow (empty: no links).
	PublicURL string
	// Language of the event titles, read on every evaluation ("ru" | "en");
	// nil: "ru".
	Language func() string
	Now      func() time.Time
	Logger   *slog.Logger
	// Metrics, when set, registers the detector metrics and the
	// per-interface gauges flow_interface_bps and
	// flow_interface_utilization_ratio {exporter, ifname, direction}.
	Metrics prometheus.Registerer
	// Lag: data younger than this is not evaluated yet (flows arrive late);
	// default 30s.
	Lag time.Duration
	// GroupLimit bounds the groups read per query; default 1000.
	GroupLimit int
	// QueryTimeout of one rule evaluation; default 30s.
	QueryTimeout time.Duration
	// TickEvery: how often Run checks for due rules; default 5s.
	TickEvery time.Duration
}

// Detector evaluates the rules and sends the events.
type Detector struct {
	conn       driver.Conn
	store      chstore.Config
	sink       Sink
	exporters  ExporterSource
	commit     CommitSource
	state      StateStore
	publicURL  string
	language   func() string
	now        func() time.Time
	log        *slog.Logger
	lag        time.Duration
	groupLimit int
	timeout    time.Duration
	tickEvery  time.Duration
	m          *metrics

	tickMu    sync.Mutex     // one Tick at a time
	tickCache map[string]any // per-tick query cache (only used under tickMu)

	mu        sync.Mutex
	rules     []*ruleRun
	alerts    map[string]map[string]*AlertState // rule ID → key → state
	queued    []Event                           // events waiting for the next delivery
	dirty     bool
	lastIface time.Time
}

type ruleRun struct {
	rule     Rule // with defaults
	fr       filter.Result
	next     time.Time
	lastEval time.Time
	duration time.Duration
	err      string
	groups   int
}

// New validates the rules, restores the persisted state and returns a
// detector. Call Run to start it.
func New(cfg Config) (*Detector, error) {
	if cfg.Conn == nil {
		return nil, errors.New("detector: Conn is required")
	}
	st := cfg.Storage.WithDefaults()
	if err := st.Validate(); err != nil {
		return nil, err
	}
	d := &Detector{
		conn: cfg.Conn, store: st, sink: cfg.Sender, exporters: cfg.Exporters, commit: cfg.Commit,
		state: cfg.State, publicURL: strings.TrimRight(cfg.PublicURL, "/"), now: cfg.Now, log: cfg.Logger,
		language: cfg.Language,
		lag:      cfg.Lag, groupLimit: cfg.GroupLimit, timeout: cfg.QueryTimeout, tickEvery: cfg.TickEvery,
		alerts: map[string]map[string]*AlertState{},
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.lag <= 0 {
		d.lag = 30 * time.Second
	}
	if d.groupLimit <= 0 {
		d.groupLimit = 1000
	}
	if d.timeout <= 0 {
		d.timeout = 30 * time.Second
	}
	if d.tickEvery <= 0 {
		d.tickEvery = 5 * time.Second
	}
	if d.state == nil {
		d.state = &MemoryStore{}
	}
	var err error
	if d.m, err = newMetrics(cfg.Metrics); err != nil {
		return nil, err
	}
	rules := cfg.Rules
	if rules == nil {
		rules = DefaultRules()
	}
	runs, err := compileRules(rules)
	if err != nil {
		return nil, err
	}
	d.rules = runs

	snap, err := d.state.Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("detector: load state: %w", err)
	}
	if snap != nil {
		for i := range snap.Alerts {
			a := snap.Alerts[i]
			if d.alerts[a.RuleID] == nil {
				d.alerts[a.RuleID] = map[string]*AlertState{}
			}
			d.alerts[a.RuleID][a.Key] = &a
		}
		if r, ok := d.sink.(interface{ Restore([]Event) }); ok && len(snap.Outbox) > 0 {
			r.Restore(snap.Outbox)
		}
	}
	// States of rules that no longer exist resolve on the first tick.
	d.mu.Lock()
	d.reconcileLocked()
	d.mu.Unlock()
	return d, nil
}

// lang is the language of the event titles.
func (d *Detector) lang() string {
	if d.language == nil {
		return LangRU
	}
	return normLang(d.language())
}

func compileRules(rules []Rule) ([]*ruleRun, error) {
	var errs []error
	ids := map[string]bool{}
	runs := make([]*ruleRun, 0, len(rules))
	for _, r := range rules {
		if err := ValidateRule(r); err != nil {
			errs = append(errs, fmt.Errorf("rule %q: %w", r.ID, err))
			continue
		}
		if ids[r.ID] {
			errs = append(errs, fmt.Errorf("rule %q: duplicate id", r.ID))
			continue
		}
		ids[r.ID] = true
		fr, _ := filter.Compile(r.Filter)
		runs = append(runs, &ruleRun{rule: r.WithDefaults(), fr: fr})
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("detector: %w", errors.Join(errs...))
	}
	return runs, nil
}

// SetRules replaces the rules. Alerts of removed or disabled rules are
// resolved (events sent on the next tick); alerts of kept rules continue.
func (d *Detector) SetRules(rules []Rule) error {
	runs, err := compileRules(rules)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	old := map[string]*ruleRun{}
	for _, r := range d.rules {
		old[r.rule.ID] = r
	}
	for _, r := range runs {
		if o := old[r.rule.ID]; o != nil {
			r.lastEval, r.duration, r.err, r.groups = o.lastEval, o.duration, o.err, o.groups
			if o.rule.Interval == r.rule.Interval {
				r.next = o.next
			}
		}
	}
	d.rules = runs
	d.reconcileLocked()
	return nil
}

// reconcileLocked resolves the alerts of rules that are gone or disabled.
func (d *Detector) reconcileLocked() {
	enabled := map[string]bool{}
	for _, r := range d.rules {
		if r.rule.Enabled {
			enabled[r.rule.ID] = true
		}
	}
	now := d.now()
	for id, states := range d.alerts {
		if enabled[id] {
			continue
		}
		for _, st := range states {
			if st.State != StatePending && st.Event != nil {
				d.queued = append(d.queued, resolvedEvent(st, st.Value, now))
			}
		}
		delete(d.alerts, id)
		d.dirty = true
	}
}

// Rules returns the current rules (with defaults filled).
func (d *Detector) Rules() []Rule {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Rule, len(d.rules))
	for i, r := range d.rules {
		out[i] = r.rule
	}
	return out
}

// Run evaluates the rules until ctx is done.
func (d *Detector) Run(ctx context.Context) error {
	t := time.NewTicker(d.tickEvery)
	defer t.Stop()
	for {
		if err := d.Tick(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("detector tick", "err", err)
		}
		select {
		case <-ctx.Done():
			// Last chance to persist.
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = d.save(sctx)
			cancel()
			return nil
		case <-t.C:
		}
	}
}

// Tick evaluates every enabled rule that is due at Now(), delivers the
// resulting events and saves the state. Errors of individual rules are
// recorded in Status and joined in the returned error.
func (d *Detector) Tick(ctx context.Context) error {
	d.tickMu.Lock()
	defer d.tickMu.Unlock()
	d.tickCache = map[string]any{}
	defer func() { d.tickCache = nil }()

	now := d.now()
	d.mu.Lock()
	due := []*ruleRun{}
	for _, r := range d.rules {
		if r.rule.Enabled && !now.Before(r.next) {
			due = append(due, r)
		}
	}
	d.mu.Unlock()

	var errs []error
	for _, r := range due {
		if err := d.evalRule(ctx, r, now); err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", r.rule.ID, err))
		}
	}
	if d.m.registered && (d.lastIface.IsZero() || now.Sub(d.lastIface) >= time.Minute) {
		if err := d.refreshInterfaceMetrics(ctx, now); err != nil {
			errs = append(errs, fmt.Errorf("interface metrics: %w", err))
		} else {
			d.lastIface = now
		}
	}

	d.mu.Lock()
	events := d.queued
	d.queued = nil
	d.updateAlertGaugesLocked()
	d.mu.Unlock()
	if err := d.deliver(ctx, events); err != nil {
		errs = append(errs, err)
	}
	if err := d.save(ctx); err != nil {
		errs = append(errs, fmt.Errorf("save state: %w", err))
	}
	return errors.Join(errs...)
}

func (d *Detector) deliver(ctx context.Context, events []Event) error {
	for _, e := range events {
		d.m.events.WithLabelValues(e.Status).Inc()
	}
	if d.sink == nil {
		return nil
	}
	outbox, hasOutbox := d.sink.(interface{ Pending() []Event })
	if len(events) == 0 && (!hasOutbox || len(outbox.Pending()) == 0) {
		return nil
	}
	err := d.sink.Deliver(ctx, events)
	if hasOutbox {
		d.m.outbox.Set(float64(len(outbox.Pending())))
		d.mu.Lock()
		d.dirty = true
		d.mu.Unlock()
	}
	if err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	return nil
}

func (d *Detector) save(ctx context.Context) error {
	d.mu.Lock()
	if !d.dirty {
		d.mu.Unlock()
		return nil
	}
	snap := &Snapshot{Version: 1, SavedAt: d.now().UTC()}
	for _, id := range slices.Sorted(maps.Keys(d.alerts)) {
		states := d.alerts[id]
		for _, k := range slices.Sorted(maps.Keys(states)) {
			snap.Alerts = append(snap.Alerts, *states[k])
		}
	}
	d.dirty = false
	d.mu.Unlock()
	if p, ok := d.sink.(interface{ Pending() []Event }); ok {
		snap.Outbox = p.Pending()
	}
	if err := d.state.Save(ctx, snap); err != nil {
		d.mu.Lock()
		d.dirty = true
		d.mu.Unlock()
		return err
	}
	return nil
}

func (d *Detector) evalRule(ctx context.Context, r *ruleRun, now time.Time) error {
	d.mu.Lock()
	active := map[string]*AlertState{}
	for k, st := range d.alerts[r.rule.ID] {
		active[k] = st
	}
	d.mu.Unlock()

	qctx, cancel := context.WithTimeout(ctx, d.timeout)
	start := time.Now()
	obs, err := d.evaluate(qctx, evalCtx{rule: r.rule, lang: d.lang(), fr: r.fr, now: now, active: active})
	cancel()
	took := time.Since(start)
	d.m.evals.WithLabelValues(r.rule.ID).Inc()

	d.mu.Lock()
	defer d.mu.Unlock()
	r.lastEval, r.duration, r.next = now, took, now.Add(r.rule.Interval.D())
	if !slices.Contains(d.rules, r) {
		return nil // replaced by SetRules meanwhile
	}
	if err != nil {
		d.m.errors.WithLabelValues(r.rule.ID).Inc()
		r.err = err.Error()
		return err
	}
	r.err, r.groups = "", len(obs)
	d.applyLocked(r.rule, obs, now)
	return nil
}

// applyLocked runs the state machine for the observations of a rule. Groups
// with a state but no observation count as "condition false" with value 0.
func (d *Detector) applyLocked(rule Rule, obs []observation, now time.Time) {
	states := d.alerts[rule.ID]
	if states == nil {
		states = map[string]*AlertState{}
		d.alerts[rule.ID] = states
	}
	seen := map[string]bool{}
	for i := range obs {
		o := &obs[i]
		if seen[o.key] {
			continue
		}
		seen[o.key] = true
		d.step(rule, states, o.key, o, now)
	}
	for k := range states {
		if !seen[k] {
			d.step(rule, states, k, nil, now)
		}
	}
	if len(states) == 0 {
		delete(d.alerts, rule.ID)
	}
}

func (d *Detector) step(rule Rule, states map[string]*AlertState, key string, o *observation, now time.Time) {
	prev := states[key]
	breach, hold, value := false, false, 0.0
	if o != nil {
		breach, hold, value = o.breach, o.hold, o.value
	}
	prevState := ""
	if prev != nil {
		prevState = prev.State
	}
	st, act := advance(prev, breach, hold, now, rule.For.D(), rule.Hysteresis.D())
	if st == nil {
		if prev != nil {
			delete(states, key)
			d.dirty = true
		}
	} else {
		st.RuleID, st.Key, st.Value, st.Seen = rule.ID, key, value, now
		if o != nil {
			st.Group = o.group
		}
		states[key] = st
		if st.State != prevState {
			d.dirty = true
		}
	}
	switch act {
	case actFire:
		ev := d.firingEvent(rule, st, o, now)
		st.Event, st.Sent = &ev, now
		d.queued = append(d.queued, ev)
		d.dirty = true
	case actResolve:
		if prev != nil && prev.Event != nil {
			d.queued = append(d.queued, resolvedEvent(prev, value, now))
		}
	}
}

func (d *Detector) firingEvent(rule Rule, st *AlertState, o *observation, now time.Time) Event {
	signal, method := rule.SignalMethod()
	labels := map[string]string{"rule_id": rule.ID, "rule": rule.Name, "kind": string(rule.Kind), "unit": o.unit}
	for k, v := range o.labels {
		if v != "" {
			labels[k] = v
		}
	}
	vars := map[string]string{}
	maps.Copy(vars, labels)
	maps.Copy(vars, o.vars)
	vars["ci"], vars["ip"], vars["source_ref"], vars["group"] = o.ci, o.ip, o.ref, o.group
	vars["value"] = trimFloat(o.value, 2)
	vars["value_text"] = formatRate(o.value, o.unit, d.lang())
	if vars["exporter"] == "" {
		vars["exporter"] = o.ci
	}
	ev := Event{
		ID: eventID(rule.ID, st.Key, st.Since), Status: StatusFiring, Signal: signal, Method: method,
		Severity: rule.Severity, Title: renderTitle(titleTemplate(rule, d.lang()), vars), CI: o.ci, SourceRef: o.ref, IP: o.ip,
		Value: ptr(o.value), Labels: labels, StartsAt: rfc3339(st.Since),
	}
	if ev.Title == "" {
		ev.Title = signal
	}
	before := o.linkBefore
	if before <= 0 {
		before = 30 * time.Minute
	}
	link := ""
	if o.linkFilter != "" || len(o.linkDims) > 0 {
		link = visualizeLink(d.publicURL, o.linkFilter, o.linkDims, o.linkUnits, st.Since.Add(-before), now.Add(30*time.Minute))
	} else {
		link = incidentLink(d.publicURL, o.ci, o.ip, st.Since, now)
	}
	if link != "" {
		ev.Links = &Links{Flow: link}
	}
	return ev
}

func resolvedEvent(st *AlertState, value float64, now time.Time) Event {
	ev := *st.Event
	ev.Labels = maps.Clone(st.Event.Labels)
	ev.Status, ev.Value, ev.EndsAt = StatusResolved, ptr(value), rfc3339(now)
	return ev
}

// RuleStatus is the state of one rule for the detector page.
type RuleStatus struct {
	Rule       Rule      `json:"rule"`
	LastEval   time.Time `json:"last_eval,omitzero"`
	NextEval   time.Time `json:"next_eval,omitzero"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	Groups     int       `json:"groups"`
	Pending    int       `json:"pending"`
	Firing     int       `json:"firing"`
}

// Status is the detector state for GET /api/detector.
type Status struct {
	Rules  []RuleStatus  `json:"rules"`
	Alerts []AlertState  `json:"alerts"`
	Queued int           `json:"queued"`
	Sender *SenderStatus `json:"sender,omitempty"`
}

// Status returns the rules with their last evaluation and the active alerts.
func (d *Detector) Status() Status {
	d.mu.Lock()
	out := Status{Rules: []RuleStatus{}, Alerts: []AlertState{}, Queued: len(d.queued)}
	for _, r := range d.rules {
		rs := RuleStatus{Rule: r.rule, LastEval: r.lastEval, NextEval: r.next, DurationMS: r.duration.Milliseconds(),
			Error: r.err, Groups: r.groups}
		for _, st := range d.alerts[r.rule.ID] {
			if st.State == StatePending {
				rs.Pending++
			} else {
				rs.Firing++
			}
		}
		out.Rules = append(out.Rules, rs)
	}
	for _, id := range slices.Sorted(maps.Keys(d.alerts)) {
		for _, k := range slices.Sorted(maps.Keys(d.alerts[id])) {
			out.Alerts = append(out.Alerts, *d.alerts[id][k])
		}
	}
	d.mu.Unlock()
	if s, ok := d.sink.(interface{ Status() SenderStatus }); ok {
		ss := s.Status()
		out.Sender = &ss
	}
	return out
}
