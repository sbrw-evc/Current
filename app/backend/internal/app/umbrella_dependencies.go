package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/umbrella"
)

// Dependency discovery (docs/integrations.md §3.3): steady CI ↔ CI traffic
// of the last 7 days becomes "depends on" proposals posted to Umbrella's CMDB,
// daily (settings key "dependencies") and on demand.

// DependencyFinder finds the steady CI ↔ CI pairs (query.Querier).
type DependencyFinder interface {
	DependencyPairs(ctx context.Context, p query.DependencyParams) ([]query.DependencyPair, error)
}

const settingDependencies = "dependencies"

// dependencySettings is the settings key "dependencies".
type dependencySettings struct {
	// Enabled runs discovery daily and sends the proposals.
	Enabled bool `json:"enabled"`
	// Hour (UTC, 0-23) after which the daily run starts.
	Hour         int `json:"hour"`
	MinFlows     int `json:"min_flows"`
	MinDays      int `json:"min_days"`
	MaxProposals int `json:"max_proposals"`
}

func defaultDependencySettings() dependencySettings {
	return dependencySettings{Enabled: false, Hour: 3, MinFlows: 100, MinDays: 3, MaxProposals: 500}
}

func (s dependencySettings) validate() error {
	switch {
	case s.Hour < 0 || s.Hour > 23:
		return httpx.BadRequest("invalid_hour", "hour must be 0-23 (UTC)")
	case s.MinFlows < 1 || s.MinFlows > 100_000_000:
		return httpx.BadRequest("invalid_min_flows", "min_flows must be at least 1")
	case s.MinDays < 1 || s.MinDays > 7:
		return httpx.BadRequest("invalid_min_days", "min_days must be 1-7")
	case s.MaxProposals < 1 || s.MaxProposals > 5000:
		return httpx.BadRequest("invalid_max_proposals", "max_proposals must be 1-5000")
	}
	return nil
}

func (s dependencySettings) params() query.DependencyParams {
	return query.DependencyParams{Days: 7, MinFlows: s.MinFlows, MinDays: s.MinDays, Limit: s.MaxProposals}
}

func (a *App) loadDependencySettings(ctx context.Context) (dependencySettings, error) {
	s := defaultDependencySettings()
	_, err := a.st.Setting(ctx, settingDependencies, &s)
	return s, err
}

// staleRun: a run without a result after this long was interrupted.
const staleRun = 30 * time.Minute

// dependenciesView is GET /api/dependencies.
type dependenciesView struct {
	Settings   dependencySettings    `json:"settings"`
	Configured bool                  `json:"configured"`
	Available  bool                  `json:"available"`
	Running    bool                  `json:"running"`
	NextRun    *time.Time            `json:"next_run"`
	LastRun    *store.DependencyRun  `json:"last_run"`
	Runs       []store.DependencyRun `json:"runs"`
	Proposals  json.RawMessage       `json:"proposals"`
}

func fixStale(r *store.DependencyRun, now time.Time) {
	if r.FinishedAt == nil && now.Sub(r.StartedAt) > staleRun {
		f := false
		r.OK = &f
		r.Error = "interrupted"
	}
}

func (a *App) dependenciesState(ctx context.Context) (dependenciesView, error) {
	v := dependenciesView{Available: a.deps.Dependencies != nil, Runs: []store.DependencyRun{}, Proposals: json.RawMessage("[]")}
	var err error
	if v.Settings, err = a.loadDependencySettings(ctx); err != nil {
		return v, err
	}
	api, err := a.loadUmbrellaAPI(ctx)
	if err != nil {
		return v, err
	}
	v.Configured = api.URL != "" && api.TokenRef != ""
	a.umb.runMu.Lock()
	v.Running = a.umb.running
	a.umb.runMu.Unlock()
	now := time.Now().UTC()
	if v.Runs, err = a.st.DependencyRuns(ctx, 10); err != nil {
		return v, err
	}
	for i := range v.Runs {
		fixStale(&v.Runs[i], now)
	}
	last, err := a.st.LatestDependencyRun(ctx, true)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return v, err
	default:
		if len(last.Proposals) > 0 {
			v.Proposals = last.Proposals
		}
		last.Proposals = nil
		v.LastRun = &last
	}
	if v.Settings.Enabled && v.Configured && v.Available {
		next := time.Date(now.Year(), now.Month(), now.Day(), v.Settings.Hour, 0, 0, 0, time.UTC)
		done, err := a.st.ScheduledDependencyRunOn(ctx, now)
		if err != nil {
			return v, err
		}
		if done {
			next = next.Add(24 * time.Hour)
		} else if next.Before(now) {
			next = now // within the next scheduler tick
		}
		v.NextRun = &next
	}
	return v, nil
}

func (a *App) getDependencies(w http.ResponseWriter, r *http.Request, p *Principal) {
	v, err := a.dependenciesState(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *App) putDependencySettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	in := defaultDependencySettings()
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		httpx.Err(w, err)
		return
	}
	ctx := r.Context()
	if err := a.st.PutSetting(ctx, settingDependencies, in); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "dependencies.settings", "", in)
	a.getDependencies(w, r, p)
}

// errRunning: a discovery run is already in progress in this process.
var errRunning = &httpx.HTTPError{Status: http.StatusConflict, Code: "already_running", Msg: "dependency discovery is already running"}

// runDependencies discovers the pairs, builds the proposals and, unless
// dryRun, posts them to Umbrella. day is set for the scheduled run (claimed
// once per day across processes; store.ErrConflict when already claimed).
func (a *App) runDependencies(ctx context.Context, trigger, actor string, dryRun bool, day *time.Time) (store.DependencyRun, []umbrella.Proposal, error) {
	if a.deps.Dependencies == nil {
		return store.DependencyRun{}, nil, &httpx.HTTPError{Status: http.StatusNotImplemented, Code: "not_implemented",
			Msg: "dependency discovery needs ClickHouse in this process"}
	}
	a.umb.runMu.Lock()
	if a.umb.running {
		a.umb.runMu.Unlock()
		return store.DependencyRun{}, nil, errRunning
	}
	a.umb.running = true
	a.umb.runMu.Unlock()
	defer func() {
		a.umb.runMu.Lock()
		a.umb.running = false
		a.umb.runMu.Unlock()
	}()

	set, err := a.loadDependencySettings(ctx)
	if err != nil {
		return store.DependencyRun{}, nil, err
	}
	params := set.params().WithDefaults()
	id, err := a.st.StartDependencyRun(ctx, trigger, actor, dryRun, day, params)
	if err != nil {
		return store.DependencyRun{}, nil, err
	}
	res := store.DependencyRunResult{}
	var props []umbrella.Proposal
	func() {
		end := time.Now().UTC()
		start := end.Add(-time.Duration(params.Days) * 24 * time.Hour)
		pairs, err := a.deps.Dependencies.DependencyPairs(ctx, params)
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Pairs = len(pairs)
		var g setup.General
		if _, err := a.st.Setting(ctx, setup.SettingGeneral, &g); err != nil {
			res.Error = err.Error()
			return
		}
		props = umbrella.BuildProposals(pairs, g.PublicURL, start, end)
		res.Proposals = props
		if dryRun {
			res.OK = true
			return
		}
		c, err := a.umbrellaClient(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		// Batches of 200 keep each request small.
		for i := 0; i < len(props); i += 200 {
			batch := props[i:min(i+200, len(props))]
			out, err := c.SendProposals(ctx, umbrella.Batch{Source: umbrella.Source, GeneratedAt: end, Proposals: batch})
			if err != nil {
				res.Error = fmt.Sprintf("sending proposals to Umbrella: %v", err)
				return
			}
			res.Sent += len(batch)
			res.Accepted += out.Accepted
			res.Updated += out.Updated
			res.Ignored += out.Ignored
		}
		res.OK = true
	}()
	// Record the result even when the request was cancelled.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := a.st.FinishDependencyRun(fctx, id, res); err != nil {
		return store.DependencyRun{}, props, err
	}
	run, err := a.st.LatestDependencyRun(fctx, true)
	if err != nil {
		return store.DependencyRun{}, props, err
	}
	run.Proposals = nil
	if !res.OK {
		slog.Warn("dependency discovery failed", "trigger", trigger, "err", res.Error)
	} else {
		slog.Info("dependency discovery", "trigger", trigger, "pairs", res.Pairs, "sent", res.Sent, "dry_run", dryRun)
	}
	return run, props, nil
}

func (a *App) runDependenciesNow(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		DryRun bool `json:"dry_run"`
	}
	if r.ContentLength != 0 && !httpx.Decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	run, props, err := a.runDependencies(ctx, store.DependencyTriggerManual, p.User.Username, in.DryRun, nil)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "dependencies.run", "", map[string]any{"dry_run": in.DryRun, "ok": run.OK, "pairs": run.Pairs, "sent": run.Sent})
	if props == nil {
		props = []umbrella.Proposal{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"run": run, "proposals": props})
}

// runDependencySchedule runs discovery once a day after the configured hour
// (UTC) while it is enabled and the Umbrella API is configured.
func (a *App) runDependencySchedule(ctx context.Context) {
	if a.deps.Dependencies == nil {
		return
	}
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		a.dependencyTick(ctx, time.Now().UTC())
	}
}

func (a *App) dependencyTick(ctx context.Context, now time.Time) {
	set, err := a.loadDependencySettings(ctx)
	if err != nil || !set.Enabled || now.Hour() < set.Hour {
		return
	}
	api, err := a.loadUmbrellaAPI(ctx)
	if err != nil || api.URL == "" || api.TokenRef == "" {
		return
	}
	if done, err := a.st.ScheduledDependencyRunOn(ctx, now); err != nil || done {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	day := now
	if _, _, err := a.runDependencies(rctx, store.DependencyTriggerSchedule, "", false, &day); err != nil &&
		!errors.Is(err, store.ErrConflict) && !errors.Is(err, errRunning) {
		slog.Warn("scheduled dependency discovery", "err", err)
	}
}
