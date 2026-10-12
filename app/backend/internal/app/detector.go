package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// ---- detector rules and status

type detectorRulesView struct {
	Rules     []json.RawMessage `json:"rules"`
	Default   bool              `json:"default"` // never saved: the built-in set
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	// NewDefaults: built-in rules added in a later version that the saved
	// set lacks and that were neither deleted nor dismissed (saved sets only).
	NewDefaults []json.RawMessage `json:"new_defaults"`
}

// detectorDismissedKey is the settings key of the built-in rule ids an
// installation does not want offered again: deleted from the saved set, or
// dismissed through POST /api/detector/rules/add-defaults.
const detectorDismissedKey = "detector_defaults_dismissed"

func ruleID(raw json.RawMessage) string {
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.ID
}

func (a *App) dismissedDefaults(ctx context.Context) (map[string]bool, error) {
	var ids []string
	if _, err := a.st.Setting(ctx, detectorDismissedKey, &ids); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (a *App) putDismissedDefaults(ctx context.Context, m map[string]bool) error {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return a.st.PutSetting(ctx, detectorDismissedKey, ids)
}

// newDefaults returns the built-in rules missing from the saved set and not
// dismissed.
func (a *App) newDefaults(ctx context.Context, saved []store.DetectorRule) ([]json.RawMessage, error) {
	dismissed, err := a.dismissedDefaults(ctx)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, r := range saved {
		have[r.ID] = true
	}
	out := []json.RawMessage{}
	for _, d := range a.deps.Detector.DefaultRules() {
		if id := ruleID(d); id != "" && !have[id] && !dismissed[id] {
			out = append(out, d)
		}
	}
	return out, nil
}

func (a *App) getDetectorRules(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Detector == nil {
		notImplemented(w, "detector")
		return
	}
	rules, found, at, err := a.st.DetectorRules(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	out := detectorRulesView{Rules: []json.RawMessage{}, NewDefaults: []json.RawMessage{}}
	if !found {
		out.Default = true
		out.Rules = append(out.Rules, a.deps.Detector.DefaultRules()...)
	} else {
		out.UpdatedAt = &at
		for _, rr := range rules {
			out.Rules = append(out.Rules, rr.Rule)
		}
		if out.NewDefaults, err = a.newDefaults(r.Context(), rules); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	httpx.JSON(w, http.StatusOK, out)
}

// addDetectorDefaults merges built-in rules added by a later version into a
// saved set: {ids?: [..]} adds those new defaults (all of them when ids is
// omitted), {dismiss: [..]} stops offering them. Rules already saved are
// never touched.
func (a *App) addDetectorDefaults(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Detector == nil {
		notImplemented(w, "detector")
		return
	}
	var in struct {
		IDs     *[]string `json:"ids"`
		Dismiss []string  `json:"dismiss"`
	}
	if r.ContentLength != 0 && !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	rules, found, _, err := a.st.DetectorRules(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if !found {
		// The built-in set is in use: every default applies already.
		a.getDetectorRules(w, r, p)
		return
	}
	fresh, err := a.newDefaults(ctx, rules)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	offered := map[string]json.RawMessage{}
	for _, d := range fresh {
		offered[ruleID(d)] = d
	}
	var add []string
	if in.IDs == nil {
		if len(in.Dismiss) == 0 {
			for _, d := range fresh {
				add = append(add, ruleID(d))
			}
		}
	} else {
		add = *in.IDs
	}
	for _, id := range append(slices.Clone(add), in.Dismiss...) {
		if _, ok := offered[id]; !ok {
			httpx.Error(w, http.StatusBadRequest, "unknown_default", "not a new built-in rule: "+id)
			return
		}
	}
	added := 0
	for _, id := range add {
		if slices.Contains(in.Dismiss, id) {
			continue
		}
		rules = append(rules, store.DetectorRule{ID: id, Rule: offered[id]})
		added++
	}
	if added > 0 {
		if err := a.st.SetDetectorRules(ctx, rules); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	if len(in.Dismiss) > 0 {
		dismissed, err := a.dismissedDefaults(ctx)
		if err != nil {
			httpx.Err(w, err)
			return
		}
		for _, id := range in.Dismiss {
			dismissed[id] = true
		}
		if err := a.putDismissedDefaults(ctx, dismissed); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	a.audit(ctx, p, "detector.rules.add_defaults", "", map[string]any{"added": add, "dismissed": in.Dismiss})
	if added > 0 {
		a.reload(ctx, ReloadDetector)
	}
	a.getDetectorRules(w, r, p)
}

// getDetectorDefaults returns the built-in rule set (the console's "restore
// defaults" for one rule or all of them).
func (a *App) getDetectorDefaults(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Detector == nil {
		notImplemented(w, "detector")
		return
	}
	out := detectorRulesView{Rules: []json.RawMessage{}, Default: true}
	out.Rules = append(out.Rules, a.deps.Detector.DefaultRules()...)
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) putDetectorRules(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Detector == nil {
		notImplemented(w, "detector")
		return
	}
	var in struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if len(in.Rules) > 500 {
		httpx.Error(w, http.StatusBadRequest, "too_many_rules", "at most 500 rules")
		return
	}
	seen := map[string]bool{}
	out := make([]store.DetectorRule, 0, len(in.Rules))
	for i, raw := range in.Rules {
		id, err := a.deps.Detector.ValidateRule(raw)
		if err != nil {
			if status, _ := httpx.StatusOf(err); status == http.StatusInternalServerError {
				err = httpx.BadRequest("invalid_rule", fmt.Sprintf("rule %d: %v", i+1, err))
			}
			httpx.Err(w, err)
			return
		}
		if seen[id] {
			httpx.Error(w, http.StatusBadRequest, "duplicate_rule", "rule id "+id+" is repeated")
			return
		}
		seen[id] = true
		out = append(out, store.DetectorRule{ID: id, Rule: raw})
	}
	ctx := r.Context()
	// A built-in rule the saved set had (or the built-in set itself, before
	// the first save) and this one drops was deleted on purpose: it is not
	// offered again as a new default.
	prev, found, _, err := a.st.DetectorRules(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	had := map[string]bool{}
	if found {
		for _, rr := range prev {
			had[rr.ID] = true
		}
	}
	var deleted []string
	for _, d := range a.deps.Detector.DefaultRules() {
		id := ruleID(d)
		if (had[id] || !found) && !seen[id] {
			deleted = append(deleted, id)
		}
	}
	if len(deleted) > 0 {
		dismissed, err := a.dismissedDefaults(ctx)
		if err != nil {
			httpx.Err(w, err)
			return
		}
		for _, id := range deleted {
			dismissed[id] = true
		}
		if err := a.putDismissedDefaults(ctx, dismissed); err != nil {
			httpx.Err(w, err)
			return
		}
	}
	if err := a.st.SetDetectorRules(ctx, out); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "detector.rules", "", map[string]int{"rules": len(out)})
	a.reload(ctx, ReloadDetector)
	a.getDetectorRules(w, r, p)
}

func (a *App) detectorStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Detector == nil {
		notImplemented(w, "detector")
		return
	}
	out, err := a.deps.Detector.Status(r.Context())
	reply(w, out, err)
}
