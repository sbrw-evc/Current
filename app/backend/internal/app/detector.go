package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// ---- detector rules and status

type detectorRulesView struct {
	Rules     []json.RawMessage `json:"rules"`
	Default   bool              `json:"default"` // never saved: the built-in set
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
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
	out := detectorRulesView{Rules: []json.RawMessage{}}
	if !found {
		out.Default = true
		out.Rules = append(out.Rules, a.deps.Detector.DefaultRules()...)
	} else {
		out.UpdatedAt = &at
		for _, rr := range rules {
			out.Rules = append(out.Rules, rr.Rule)
		}
	}
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
