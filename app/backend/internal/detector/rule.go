// Package detector evaluates traffic rules on the flows stored in ClickHouse
// (link utilization and commit, DDoS, anomalies and drops against weekly
// baselines, silent exporters) and sends firing / resolved events to the
// Umbrella connector built from the network-flow preset (docs/plan.md §4.3).
package detector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Kind is what a rule measures.
type Kind string

const (
	KindLinkUtilization Kind = "link_utilization" // interface bps / speed, per exporter, interface, direction
	KindLinkCommit      Kind = "link_commit"      // 95th percentile (5 min samples) vs circuit commit
	KindDDoSVolumetric  Kind = "ddos_volumetric"  // bps / pps per DstAddr over threshold and baseline × k
	KindDDoSSyn         Kind = "ddos_syn"         // share of SYN-without-ACK packets per DstAddr
	KindTrafficAnomaly  Kind = "traffic_anomaly"  // deviation from the same hour-of-week over N weeks
	KindTrafficDrop     Kind = "traffic_drop"     // actual < ratio × expected
	KindExporterSilent  Kind = "exporter_silent"  // no flows from an exporter for N minutes
	KindCustom          Kind = "custom"           // bps / pps per dimensions compared to a threshold
)

// Kinds lists the rule kinds in display order.
var Kinds = []Kind{KindLinkUtilization, KindLinkCommit, KindDDoSVolumetric, KindDDoSSyn,
	KindTrafficAnomaly, KindTrafficDrop, KindExporterSilent, KindCustom}

// Signal and method of the built-in kinds (plan table 4.3).
var kindSignals = map[Kind]struct{ signal, method string }{
	KindLinkUtilization: {"use.link.utilization", "USE"},
	KindLinkCommit:      {"use.link.commit", "USE"},
	KindDDoSVolumetric:  {"red.ddos.volumetric", "RED"},
	KindDDoSSyn:         {"red.ddos.syn", "RED"},
	KindTrafficAnomaly:  {"red.traffic.anomaly", "RED"},
	KindTrafficDrop:     {"red.traffic.drop", "RED"},
	KindExporterSilent:  {"use.exporter.silent", "USE"},
}

// Severities accepted by Umbrella (P1 … P5).
var Severities = []string{"critical", "error", "warning", "low", "info"}

// Duration is a time.Duration that reads and writes JSON as "5m" (a number
// is taken as seconds).
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string {
	if d == 0 {
		return "0s"
	}
	s := time.Duration(d).String()
	// "5m0s" → "5m", "1h0m0s" → "1h".
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = v
		return nil
	}
	var secs float64
	if err := json.Unmarshal(b, &secs); err != nil {
		return fmt.Errorf("duration: %s", b)
	}
	*d = Duration(secs * float64(time.Second))
	return nil
}

// ParseDuration parses Go durations plus days and weeks ("7d", "2w").
func ParseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(s, suffix); ok {
			f, err := strconv.ParseFloat(n, 64)
			if err != nil {
				return 0, fmt.Errorf("duration %q: %w", s, err)
			}
			return Duration(f * float64(unit)), nil
		}
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", s, err)
	}
	return Duration(v), nil
}

// Thresholds of a rule; which ones apply depends on the kind (see Rule).
type Thresholds struct {
	BPS     float64  `json:"bps,omitempty"`     // bits per second
	PPS     float64  `json:"pps,omitempty"`     // packets per second
	Percent float64  `json:"percent,omitempty"` // of interface speed / of commit
	Ratio   float64  `json:"ratio,omitempty"`   // 0..1
	Silence Duration `json:"silence,omitempty"` // exporter_silent: no flows for this long
}

// Baseline parameters.
type Baseline struct {
	// Weeks of history (same hour-of-week) for traffic_anomaly / traffic_drop.
	Weeks int `json:"weeks,omitempty"`
	// MinSamples: weeks with data needed before the baseline is trusted.
	MinSamples int `json:"min_samples,omitempty"`
	// Window: ddos_volumetric trailing baseline window before the evaluated one.
	Window Duration `json:"window,omitempty"`
	// K: traffic_anomaly — deviation in robust sigmas (1.4826 × MAD);
	// ddos_volumetric — multiplier of the baseline.
	K float64 `json:"k,omitempty"`
	// Ratio: traffic_anomaly — minimum relative deviation from the median.
	Ratio float64 `json:"ratio,omitempty"`
	// MinVolume (bps): groups whose expected and actual rates are both below
	// are ignored.
	MinVolume float64 `json:"min_volume,omitempty"`
	// Direction of traffic_anomaly: "up" (default), "down" or "both".
	Direction string `json:"direction,omitempty"`
}

// Rule is one detection rule. It is stored as JSON by the platform.
//
// Per kind:
//
//   - link_utilization: Thresholds.Percent of interface speed over Window
//     (default 1m), both directions; Filter on flows.
//   - link_commit: 95th percentile of 5-minute bit rates since the start of
//     the month (or over Window when set), max of both directions, above
//     Thresholds.Percent (default 100) of the commit given by CommitSource.
//   - ddos_volumetric: per DstAddr over Window (raw flows, default 1m),
//     bps ≥ Thresholds.BPS or pps ≥ Thresholds.PPS, and above Baseline.K ×
//     the rate of the same address over Baseline.Window before. While firing
//     only the absolute threshold is checked.
//   - ddos_syn: per DstAddr, SYN-without-ACK packets ≥ Thresholds.PPS and
//     their share of TCP packets ≥ Thresholds.Ratio.
//   - traffic_anomaly: per Dimensions (rollup columns), rate over Window vs
//     the median of the same hour-of-week over Baseline.Weeks weeks: deviates
//     by more than max(K × 1.4826 × MAD, Ratio × median).
//   - traffic_drop: per Dimensions, expected (median) ≥ Baseline.MinVolume and
//     actual < Thresholds.Ratio × expected.
//   - exporter_silent: no flows for Thresholds.Silence.
//   - custom: per Dimensions, Metric (bps | pps) Operator (> | <) the
//     Thresholds.BPS / PPS; Signal is required.
type Rule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Kind       Kind       `json:"kind"`
	Filter     string     `json:"filter,omitempty"`
	Dimensions []string   `json:"dimensions,omitempty"`
	Thresholds Thresholds `json:"thresholds"`
	// Window of data each evaluation looks at (kind default when 0).
	Window Duration `json:"window,omitempty"`
	// For: the condition must hold this long before the event fires.
	For Duration `json:"for,omitempty"`
	// Interval between evaluations (kind default when 0).
	Interval Duration `json:"interval,omitempty"`
	// Hysteresis: a firing alert resolves after the condition has been false
	// for this long.
	Hysteresis Duration  `json:"hysteresis,omitempty"`
	Severity   string    `json:"severity"`
	Baseline   *Baseline `json:"baseline,omitempty"`
	// Signal and Method are derived from Kind; for custom rules Signal is
	// required and Method defaults from its prefix (red. / use.).
	Signal string `json:"signal,omitempty"`
	Method string `json:"method,omitempty"`
	// Metric ("bps" | "pps") and Operator (">" | "<") of custom rules.
	Metric   string `json:"metric,omitempty"`
	Operator string `json:"operator,omitempty"`
	// Title template: ${ci}, ${ip}, ${value}, ${value_text}, ${rule},
	// ${group}, ${threshold_text}, ${expected_text} and every label
	// (${interface}, ${exporter}, ${direction}, ${dst_ip}, dimension names…).
	// Empty: the kind's default.
	Title string `json:"title,omitempty"`
}

// SignalMethod returns the event signal and method of the rule.
func (r Rule) SignalMethod() (signal, method string) {
	if s, ok := kindSignals[r.Kind]; ok {
		return s.signal, s.method
	}
	signal, method = r.Signal, strings.ToUpper(r.Method)
	if method == "" {
		switch {
		case strings.HasPrefix(signal, "red."):
			method = "RED"
		case strings.HasPrefix(signal, "use."):
			method = "USE"
		}
	}
	return signal, method
}

// kind defaults: window, interval.
var kindDefaults = map[Kind]struct{ window, interval time.Duration }{
	KindLinkUtilization: {time.Minute, time.Minute},
	KindLinkCommit:      {0, 15 * time.Minute},
	KindDDoSVolumetric:  {time.Minute, 30 * time.Second},
	KindDDoSSyn:         {time.Minute, 30 * time.Second},
	KindTrafficAnomaly:  {15 * time.Minute, 5 * time.Minute},
	KindTrafficDrop:     {15 * time.Minute, 5 * time.Minute},
	KindExporterSilent:  {0, time.Minute},
	KindCustom:          {5 * time.Minute, time.Minute},
}

// WithDefaults fills zero fields with the kind defaults.
func (r Rule) WithDefaults() Rule {
	d := kindDefaults[r.Kind]
	if r.Window == 0 {
		r.Window = Duration(d.window)
	}
	if r.Interval == 0 {
		r.Interval = Duration(d.interval)
	}
	if r.Severity == "" {
		r.Severity = "warning"
	}
	b := Baseline{}
	if r.Baseline != nil {
		b = *r.Baseline
	}
	switch r.Kind {
	case KindLinkCommit:
		if r.Thresholds.Percent == 0 {
			r.Thresholds.Percent = 100
		}
	case KindDDoSVolumetric:
		if b.Window == 0 {
			b.Window = Duration(time.Hour)
		}
		if b.K == 0 {
			b.K = 3
		}
	case KindTrafficAnomaly, KindTrafficDrop:
		if b.Weeks == 0 {
			b.Weeks = 4
		}
		if b.MinSamples == 0 {
			b.MinSamples = min(2, b.Weeks)
		}
		if r.Kind == KindTrafficAnomaly {
			if b.K == 0 {
				b.K = 3
			}
			if b.Direction == "" {
				b.Direction = "up"
			}
		}
	case KindExporterSilent:
		if r.Thresholds.Silence == 0 {
			r.Thresholds.Silence = Duration(10 * time.Minute)
		}
	case KindCustom:
		if r.Metric == "" {
			r.Metric = "bps"
		}
		if r.Operator == "" {
			r.Operator = ">"
		}
	}
	r.Baseline = &b
	return r
}

var (
	ruleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	signalRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
)

// rollupKind: the kind reads the aggregated tables only.
func rollupKind(k Kind) bool {
	return k == KindTrafficAnomaly || k == KindTrafficDrop || k == KindLinkCommit
}

func inRollup(name string) bool {
	c, ok := schema.ByName(name)
	return ok && (c.Rollup || c.Metric || c.Name == "TimeReceived")
}

// ValidateRule checks a rule; all problems are joined in the error.
func ValidateRule(r Rule) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if !ruleIDRe.MatchString(r.ID) {
		bad("id %q: lower-case letters, digits, '.', '_', '-' (max 64)", r.ID)
	}
	if _, ok := kindDefaults[r.Kind]; !ok {
		bad("kind %q is unknown", r.Kind)
		return errors.Join(errs...)
	}
	if r.Severity != "" && !slices.Contains(Severities, r.Severity) {
		bad("severity %q: one of %v", r.Severity, Severities)
	}
	fr, err := filter.Compile(r.Filter)
	if err != nil {
		bad("filter: %v", err)
	} else if rollupKind(r.Kind) {
		for _, c := range fr.Columns {
			if !inRollup(c) {
				bad("filter: column %s is not in the aggregated tables", c)
			}
		}
	}
	seen := map[string]bool{}
	for _, d := range r.Dimensions {
		c, ok := schema.ByName(d)
		switch {
		case !ok || !c.Dimension:
			bad("dimension %q is unknown", d)
		case seen[d]:
			bad("dimension %q is repeated", d)
		case (r.Kind == KindTrafficAnomaly || r.Kind == KindTrafficDrop) && !c.Rollup:
			bad("dimension %s is not in the aggregated tables", d)
		}
		seen[d] = true
	}
	if len(r.Dimensions) > 8 {
		bad("at most 8 dimensions")
	}
	for name, d := range map[string]Duration{"window": r.Window, "for": r.For, "interval": r.Interval, "hysteresis": r.Hysteresis} {
		if d < 0 {
			bad("%s must not be negative", name)
		}
	}
	if r.Interval != 0 && r.Interval.D() < 10*time.Second {
		bad("interval must be at least 10s")
	}
	t := r.Thresholds
	if t.BPS < 0 || t.PPS < 0 || t.Percent < 0 || t.Ratio < 0 || t.Silence < 0 {
		bad("thresholds must not be negative")
	}
	if b := r.Baseline; b != nil {
		if b.Weeks < 0 || b.Weeks > 52 || b.MinSamples < 0 || b.K < 0 || b.Ratio < 0 || b.MinVolume < 0 || b.Window < 0 {
			bad("baseline: weeks 0..52, other values not negative")
		}
		if b.MinSamples > 0 && b.Weeks > 0 && b.MinSamples > b.Weeks {
			bad("baseline: min_samples > weeks")
		}
		if b.Direction != "" && b.Direction != "up" && b.Direction != "down" && b.Direction != "both" {
			bad("baseline: direction is up, down or both")
		}
	}
	switch r.Kind {
	case KindLinkUtilization:
		if t.Percent <= 0 {
			bad("thresholds.percent is required")
		}
	case KindDDoSVolumetric:
		if t.BPS <= 0 && t.PPS <= 0 {
			bad("thresholds.bps or thresholds.pps is required")
		}
	case KindDDoSSyn:
		if t.Ratio <= 0 || t.Ratio > 1 {
			bad("thresholds.ratio must be in (0, 1]")
		}
	case KindTrafficDrop:
		if t.Ratio <= 0 || t.Ratio >= 1 {
			bad("thresholds.ratio must be in (0, 1)")
		}
	case KindCustom:
		if !signalRe.MatchString(r.Signal) {
			bad("signal is required for custom rules (lower-case, e.g. red.traffic.dns)")
		}
		if m := strings.ToUpper(r.Method); m != "" && m != "RED" && m != "USE" && m != "OTHER" {
			bad("method is RED, USE or other")
		}
		if r.Metric != "" && r.Metric != "bps" && r.Metric != "pps" {
			bad("metric is bps or pps")
		}
		if r.Operator != "" && r.Operator != ">" && r.Operator != "<" {
			bad("operator is > or <")
		}
		if (r.Metric == "pps" && t.PPS <= 0) || (r.Metric != "pps" && t.BPS <= 0) {
			bad("threshold of the metric is required")
		}
	}
	return errors.Join(errs...)
}

// DefaultRules is the built-in rule set (plan table 4.3).
func DefaultRules() []Rule {
	m := func(d time.Duration) Duration { return Duration(d) }
	return []Rule{
		{
			ID: "link-utilization", Name: "Interface utilization", Enabled: true, Kind: KindLinkUtilization,
			Thresholds: Thresholds{Percent: 85}, Window: m(time.Minute), For: m(5 * time.Minute),
			Interval: m(time.Minute), Hysteresis: m(5 * time.Minute), Severity: "warning",
		},
		{
			ID: "link-commit", Name: "95th percentile above commit", Enabled: true, Kind: KindLinkCommit,
			Thresholds: Thresholds{Percent: 100}, Interval: m(15 * time.Minute), Hysteresis: m(time.Hour),
			Severity: "warning",
		},
		{
			ID: "ddos-volumetric", Name: "Volumetric DDoS", Enabled: true, Kind: KindDDoSVolumetric,
			Filter:     "InIfBoundary = 'external'",
			Thresholds: Thresholds{BPS: 1e9, PPS: 100_000}, Window: m(time.Minute), For: m(time.Minute),
			Interval: m(30 * time.Second), Hysteresis: m(5 * time.Minute), Severity: "critical",
			Baseline: &Baseline{Window: m(time.Hour), K: 3},
		},
		{
			ID: "ddos-syn", Name: "SYN flood", Enabled: true, Kind: KindDDoSSyn,
			Filter:     "InIfBoundary = 'external'",
			Thresholds: Thresholds{Ratio: 0.5, PPS: 10_000}, Window: m(time.Minute), For: m(time.Minute),
			Interval: m(30 * time.Second), Hysteresis: m(5 * time.Minute), Severity: "error",
		},
		{
			ID: "traffic-anomaly", Name: "Traffic anomaly on external interfaces", Enabled: true, Kind: KindTrafficAnomaly,
			Filter: "InIfBoundary = 'external'", Dimensions: []string{"ExporterName", "InIfName"},
			Window: m(15 * time.Minute), For: m(15 * time.Minute), Interval: m(5 * time.Minute),
			Hysteresis: m(15 * time.Minute), Severity: "warning",
			Baseline: &Baseline{Weeks: 4, MinSamples: 2, K: 3, Ratio: 0.5, MinVolume: 10e6, Direction: "up"},
		},
		{
			ID: "traffic-drop", Name: "Service traffic drop", Enabled: true, Kind: KindTrafficDrop,
			Filter: "DstCI != ''", Dimensions: []string{"DstCI"},
			Thresholds: Thresholds{Ratio: 0.1}, Window: m(15 * time.Minute), For: m(15 * time.Minute),
			Interval: m(5 * time.Minute), Hysteresis: m(15 * time.Minute), Severity: "error",
			Baseline: &Baseline{Weeks: 4, MinSamples: 2, MinVolume: 1e6},
		},
		{
			ID: "exporter-silent", Name: "Silent exporter", Enabled: true, Kind: KindExporterSilent,
			Thresholds: Thresholds{Silence: m(10 * time.Minute)}, Interval: m(time.Minute),
			Hysteresis: m(time.Minute), Severity: "low",
		},
		defaultThreatRule(),
	}
}
