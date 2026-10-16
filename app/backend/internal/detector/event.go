package detector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/schema"
)

// Event is one event in the format of the Beacon network-flow preset
// (Beacon app/docs/flow.md). The ingest endpoint accepts one object or an
// array.
type Event struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"` // firing | resolved
	Signal    string            `json:"signal"`
	Method    string            `json:"method,omitempty"` // RED | USE
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	CI        string            `json:"ci,omitempty"`
	SourceRef string            `json:"source_ref,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Value     *float64          `json:"value,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Links     *Links            `json:"links,omitempty"`
	StartsAt  string            `json:"starts_at,omitempty"` // RFC 3339 UTC
	EndsAt    string            `json:"ends_at,omitempty"`
}

// Links of an event.
type Links struct {
	Flow string `json:"flow,omitempty"`
}

const (
	StatusFiring   = "firing"
	StatusResolved = "resolved"
)

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func ptr(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	v = math.Round(v*1000) / 1000
	return &v
}

var templateRe = regexp.MustCompile(`\$\{([A-Za-z0-9_.]+)\}`)

// renderTitle replaces ${name} with vars[name] (unknown names become "").
func renderTitle(tpl string, vars map[string]string) string {
	out := templateRe.ReplaceAllStringFunc(tpl, func(m string) string {
		return vars[m[2:len(m)-1]]
	})
	return strings.Join(strings.Fields(out), " ")
}

// formatRate formats a value for event titles in lang with SI prefixes,
// e.g. "4.2 Гбит/с" or "4.2 Gbit/s".
func formatRate(v float64, unit, lang string) string {
	switch unit {
	case "bps":
		return siPrefix(v, strings.Split(unitsBPS.in(lang), "|"))
	case "pps":
		return siPrefix(v, strings.Split(unitsPPS.in(lang), "|"))
	case "%":
		return trimFloat(v, 1) + " %"
	case "min":
		return trimFloat(v, 0) + " " + unitMinutes.in(lang)
	}
	return trimFloat(v, 2)
}

func siPrefix(v float64, units []string) string {
	i := 0
	for math.Abs(v) >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return trimFloat(v, 1) + " " + units[i]
}

func trimFloat(v float64, prec int) string {
	s := fmt.Sprintf("%.*f", prec, v)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

// unmapIP returns the address text with IPv4-mapped IPv6 unmapped.
func unmapIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	return a.Unmap().String()
}

// filterString quotes s as a filter-language string literal.
func filterString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return "'" + r.Replace(s) + "'"
}

// filterValue is the literal of a dimension value for its column.
func filterValue(column, v string) string {
	if c, ok := schema.ByName(column); ok {
		switch c.Kind {
		case schema.KindIP:
			if a, err := netip.ParseAddr(v); err == nil {
				return a.Unmap().String()
			}
		case schema.KindUint:
			if _, err := fmt.Sscanf(v, "%d", new(uint64)); err == nil {
				return v
			}
		}
	}
	return filterString(v)
}

// view is the URL state of the web Visualize page (app/web/src/pages/
// visualize/state.ts): ?q=base64url(JSON) with short keys.
type view struct {
	R [2]string `json:"r"`
	G string    `json:"g"`
	U string    `json:"u"`
	D []string  `json:"d"`
	L int       `json:"l"`
	F string    `json:"f"`
}

// visualizeLink returns <publicURL>/visualize?q=… for the filter, dimensions
// and range ("" without a public URL).
func visualizeLink(publicURL, filterText string, dims []string, units string, from, to time.Time) string {
	if publicURL == "" {
		return ""
	}
	if units == "" {
		units = "l3bps"
	}
	if dims == nil {
		dims = []string{}
	}
	v := view{R: [2]string{rfc3339(from), rfc3339(to)}, G: "stacked", U: units, D: dims, L: 10, F: filterText}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	q := base64.RawURLEncoding.EncodeToString(bytes.TrimSpace(buf.Bytes()))
	return strings.TrimRight(publicURL, "/") + "/visualize?q=" + q
}

// incidentLink is the /go/incident fallback link the web app also accepts.
func incidentLink(publicURL, ci, ip string, from, to time.Time) string {
	if publicURL == "" {
		return ""
	}
	q := make([]string, 0, 4)
	if ci != "" {
		q = append(q, "ci="+url.QueryEscape(ci))
	}
	if ip != "" {
		q = append(q, "ip="+url.QueryEscape(ip))
	}
	q = append(q, "from="+url.QueryEscape(rfc3339(from)), "to="+url.QueryEscape(rfc3339(to)))
	return strings.TrimRight(publicURL, "/") + "/go/incident?" + strings.Join(q, "&")
}

// andFilters joins filter texts with AND, parenthesised.
func andFilters(parts ...string) string {
	var raw []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			raw = append(raw, p)
		}
	}
	if len(raw) == 1 {
		return raw[0]
	}
	for i, p := range raw {
		raw[i] = "(" + p + ")"
	}
	return strings.Join(raw, " AND ")
}
