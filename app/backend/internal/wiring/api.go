package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/current/app/backend/internal/classifier"
	"github.com/sbrw-evc/current/app/backend/internal/collector"
	"github.com/sbrw-evc/current/app/backend/internal/devices"
	"github.com/sbrw-evc/current/app/backend/internal/filter"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/query"
	"github.com/sbrw-evc/current/app/backend/internal/schema"
	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
)

// MapError turns query and filter errors into HTTP 400s; other errors pass.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	var ve *query.ValidationError
	if errors.As(err, &ve) {
		return httpx.BadRequest("invalid_request", ve.Error())
	}
	var fe *filter.Error
	if errors.As(err, &fe) {
		return httpx.BadRequest("invalid_filter", fe.Error())
	}
	return err
}

// decode reads a JSON request strictly; errors are 400s.
func decode(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return httpx.BadRequest("invalid_request", "invalid request: "+err.Error())
	}
	return nil
}

// Traffic implements app.Visualizer, app.FlowSearcher, app.ExporterLister
// and app.Widgets over query.Querier.
type Traffic struct {
	Q *query.Querier
	// Collector of this process (role all): its registry is merged into the
	// exporters list. nil in the api role.
	Collector *collector.Collector
	// Devices links exporters to managed network devices; nil = none.
	Devices *devices.Service
}

// Visualize implements app.Visualizer.
func (t *Traffic) Visualize(ctx context.Context, raw json.RawMessage) (any, error) {
	var req query.VisualizeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	out, err := t.Q.Visualize(ctx, req)
	return out, MapError(err)
}

// SearchFlows implements app.FlowSearcher.
func (t *Traffic) SearchFlows(ctx context.Context, raw json.RawMessage) (any, error) {
	var req query.FlowsSearchRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	out, err := t.Q.SearchFlows(ctx, req)
	return out, MapError(err)
}

// Summary implements app.Widgets.
func (t *Traffic) Summary(ctx context.Context) (any, error) {
	out, err := t.Q.WidgetSummary(ctx)
	return out, MapError(err)
}

// Top implements app.Widgets.
func (t *Traffic) Top(ctx context.Context, what string) (any, error) {
	out, err := t.Q.WidgetTop(ctx, what, 0)
	return out, MapError(err)
}

// Graph implements app.Widgets.
func (t *Traffic) Graph(ctx context.Context, points int) (any, error) {
	out, err := t.Q.WidgetGraph(ctx, points)
	return out, MapError(err)
}

// LastFlow implements app.Widgets.
func (t *Traffic) LastFlow(ctx context.Context) (any, error) {
	out, err := t.Q.LastFlow(ctx)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

// Exporters implements app.ExporterLister: the ClickHouse aggregates of the
// last 5 minutes merged with the collector registry of this process
// (exporters silent in ClickHouse, sampling rates, last seen, flows/s and
// interface names learned from option data / sFlow counters).
func (t *Traffic) Exporters(ctx context.Context) (any, error) {
	resp, err := t.Q.Exporters(ctx, 0)
	if err != nil {
		return nil, err
	}
	// The collector registry is not scoped: users restricted to a Beacon
	// scope see only the exporters of their flows.
	if t.Collector != nil && !query.Scoped(ctx) {
		resp.Results = MergeExporters(resp.Results, t.Collector.Exporters())
	}
	if t.Devices != nil {
		LinkExporterDevices(ctx, resp.Results, t.Devices)
	}
	return resp, nil
}

// LinkExporterDevices marks the exporters that are managed devices.
func LinkExporterDevices(ctx context.Context, exps []query.Exporter, svc *devices.Service) {
	links, err := svc.ExporterDevices(ctx)
	if err != nil || len(links) == 0 {
		return
	}
	for i := range exps {
		a, err := netip.ParseAddr(exps[i].Address)
		if err != nil {
			continue
		}
		if d, ok := links[a.Unmap()]; ok {
			exps[i].Device = &query.ExporterDevice{ID: d.ID, Name: d.Name, Status: d.Status, Platform: d.Platform}
		}
	}
}

// MergeExporters merges the collector registry into the ClickHouse exporters.
func MergeExporters(ch []query.Exporter, reg []collector.ExporterInfo) []query.Exporter {
	idx := map[string]int{}
	for i, e := range ch {
		idx[e.Address] = i
	}
	for _, r := range reg {
		addr := r.Address.Unmap().String()
		i, ok := idx[addr]
		if !ok {
			ch = append(ch, query.Exporter{Address: addr, Interfaces: []query.ExporterInterface{}, SamplingRates: []uint64{}})
			i = len(ch) - 1
			idx[addr] = i
		}
		e := &ch[i]
		if r.LastSeen.After(e.LastSeen) {
			e.LastSeen = r.LastSeen.UTC()
		}
		if r.FlowsPerSecond > 0 {
			e.FlowsPerSecond = r.FlowsPerSecond
		}
		for _, rate := range r.SamplingRates {
			if !slices.Contains(e.SamplingRates, rate) {
				e.SamplingRates = append(e.SamplingRates, rate)
			}
		}
		slices.Sort(e.SamplingRates)
		ifIdx := map[uint32]int{}
		for j, it := range e.Interfaces {
			ifIdx[it.Index] = j
		}
		for _, ri := range r.Interfaces {
			j, ok := ifIdx[ri.Index]
			if !ok {
				e.Interfaces = append(e.Interfaces, query.ExporterInterface{Index: ri.Index, Name: ri.Name,
					Description: ri.Description, Speed: ri.Speed})
				continue
			}
			it := &e.Interfaces[j]
			if it.Name == "" {
				it.Name = ri.Name
			}
			if it.Description == "" {
				it.Description = ri.Description
			}
			if it.Speed == 0 {
				it.Speed = ri.Speed
			}
		}
		slices.SortFunc(e.Interfaces, func(a, b query.ExporterInterface) int { return int(a.Index) - int(b.Index) })
	}
	slices.SortFunc(ch, func(a, b query.Exporter) int { return strings.Compare(a.Address, b.Address) })
	return ch
}

// Filter implements app.FilterService: validation and completion by
// internal/filter, value completion from ClickHouse.
type Filter struct {
	Conn    driver.Conn // nil: no value completion from data
	Storage chstore.Config
	// Now is the clock (tests).
	Now func() time.Time
}

type filterError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Offset  int    `json:"offset"`
	Message string `json:"message"`
}

// Validate implements app.FilterService.
func (f *Filter) Validate(_ context.Context, raw json.RawMessage) (any, error) {
	var req struct {
		Filter string `json:"filter"`
	}
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	res, errs := filter.Validate(req.Filter)
	out := struct {
		Valid  bool          `json:"valid"`
		Errors []filterError `json:"errors"`
		Parsed string        `json:"parsed"`
	}{Valid: len(errs) == 0, Errors: []filterError{}}
	for _, e := range errs {
		out.Errors = append(out.Errors, filterError{e.Line, e.Column, e.Offset, e.Message})
	}
	if out.Valid {
		out.Parsed = res.Normalized
	}
	return out, nil
}

// MaxValueCompletions bounds the values read from ClickHouse.
const MaxValueCompletions = 20

// Complete implements app.FilterService.
func (f *Filter) Complete(ctx context.Context, raw json.RawMessage) (any, error) {
	var req struct {
		What   string `json:"what"`
		Column string `json:"column"`
		Prefix string `json:"prefix"`
	}
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	var out []filter.Completion
	switch req.What {
	case "column":
		out = filter.CompleteColumns(req.Prefix)
	case "operator":
		out = filter.CompleteOperators(req.Column)
	case "value":
		var err error
		if out, err = f.values(ctx, req.Column, req.Prefix); err != nil {
			return nil, err
		}
	default:
		return nil, httpx.BadRequest("invalid_request", "what must be column, operator or value")
	}
	if out == nil {
		out = []filter.Completion{}
	}
	return map[string]any{"completions": out}, nil
}

func (f *Filter) values(ctx context.Context, column, prefix string) ([]filter.Completion, error) {
	out := filter.StaticValues(column, prefix)
	kind, ok := filter.ValueColumnKind(column)
	if !ok || f.Conn == nil || (kind != schema.KindString && kind != schema.KindUint) {
		return out, nil
	}
	name, _ := filter.CanonicalColumn(column)
	col, ok := schema.ByName(name)
	if !ok {
		return out, nil
	}
	st := f.Storage.WithDefaults()
	res := st.Raw()
	if col.Rollup {
		if rs := st.Rollups(); len(rs) > 0 {
			res = rs[len(rs)-1] // coarsest (flows_1h)
		}
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	since := now().Add(-24 * time.Hour).Unix()
	expr := "toString(" + chstore.QuoteIdent(col.Name) + ")"
	sql := fmt.Sprintf(`SELECT v FROM (SELECT %[1]s AS v, sum(Bytes) AS b FROM %[2]s
WHERE TimeReceived >= toDateTime(%[3]d) AND startsWith(lower(v), lower(?)) AND v != ''
GROUP BY v) ORDER BY b DESC, v LIMIT %[4]d`, expr, st.Table(res.Table), since, MaxValueCompletions)
	if kind == schema.KindUint {
		sql = strings.Replace(sql, "AND v != ''", "AND v != '0'", 1)
	}
	rows, err := f.Conn.Query(ctx, sql, prefix)
	if err != nil {
		return nil, fmt.Errorf("value completion: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for _, c := range out {
		seen[c.Label] = true
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		c := filter.Completion{Label: v, Detail: col.Name, Quoted: kind == schema.KindString}
		if kind == schema.KindUint && strings.HasSuffix(col.Name, "AS") {
			c.Detail = "AS" + v
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Classifiers implements app.ClassifierService.
type Classifiers struct{}

// Validate implements app.ClassifierService.
func (Classifiers) Validate(kind string, rules []string) error {
	var cfg classifier.Config
	switch kind {
	case classifier.KindExporter:
		cfg.Exporter = rules
	case classifier.KindInterface:
		cfg.Interface = rules
	default:
		return httpx.BadRequest("invalid_kind", "unknown classifier kind "+kind)
	}
	if errs := classifier.Validate(cfg); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, "rule "+strconv.Itoa(e.Index+1)+": "+e.Message)
		}
		return httpx.BadRequest("invalid_rule", strings.Join(msgs, "; "))
	}
	return nil
}

// Preview implements app.ClassifierService. sample is {exporter, interface}
// (classifier.PreviewRequest), or, as the console sends it, the exporter
// object itself (kind exporter) or the interface object with an optional
// "exporter" member (kind interface).
func (Classifiers) Preview(_ context.Context, kind string, rules []string, sample json.RawMessage) (any, error) {
	req := classifier.PreviewRequest{Kind: kind, Rules: rules}
	if len(bytes.TrimSpace(sample)) > 0 && !bytes.Equal(bytes.TrimSpace(sample), []byte("null")) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(sample, &m); err != nil {
			return nil, httpx.BadRequest("invalid_sample", "sample must be a JSON object: "+err.Error())
		}
		_, hasExp := m["exporter"]
		_, hasIf := m["interface"]
		var err error
		switch {
		case hasIf || (hasExp && kind == classifier.KindExporter):
			err = json.Unmarshal(sample, &req.Sample)
		case kind == classifier.KindExporter:
			err = json.Unmarshal(sample, &req.Sample.Exporter)
		default:
			if hasExp {
				err = json.Unmarshal(m["exporter"], &req.Sample.Exporter)
			}
			if err == nil {
				err = json.Unmarshal(sample, &req.Sample.Interface)
			}
		}
		if err != nil {
			return nil, httpx.BadRequest("invalid_sample", "sample: "+err.Error())
		}
	}
	res, err := classifier.Preview(req)
	if err != nil {
		return nil, httpx.BadRequest("invalid_request", err.Error())
	}
	return res, nil
}
