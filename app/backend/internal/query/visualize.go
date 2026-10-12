package query

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Visualize request bounds.
const (
	MinLimit  = 1
	MaxLimit  = 50
	MinPoints = 5
	MaxPoints = 2000
)

// normalize applies defaults (points 200, limit 10, units l3bps, graph
// stacked) and validates the request.
func (req VisualizeRequest) normalize() (VisualizeRequest, error) {
	if req.Points == 0 {
		req.Points = 200
	}
	if req.Limit == 0 {
		req.Limit = 10
	}
	if req.Units == "" {
		req.Units = UnitsL3bps
	}
	if req.Graph == "" {
		req.Graph = GraphStacked
	}
	if req.Start.IsZero() || req.End.IsZero() {
		return req, invalid("start", "start and end are required")
	}
	if !req.End.After(req.Start) {
		return req, invalid("end", "end must be after start")
	}
	if req.Points < MinPoints || req.Points > MaxPoints {
		return req, invalid("points", "must be between %d and %d", MinPoints, MaxPoints)
	}
	if req.Limit < MinLimit || req.Limit > MaxLimit {
		return req, invalid("limit", "must be between %d and %d", MinLimit, MaxLimit)
	}
	switch req.Units {
	case UnitsL3bps, UnitsL2bps, UnitsPps, UnitsInL2Pct, UnitsOutL2Pct:
	default:
		return req, invalid("units", "unknown units %q", req.Units)
	}
	switch req.Graph {
	case GraphStacked, GraphLines, GraphGrid:
	case GraphSankey:
		if len(req.Dimensions) == 0 {
			return req, invalid("dimensions", "sankey needs at least one dimension")
		}
	default:
		return req, invalid("graph", "unknown graph %q", req.Graph)
	}
	seen := map[string]bool{}
	for _, d := range req.Dimensions {
		c, ok := schema.ByName(d)
		if !ok || !c.Dimension {
			return req, invalid("dimensions", "%q is not a dimension", d)
		}
		if seen[d] {
			return req, invalid("dimensions", "%q is repeated", d)
		}
		seen[d] = true
	}
	return req, nil
}

// usedColumns lists the columns a request reads (to choose the resolution).
func usedColumns(req VisualizeRequest, fr filter.Result) []string {
	cols := append([]string{}, req.Dimensions...)
	cols = append(cols, fr.Columns...)
	cols = append(cols, unitColumns(req.Units)...)
	if req.Bidirectional {
		n := len(cols)
		for _, c := range cols[:n] {
			cols = append(cols, reverseName(c))
		}
	}
	return cols
}

// Visualize answers POST /api/visualize with a *TimeSeriesResponse or, for
// graph "sankey", a *SankeyResponse. Errors are *ValidationError,
// *filter.Error, or query errors.
func (q *Querier) Visualize(ctx context.Context, req VisualizeRequest) (any, error) {
	req, err := req.normalize()
	if err != nil {
		return nil, err
	}
	fr, err := filter.Compile(req.Filter)
	if err != nil {
		return nil, err
	}
	res := chooseResolution(q.store, usedColumns(req, fr), req.Start, req.End, req.Points, q.now())
	if req.Graph == GraphSankey {
		return q.sankey(ctx, req, fr, sankeyPlan(res, req.Start, req.End))
	}
	p := makePlan(res, req.Start, req.End, req.Points)

	direct, sql1, err := q.series(ctx, p, req.Dimensions, fr.SQL, req.Units, req.Limit, 1)
	if err != nil {
		return nil, err
	}
	all := direct
	sqls := []string{sql1}
	if req.Bidirectional {
		rdims := make([]string, len(req.Dimensions))
		for i, d := range req.Dimensions {
			rdims[i] = reverseName(d)
		}
		reverse, sql2, err := q.series(ctx, p, rdims, fr.ReverseSQL, reverseUnits(req.Units), req.Limit, 2)
		if err != nil {
			return nil, err
		}
		all = append(all, reverse...)
		sqls = append(sqls, sql2)
	}

	out := &TimeSeriesResponse{
		T:          make([]time.Time, p.buckets),
		Rows:       [][]string{},
		Points:     [][]float64{},
		Axis:       []int{},
		Average:    []float64{},
		Min:        []float64{},
		Max:        []float64{},
		P95:        []float64{},
		Resolution: p.res.Name,
		SQL:        strings.Join(sqls, ";\n\n"),
	}
	for i := range out.T {
		out.T[i] = time.Unix(p.start+int64(i)*p.step, 0).UTC()
	}
	for _, s := range all {
		out.Rows = append(out.Rows, s.labels)
		out.Points = append(out.Points, s.values)
		out.Axis = append(out.Axis, s.axis)
		st := computeStats(s.values)
		out.Average = append(out.Average, st.avg)
		out.Min = append(out.Min, st.min)
		out.Max = append(out.Max, st.max)
		out.P95 = append(out.P95, st.p95)
	}
	return out, nil
}

type series struct {
	axis   int
	other  bool
	labels []string
	values []float64
	total  float64
}

// series runs one time-series query and returns the rows ordered by total,
// "Other" last.
func (q *Querier) series(ctx context.Context, p plan, dims []string, filterSQL, units string, limit, axis int) ([]series, string, error) {
	sql := timeSeriesSQL(q.table(p.res), p, dims, filterSQL, units, limit)
	rows, err := q.conn.Query(ctx, sql)
	if err != nil {
		return nil, sql, fmt.Errorf("visualize: %w", err)
	}
	defer rows.Close()
	byKey := map[string]*series{}
	var order []*series
	for rows.Next() {
		var (
			known uint8
			vals  []string
			t     time.Time
			xps   float64
		)
		if err := rows.Scan(&known, &vals, &t, &xps); err != nil {
			return nil, sql, fmt.Errorf("visualize: scan: %w", err)
		}
		key := fmt.Sprint(known, "\x00", strings.Join(vals, "\x00"))
		s := byKey[key]
		if s == nil {
			s = &series{axis: axis, other: known == 0, values: make([]float64, p.buckets)}
			switch {
			case len(dims) == 0:
				s.labels = []string{LabelTotal}
			case known == 0:
				s.labels = make([]string, len(dims))
				for i := range s.labels {
					s.labels[i] = LabelOther
				}
			default:
				s.labels = make([]string, len(dims))
				for i, d := range dims {
					if i < len(vals) {
						s.labels[i] = q.formatValue(d, vals[i])
					}
				}
			}
			byKey[key] = s
			order = append(order, s)
		}
		idx := (t.Unix() - p.start) / p.step
		if idx < 0 || idx >= int64(p.buckets) || math.IsNaN(xps) || math.IsInf(xps, 0) {
			continue
		}
		s.values[idx] += xps
		s.total += xps
	}
	if err := rows.Err(); err != nil {
		return nil, sql, fmt.Errorf("visualize: %w", err)
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].other != order[j].other {
			return !order[i].other
		}
		return order[i].total > order[j].total
	})
	out := make([]series, len(order))
	for i, s := range order {
		out[i] = *s
	}
	return out, sql, nil
}

type stats struct{ avg, min, max, p95 float64 }

// computeStats returns the average, min, max and 95th percentile (linear
// interpolation between closest ranks) of the values.
func computeStats(v []float64) stats {
	if len(v) == 0 {
		return stats{}
	}
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	var sum float64
	for _, x := range v {
		sum += x
	}
	pos := 0.95 * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	p95 := sorted[lo] + (sorted[hi]-sorted[lo])*(pos-float64(lo))
	return stats{avg: sum / float64(len(v)), min: sorted[0], max: sorted[len(sorted)-1], p95: p95}
}

// sankey runs the sankey query and builds nodes and links between
// consecutive dimensions.
func (q *Querier) sankey(ctx context.Context, req VisualizeRequest, fr filter.Result, p plan) (*SankeyResponse, error) {
	sql := sankeySQL(q.table(p.res), p, req.Dimensions, fr.SQL, req.Units, req.Limit)
	rows, err := q.conn.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("visualize: %w", err)
	}
	defer rows.Close()
	out := &SankeyResponse{Rows: [][]string{}, Xps: []float64{}, Nodes: []string{}, Links: []SankeyLink{}, Resolution: p.res.Name, SQL: sql}
	for rows.Next() {
		var (
			vals []*string
			xps  float64
		)
		if err := rows.Scan(&vals, &xps); err != nil {
			return nil, fmt.Errorf("visualize: scan: %w", err)
		}
		labels := make([]string, len(req.Dimensions))
		for i, d := range req.Dimensions {
			if i < len(vals) && vals[i] != nil {
				labels[i] = q.formatValue(d, *vals[i])
			} else {
				labels[i] = LabelOther
			}
		}
		out.Rows = append(out.Rows, labels)
		out.Xps = append(out.Xps, xps)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("visualize: %w", err)
	}
	out.Nodes, out.Links = sankeyGraph(req.Dimensions, out.Rows, out.Xps)
	return out, nil
}

// sankeyGraph derives the nodes ("Column: label", in order of first
// appearance by dimension) and the links between consecutive dimensions
// (summed, largest first).
func sankeyGraph(dims []string, rows [][]string, xps []float64) ([]string, []SankeyLink) {
	nodes := []string{}
	seen := map[string]bool{}
	for i, d := range dims {
		for _, r := range rows {
			n := d + ": " + r[i]
			if !seen[n] {
				seen[n] = true
				nodes = append(nodes, n)
			}
		}
	}
	type pair struct{ s, t string }
	sums := map[pair]float64{}
	var order []pair
	for ri, r := range rows {
		for i := 0; i+1 < len(dims); i++ {
			k := pair{dims[i] + ": " + r[i], dims[i+1] + ": " + r[i+1]}
			if _, ok := sums[k]; !ok {
				order = append(order, k)
			}
			sums[k] += xps[ri]
		}
	}
	links := make([]SankeyLink, 0, len(order))
	for _, k := range order {
		links = append(links, SankeyLink{Source: k.s, Target: k.t, Xps: sums[k]})
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].Xps > links[j].Xps })
	return nodes, links
}
