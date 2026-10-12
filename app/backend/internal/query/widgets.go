package query

import (
	"context"
	"fmt"
	"time"
)

// WidgetWindow is the period of the summary, top and exporter aggregates.
const WidgetWindow = 5 * time.Minute

// TopWhat maps the {what} of /api/widgets/top/{what} to its column.
var TopWhat = map[string]string{
	"src-as":      "SrcAS",
	"dst-as":      "DstAS",
	"src-country": "SrcCountry",
	"dst-country": "DstCountry",
	"app":         "App",
	"exporter":    "ExporterName",
	"src-port":    "SrcPort",
	"dst-port":    "DstPort",
}

// window returns the last WidgetWindow as unix seconds [start, end).
func (q *Querier) window(d time.Duration) (int64, int64) {
	end := q.now().Unix()
	return end - int64(d/time.Second), end
}

func summarySQL(table string, start, end int64) string {
	secs := end - start
	return fmt.Sprintf(`SELECT
    count() / %[1]d AS fps,
    uniqExact(ExporterAddress) AS exporters,
    toFloat64(sumIf(Bytes, InIfBoundary = 'external')) * 8 / %[1]d AS bps_in,
    toFloat64(sumIf(Bytes, OutIfBoundary = 'external')) * 8 / %[1]d AS bps_out
FROM %[2]s
WHERE TimeReceived >= toDateTime(%[3]d) AND TimeReceived < toDateTime(%[4]d)`, secs, table, start, end)
}

// WidgetSummary answers GET /api/widgets/summary over the last 5 minutes.
func (q *Querier) WidgetSummary(ctx context.Context) (*SummaryWidget, error) {
	start, end := q.window(WidgetWindow)
	var out SummaryWidget
	err := q.conn.QueryRow(ctx, summarySQL(q.table(q.store.Raw()), start, end)).
		Scan(&out.FlowsPerSecond, &out.Exporters, &out.BpsInExternal, &out.BpsOutExternal)
	if err != nil {
		return nil, fmt.Errorf("summary widget: %w", err)
	}
	return &out, nil
}

func topSQL(table, column string, start, end int64, limit int) string {
	return fmt.Sprintf(`SELECT v, b, sum(b) OVER () AS total
FROM (
    SELECT %s AS v, toFloat64(sum(Bytes)) AS b
    FROM %s
    WHERE TimeReceived >= toDateTime(%d) AND TimeReceived < toDateTime(%d)
    GROUP BY v
)
ORDER BY b DESC
LIMIT %d`, dimExpr(column), table, start, end, limit)
}

// WidgetTop answers GET /api/widgets/top/{what}: the top values by bytes
// over the last 5 minutes, with the remainder as "Other". limit 0 means 5.
func (q *Querier) WidgetTop(ctx context.Context, what string, limit int) (*TopWidget, error) {
	column, ok := TopWhat[what]
	if !ok {
		return nil, invalid("what", "unknown top %q", what)
	}
	if limit == 0 {
		limit = 5
	}
	if limit < 1 || limit > MaxLimit {
		return nil, invalid("limit", "must be between 1 and %d", MaxLimit)
	}
	start, end := q.window(WidgetWindow)
	rows, err := q.conn.Query(ctx, topSQL(q.table(q.store.Raw()), column, start, end, limit))
	if err != nil {
		return nil, fmt.Errorf("top widget: %w", err)
	}
	defer rows.Close()
	out := &TopWidget{Top: []TopItem{}}
	var total, shown float64
	for rows.Next() {
		var v string
		var b float64
		if err := rows.Scan(&v, &b, &total); err != nil {
			return nil, fmt.Errorf("top widget: %w", err)
		}
		if total <= 0 {
			continue
		}
		shown += b
		out.Top = append(out.Top, TopItem{Name: q.formatValue(column, v), Percent: b * 100 / total})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("top widget: %w", err)
	}
	if total > 0 && total-shown > total*1e-9 {
		out.Top = append(out.Top, TopItem{Name: LabelOther, Percent: (total - shown) * 100 / total})
	}
	return out, nil
}

// WidgetGraph answers GET /api/widgets/graph: inbound external traffic
// (InIfBoundary = 'external') over the last 24 hours in Gbit/s. points 0
// means 200.
func (q *Querier) WidgetGraph(ctx context.Context, points int) (*GraphWidget, error) {
	if points == 0 {
		points = 200
	}
	if points < MinPoints || points > MaxPoints {
		return nil, invalid("points", "must be between %d and %d", MinPoints, MaxPoints)
	}
	end := q.now()
	start := end.Add(-24 * time.Hour)
	res := chooseResolution(q.store, append([]string{"InIfBoundary"}, scopeColumns(ctx)...), start, end, points, end)
	p := makePlan(res, start, end, points)
	s, _, err := q.series(ctx, p, nil, "InIfBoundary = 'external'", UnitsL3bps, 1, 1)
	if err != nil {
		return nil, fmt.Errorf("graph widget: %w", err)
	}
	out := &GraphWidget{T: make([]time.Time, p.buckets), Gbps: make([]float64, p.buckets)}
	for i := range out.T {
		out.T[i] = time.Unix(p.start+int64(i)*p.step, 0).UTC()
	}
	if len(s) > 0 {
		for i, v := range s[0].values {
			out.Gbps[i] = v / 1e9
		}
	}
	return out, nil
}
