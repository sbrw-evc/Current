package query

import (
	"fmt"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

// l2Overhead is the Ethernet overhead added per packet for L2 units:
// header 14 + FCS 4 bytes.
const l2Overhead = 18

// inRollup reports whether a column exists in the aggregated tables.
func inRollup(name string) bool {
	c, ok := schema.ByName(name)
	if !ok {
		return false
	}
	return c.Rollup || c.Metric || c.Name == "TimeReceived"
}

// reverseName returns the opposite-direction column (itself when none).
func reverseName(name string) string {
	if c, ok := schema.ByName(name); ok && c.Reverse != "" {
		return c.Reverse
	}
	return name
}

// chooseResolution picks the table for a query over [start, end) with the
// given number of points, using the columns referenced. Raw is used when a
// column is not in the aggregates; otherwise the coarsest aggregate whose
// interval is ≤ (end-start)/points and whose TTL still covers start. When
// nothing fits but raw no longer covers start, the finest aggregate that
// covers it is used instead.
func chooseResolution(cfg chstore.Config, cols []string, start, end time.Time, points int, now time.Time) chstore.Resolution {
	raw := cfg.Raw()
	for _, c := range cols {
		if !inRollup(c) {
			return raw
		}
	}
	if points < 1 {
		points = 1
	}
	want := end.Sub(start) / time.Duration(points)
	best := raw
	for _, r := range cfg.Rollups() {
		if r.Interval <= want && !start.Before(now.Add(-r.TTL)) {
			best = r
		}
	}
	if best.Name == raw.Name && start.Before(now.Add(-raw.TTL)) {
		for _, r := range cfg.Rollups() {
			if !start.Before(now.Add(-r.TTL)) {
				return r
			}
		}
	}
	return best
}

// plan is the time layout of a time-series query.
type plan struct {
	res     chstore.Resolution
	step    int64 // seconds per point
	start   int64 // unix seconds, aligned on step
	end     int64 // unix seconds, exclusive, start + buckets*step
	buckets int
}

func makePlan(res chstore.Resolution, start, end time.Time, points int) plan {
	span := end.Unix() - start.Unix()
	if span < 1 {
		span = 1
	}
	step := (span + int64(points) - 1) / int64(points)
	if step < 1 {
		step = 1
	}
	if iv := int64(res.Interval / time.Second); iv > 0 {
		step = (step + iv - 1) / iv * iv
	}
	s := start.Unix() / step * step
	n := (end.Unix() - s + step - 1) / step
	if n < 1 {
		n = 1
	}
	return plan{res: res, step: step, start: s, end: s + n*step, buckets: int(n)}
}

// sankeyPlan aligns [start, end) on the resolution interval.
func sankeyPlan(res chstore.Resolution, start, end time.Time) plan {
	iv := int64(res.Interval / time.Second)
	if iv < 1 {
		iv = 1
	}
	s := start.Unix() / iv * iv
	e := (end.Unix() + iv - 1) / iv * iv
	if e <= s {
		e = s + iv
	}
	return plan{res: res, step: e - s, start: s, end: e, buckets: 1}
}

func (p plan) where(filterSQL string) string {
	if strings.TrimSpace(filterSQL) == "" {
		filterSQL = "1"
	}
	return fmt.Sprintf("TimeReceived >= toDateTime(%d) AND TimeReceived < toDateTime(%d) AND (%s)", p.start, p.end, filterSQL)
}

// metricSum is the per-period sum of the unit (divide by seconds for a rate).
func metricSum(units string) string {
	switch units {
	case UnitsL2bps:
		return fmt.Sprintf("toFloat64(sum(Bytes) + %d * sum(Packets)) * 8", l2Overhead)
	case UnitsPps:
		return "toFloat64(sum(Packets))"
	case UnitsInL2Pct:
		return fmt.Sprintf("sum(if(InIfSpeed = 0, 0, (Bytes + %d * Packets) * 8 * 100 / InIfSpeed))", l2Overhead)
	case UnitsOutL2Pct:
		return fmt.Sprintf("sum(if(OutIfSpeed = 0, 0, (Bytes + %d * Packets) * 8 * 100 / OutIfSpeed))", l2Overhead)
	default: // l3bps
		return "toFloat64(sum(Bytes)) * 8"
	}
}

// reverseUnits swaps the interface side of percentage units.
func reverseUnits(units string) string {
	switch units {
	case UnitsInL2Pct:
		return UnitsOutL2Pct
	case UnitsOutL2Pct:
		return UnitsInL2Pct
	}
	return units
}

// unitColumns are the columns a unit reads.
func unitColumns(units string) []string {
	switch units {
	case UnitsInL2Pct:
		return []string{"InIfSpeed"}
	case UnitsOutL2Pct:
		return []string{"OutIfSpeed"}
	}
	return nil
}

// dimExpr is the String expression of a dimension column: IPs in text with
// IPv4-mapped addresses unmapped, everything else via toString.
func dimExpr(name string) string {
	c, _ := schema.ByName(name)
	id := quoteIdent(name)
	if c.Kind == schema.KindIP {
		return schema.IPText(id)
	}
	return "toString(" + id + ")"
}

func dimsArray(dims []string) string {
	parts := make([]string, len(dims))
	for i, d := range dims {
		parts[i] = dimExpr(d)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// timeSeriesSQL returns per (known, dims, t) the rate of units. known is 0
// for the rows folded into "Other" (dims is then empty). Missing time
// buckets are filled with 0 for every series (WITH FILL by sorting prefix).
func timeSeriesSQL(table string, p plan, dims []string, filterSQL, units string, limit int) string {
	where := p.where(filterSQL)
	bucket := fmt.Sprintf("toStartOfInterval(TimeReceived, INTERVAL %d SECOND)", p.step)
	fill := fmt.Sprintf("WITH FILL FROM toDateTime(%d) TO toDateTime(%d) STEP %d", p.start, p.end, p.step)
	value := fmt.Sprintf("%s / %d", metricSum(units), p.step)
	if len(dims) == 0 {
		return fmt.Sprintf(`SELECT
    toUInt8(1) AS known,
    CAST([], 'Array(String)') AS dims,
    %s AS t,
    %s AS xps
FROM %s
WHERE %s
GROUP BY t
ORDER BY t %s`, bucket, value, table, where, fill)
	}
	arr := dimsArray(dims)
	return fmt.Sprintf(`SELECT
    toUInt8(%[1]s IN (
        SELECT %[1]s FROM %[2]s
        WHERE %[3]s
        GROUP BY 1
        ORDER BY %[4]s DESC
        LIMIT %[5]d
    )) AS known,
    if(known = 1, %[1]s, CAST([], 'Array(String)')) AS dims,
    %[6]s AS t,
    %[7]s AS xps
FROM %[2]s
WHERE %[3]s
GROUP BY known, dims, t
ORDER BY known DESC, dims, t %[8]s`, arr, table, where, metricSum(units), limit, bucket, value, fill)
}

// sankeySQL returns per combination the rate of units over the period. Each
// dimension keeps its own top values; the others become NULL ("Other").
func sankeySQL(table string, p plan, dims []string, filterSQL, units string, limit int) string {
	where := p.where(filterSQL)
	parts := make([]string, len(dims))
	for i, d := range dims {
		e := dimExpr(d)
		parts[i] = fmt.Sprintf(`if(%[1]s IN (SELECT %[1]s FROM %[2]s WHERE %[3]s GROUP BY 1 ORDER BY %[4]s DESC LIMIT %[5]d), toNullable(%[1]s), NULL)`,
			e, table, where, metricSum(units), limit)
	}
	return fmt.Sprintf(`SELECT
    [%s] AS dims,
    %s / %d AS xps
FROM %s
WHERE %s
GROUP BY dims
ORDER BY xps DESC`, strings.Join(parts, ",\n     "), metricSum(units), p.step, table, where)
}
