package query

import (
	"context"
	"fmt"
	"sort"
	"time"
)

func exportersSQL(table string, start, end int64) string {
	return fmt.Sprintf(`SELECT
    %[1]s AS address,
    argMax(ExporterName, TimeReceived),
    argMax(ExporterRef, TimeReceived),
    argMax(ExporterSite, TimeReceived),
    argMax(ExporterRole, TimeReceived),
    max(TimeReceived),
    count() / %[2]d,
    arraySort(groupUniqArray(SamplingRate))
FROM %[3]s
WHERE TimeReceived >= toDateTime(%[4]d) AND TimeReceived < toDateTime(%[5]d)
GROUP BY address
ORDER BY address`, dimExpr("ExporterAddress"), end-start, table, start, end)
}

func exporterInterfacesSQL(table string, start, end int64) string {
	return fmt.Sprintf(`SELECT
    address,
    tupleElement(i, 2) AS idx,
    argMax(tupleElement(i, 3), TimeReceived),
    argMax(tupleElement(i, 4), TimeReceived),
    max(tupleElement(i, 5)),
    argMax(tupleElement(i, 6), TimeReceived),
    argMax(tupleElement(i, 7), TimeReceived),
    toFloat64(sumIf(Bytes, tupleElement(i, 1) = 0)) * 8 / %[2]d AS in_bps,
    toFloat64(sumIf(Bytes, tupleElement(i, 1) = 1)) * 8 / %[2]d AS out_bps
FROM (
    SELECT
        %[1]s AS address,
        TimeReceived,
        Bytes,
        arrayJoin([
            (0, InIfIndex, toString(InIfName), toString(InIfDescription), InIfSpeed, toString(InIfBoundary), toString(InIfProvider)),
            (1, OutIfIndex, toString(OutIfName), toString(OutIfDescription), OutIfSpeed, toString(OutIfBoundary), toString(OutIfProvider))
        ]) AS i
    FROM %[3]s
    WHERE TimeReceived >= toDateTime(%[4]d) AND TimeReceived < toDateTime(%[5]d)
)
WHERE idx != 0 OR tupleElement(i, 3) != ''
GROUP BY address, idx
ORDER BY address, idx`, dimExpr("ExporterAddress"), end-start, table, start, end)
}

// Exporters answers GET /api/exporters from the raw flows of the last
// window (0 means WidgetWindow): per exporter its latest attributes, flow
// rate, sampling rates and per-interface in/out bit rates. Exporters silent
// during the window are absent (merge with the exporter registry upstream).
func (q *Querier) Exporters(ctx context.Context, window time.Duration) (*ExportersResponse, error) {
	if window <= 0 {
		window = WidgetWindow
	}
	start, end := q.window(window)
	table := q.table(q.store.Raw())

	rows, err := q.conn.Query(ctx, exportersSQL(table, start, end))
	if err != nil {
		return nil, fmt.Errorf("exporters: %w", err)
	}
	defer rows.Close()
	out := &ExportersResponse{Results: []Exporter{}}
	index := map[string]int{}
	for rows.Next() {
		e := Exporter{Interfaces: []ExporterInterface{}}
		if err := rows.Scan(&e.Address, &e.Name, &e.Ref, &e.Site, &e.Role, &e.LastSeen, &e.FlowsPerSecond, &e.SamplingRates); err != nil {
			return nil, fmt.Errorf("exporters: %w", err)
		}
		e.LastSeen = e.LastSeen.UTC()
		if e.SamplingRates == nil {
			e.SamplingRates = []uint64{}
		}
		index[e.Address] = len(out.Results)
		out.Results = append(out.Results, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("exporters: %w", err)
	}
	rows.Close()

	irows, err := q.conn.Query(ctx, exporterInterfacesSQL(table, start, end))
	if err != nil {
		return nil, fmt.Errorf("exporters: interfaces: %w", err)
	}
	defer irows.Close()
	for irows.Next() {
		var addr string
		var it ExporterInterface
		if err := irows.Scan(&addr, &it.Index, &it.Name, &it.Description, &it.Speed, &it.Boundary, &it.Provider, &it.InBps, &it.OutBps); err != nil {
			return nil, fmt.Errorf("exporters: interfaces: %w", err)
		}
		if i, ok := index[addr]; ok {
			out.Results[i].Interfaces = append(out.Results[i].Interfaces, it)
		}
	}
	if err := irows.Err(); err != nil {
		return nil, fmt.Errorf("exporters: interfaces: %w", err)
	}
	for i := range out.Results {
		sort.SliceStable(out.Results[i].Interfaces, func(a, b int) bool {
			return out.Results[i].Interfaces[a].Index < out.Results[i].Interfaces[b].Index
		})
	}
	return out, nil
}
