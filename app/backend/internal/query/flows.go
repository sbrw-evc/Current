package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Search bounds.
const (
	DefaultSearchLimit = 100
	MaxSearchLimit     = 1000
)

// selectExpr returns the SELECT expression of a column for raw flow output
// (IPs as text) and a constructor of its scan destination.
func selectExpr(c schema.Column) (string, func() any) {
	id := quoteIdent(c.Name)
	if c.Kind == schema.KindIP {
		return dimExpr(c.Name), func() any { return new(string) }
	}
	switch c.Type {
	case "Array(UInt32)":
		return id, func() any { return new([]uint32) }
	case "Array(String)":
		return id, func() any { return new([]string) }
	}
	t := strings.TrimSuffix(strings.TrimPrefix(c.Type, "LowCardinality("), ")")
	switch t {
	case "DateTime":
		return id, func() any { return new(time.Time) }
	case "UInt64":
		return id, func() any { return new(uint64) }
	case "UInt32":
		return id, func() any { return new(uint32) }
	case "UInt16":
		return id, func() any { return new(uint16) }
	case "UInt8":
		return id, func() any { return new(uint8) }
	case "String":
		return id, func() any { return new(string) }
	}
	return "toString(" + id + ")", func() any { return new(string) }
}

// deref turns a scan destination into a JSON-ready value.
func deref(v any) any {
	switch x := v.(type) {
	case *time.Time:
		return x.UTC()
	case *uint64:
		return *x
	case *uint32:
		return *x
	case *uint16:
		return *x
	case *uint8:
		return *x
	case *string:
		return *x
	case *[]uint32:
		if *x == nil {
			return []uint32{}
		}
		return *x
	case *[]string:
		if *x == nil {
			return []string{}
		}
		return *x
	}
	return v
}

// rawFlowsQuery selects every registry column of the raw table.
func (q *Querier) rawFlowsQuery(where, orderBy string, limit int) (string, []string, []func() any) {
	names := make([]string, 0, len(schema.Columns))
	exprs := make([]string, 0, len(schema.Columns))
	dests := make([]func() any, 0, len(schema.Columns))
	for _, c := range schema.Columns {
		e, d := selectExpr(c)
		names = append(names, c.Name)
		if e != quoteIdent(c.Name) {
			e += " AS " + quoteIdent(c.Name)
		}
		exprs = append(exprs, e)
		dests = append(dests, d)
	}
	sql := fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT %d",
		strings.Join(exprs, ", "), q.table(q.store.Raw()), where, orderBy, limit)
	return sql, names, dests
}

func (q *Querier) scanFlows(ctx context.Context, sql string, dests []func() any) ([][]any, error) {
	rows, err := q.conn.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := [][]any{}
	for rows.Next() {
		ptrs := make([]any, len(dests))
		for i, d := range dests {
			ptrs[i] = d()
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]any, len(ptrs))
		for i, p := range ptrs {
			row[i] = deref(p)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// searchSQL validates the request and builds its query.
func (q *Querier) searchSQL(req FlowsSearchRequest) (string, []string, []func() any, error) {
	if req.Limit == 0 {
		req.Limit = DefaultSearchLimit
	}
	if req.Limit < 1 || req.Limit > MaxSearchLimit {
		return "", nil, nil, invalid("limit", "must be between 1 and %d", MaxSearchLimit)
	}
	if req.Start.IsZero() || req.End.IsZero() || !req.End.After(req.Start) {
		return "", nil, nil, invalid("end", "start and end are required, end after start")
	}
	order := "TimeReceived DESC"
	switch req.Order {
	case "", "time":
	case "bytes":
		order = "Bytes DESC, TimeReceived DESC"
	default:
		return "", nil, nil, invalid("order", "must be \"time\" or \"bytes\"")
	}
	fr, err := filter.Compile(req.Filter)
	if err != nil {
		return "", nil, nil, err
	}
	where := fmt.Sprintf("TimeReceived >= toDateTime(%d) AND TimeReceived < toDateTime(%d) AND (%s)",
		req.Start.Unix(), req.End.Unix(), fr.SQL)
	sql, names, dests := q.rawFlowsQuery(where, order, req.Limit)
	return sql, names, dests, nil
}

// SearchFlows answers POST /api/flows/search from the raw table.
func (q *Querier) SearchFlows(ctx context.Context, req FlowsSearchRequest) (*FlowsSearchResponse, error) {
	sql, names, dests, err := q.searchSQL(req)
	if err != nil {
		return nil, err
	}
	rows, err := q.scanFlows(ctx, sql, dests)
	if err != nil {
		return nil, fmt.Errorf("flows search: %w", err)
	}
	return &FlowsSearchResponse{Columns: names, Rows: rows}, nil
}

// LastFlow answers GET /api/widgets/last-flow: the most recent flow as
// {Column: value}, or nil when there is none in the last 24 hours.
func (q *Querier) LastFlow(ctx context.Context) (map[string]any, error) {
	since := q.now().Add(-24 * time.Hour).Unix()
	sql, names, dests := q.rawFlowsQuery(fmt.Sprintf("TimeReceived >= toDateTime(%d)", since), "TimeReceived DESC", 1)
	rows, err := q.scanFlows(ctx, sql, dests)
	if err != nil {
		return nil, fmt.Errorf("last flow: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(names))
	for i, n := range names {
		out[n] = rows[0][i]
	}
	return out, nil
}
