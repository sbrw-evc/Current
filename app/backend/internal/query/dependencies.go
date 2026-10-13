package query

import (
	"context"
	"fmt"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Dependency discovery (docs/integrations.md §3.3): steady CI ↔ CI traffic
// over the last days, both ends resolved to Inventory DB source_refs
// (SrcCI / DstCI), with the server side detected by the port.
//
// The raw table is read because the aggregates have no ports. The server of a
// flow is the side with the lower port (well-known and registered ports are
// lower than ephemeral ones); on equal ports the destination.

// DependencyParams are the discovery thresholds.
type DependencyParams struct {
	// Days is the period (default 7).
	Days int `json:"days"`
	// MinFlows is the minimum number of flow records over the period (default 100).
	MinFlows int `json:"min_flows"`
	// MinDays is the minimum number of distinct days with traffic (default 3).
	MinDays int `json:"min_days"`
	// Limit bounds the pairs returned, largest first (default 500).
	Limit int `json:"limit"`
}

// WithDefaults fills zero fields.
func (p DependencyParams) WithDefaults() DependencyParams {
	if p.Days <= 0 {
		p.Days = 7
	}
	if p.MinFlows <= 0 {
		p.MinFlows = 100
	}
	if p.MinDays <= 0 {
		p.MinDays = 3
	}
	if p.MinDays > p.Days {
		p.MinDays = p.Days
	}
	if p.Limit <= 0 {
		p.Limit = 500
	}
	return p
}

// DependencyPair is a client CI talking to a server CI on one port.
type DependencyPair struct {
	ClientRef  string    `json:"client_ref"`
	ClientName string    `json:"client_name"`
	ClientIP   string    `json:"client_ip"`
	ServerRef  string    `json:"server_ref"`
	ServerName string    `json:"server_name"`
	ServerIP   string    `json:"server_ip"`
	Proto      uint8     `json:"proto"`
	Port       uint16    `json:"port"`
	App        string    `json:"app"`
	Bytes      uint64    `json:"bytes"`
	Flows      uint64    `json:"flows"`
	DaysSeen   uint64    `json:"days_seen"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// dependencySQL is the discovery query over [start, end).
func dependencySQL(table string, start, end int64, p DependencyParams) string {
	return fmt.Sprintf(`SELECT
    if(srv_dst, SrcCI, DstCI) AS client_ref,
    toString(argMax(if(srv_dst, SrcHost, DstHost), Bytes)) AS client_name,
    %[1]s AS client_ip,
    if(srv_dst, DstCI, SrcCI) AS server_ref,
    toString(argMax(if(srv_dst, DstHost, SrcHost), Bytes)) AS server_name,
    %[2]s AS server_ip,
    Proto,
    if(srv_dst, DstPort, SrcPort) AS port,
    toString(argMax(App, Bytes)) AS app,
    sum(Bytes) AS bytes,
    count() AS flows,
    uniqExact(toDate(TimeReceived)) AS days_seen,
    min(TimeReceived) AS first_seen,
    max(TimeReceived) AS last_seen
FROM (
    SELECT TimeReceived, SrcCI, DstCI, SrcHost, DstHost, SrcAddr, DstAddr, Proto, SrcPort, DstPort, App, Bytes,
        DstPort <= SrcPort AS srv_dst
    FROM %[3]s
    WHERE TimeReceived >= toDateTime(%[4]d) AND TimeReceived < toDateTime(%[5]d)
      AND SrcCI != '' AND DstCI != '' AND SrcCI != DstCI
      AND Proto IN (6, 17, 132) AND SrcPort != 0 AND DstPort != 0
)
GROUP BY client_ref, server_ref, Proto, port
HAVING flows >= %[6]d AND days_seen >= %[7]d
ORDER BY bytes DESC
LIMIT %[8]d`,
		schema.IPText("argMax(if(srv_dst, SrcAddr, DstAddr), Bytes)"),
		schema.IPText("argMax(if(srv_dst, DstAddr, SrcAddr), Bytes)"),
		table, start, end, p.MinFlows, p.MinDays, p.Limit)
}

// DependencyPairs returns the steady CI ↔ CI pairs of the last p.Days days.
func (q *Querier) DependencyPairs(ctx context.Context, p DependencyParams) ([]DependencyPair, error) {
	p = p.WithDefaults()
	end := q.now().UTC()
	start := end.Add(-time.Duration(p.Days) * 24 * time.Hour)
	rows, err := q.conn.Query(ctx, dependencySQL(q.table(q.store.Raw()), start.Unix(), end.Unix(), p))
	if err != nil {
		return nil, fmt.Errorf("dependencies: %w", err)
	}
	defer rows.Close()
	out := []DependencyPair{}
	for rows.Next() {
		var d DependencyPair
		if err := rows.Scan(&d.ClientRef, &d.ClientName, &d.ClientIP, &d.ServerRef, &d.ServerName, &d.ServerIP,
			&d.Proto, &d.Port, &d.App, &d.Bytes, &d.Flows, &d.DaysSeen, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, fmt.Errorf("dependencies: scan: %w", err)
		}
		d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dependencies: %w", err)
	}
	return out, nil
}
