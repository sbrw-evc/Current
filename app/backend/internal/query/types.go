// Package query answers the console's read API (docs/api.md): visualize
// (time series and sankey), home widgets, raw flow search and exporter
// aggregates, over the ClickHouse tables of internal/storage/clickhouse.
package query

import (
	"fmt"
	"time"
)

// Units of the visualize values.
const (
	UnitsL3bps    = "l3bps"
	UnitsL2bps    = "l2bps"
	UnitsPps      = "pps"
	UnitsInL2Pct  = "inl2%"
	UnitsOutL2Pct = "outl2%"
)

// Graph kinds.
const (
	GraphStacked = "stacked"
	GraphLines   = "lines"
	GraphGrid    = "grid"
	GraphSankey  = "sankey"
)

// VisualizeRequest is the body of POST /api/visualize.
type VisualizeRequest struct {
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Points        int       `json:"points"`
	Dimensions    []string  `json:"dimensions"`
	Limit         int       `json:"limit"`
	Filter        string    `json:"filter"`
	Units         string    `json:"units"`
	Bidirectional bool      `json:"bidirectional"`
	Graph         string    `json:"graph"`
}

// TimeSeriesResponse answers a visualize request with a time graph.
type TimeSeriesResponse struct {
	T          []time.Time `json:"t"`
	Rows       [][]string  `json:"rows"`
	Points     [][]float64 `json:"points"`
	Axis       []int       `json:"axis"`
	Average    []float64   `json:"average"`
	Min        []float64   `json:"min"`
	Max        []float64   `json:"max"`
	P95        []float64   `json:"p95"`
	Resolution string      `json:"resolution"`
	SQL        string      `json:"sql"`
}

// SankeyResponse answers a visualize request with graph "sankey".
// Resolution and SQL are extra (not in docs/api.md) for debugging.
type SankeyResponse struct {
	Rows       [][]string   `json:"rows"`
	Xps        []float64    `json:"xps"`
	Nodes      []string     `json:"nodes"`
	Links      []SankeyLink `json:"links"`
	Resolution string       `json:"resolution,omitempty"`
	SQL        string       `json:"sql,omitempty"`
}

// SankeyLink is a link between two nodes of consecutive dimensions.
type SankeyLink struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Xps    float64 `json:"xps"`
}

// SummaryWidget is GET /api/widgets/summary.
type SummaryWidget struct {
	FlowsPerSecond float64 `json:"flows_per_second"`
	Exporters      uint64  `json:"exporters"`
	BpsInExternal  float64 `json:"bps_in_external"`
	BpsOutExternal float64 `json:"bps_out_external"`
}

// TopWidget is GET /api/widgets/top/{what}.
type TopWidget struct {
	Top []TopItem `json:"top"`
}

// TopItem is one entry of TopWidget.
type TopItem struct {
	Name    string  `json:"name"`
	Percent float64 `json:"percent"`
}

// GraphWidget is GET /api/widgets/graph.
type GraphWidget struct {
	T    []time.Time `json:"t"`
	Gbps []float64   `json:"gbps"`
}

// FlowsSearchRequest is the body of POST /api/flows/search.
type FlowsSearchRequest struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Filter string    `json:"filter"`
	Limit  int       `json:"limit"`
	Order  string    `json:"order"` // "time" (default) or "bytes"
}

// FlowsSearchResponse answers POST /api/flows/search. Rows hold JSON-ready
// values in the order of Columns (IPs as text, times as RFC 3339).
type FlowsSearchResponse struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// ExportersResponse is GET /api/exporters.
type ExportersResponse struct {
	Results []Exporter `json:"results"`
}

// Exporter aggregates the recent flows of one exporter.
type Exporter struct {
	Address        string              `json:"address"`
	Name           string              `json:"name"`
	Ref            string              `json:"ref"`
	Site           string              `json:"site"`
	Role           string              `json:"role"`
	LastSeen       time.Time           `json:"last_seen"`
	FlowsPerSecond float64             `json:"flows_per_second"`
	SamplingRates  []uint64            `json:"sampling_rates"`
	Interfaces     []ExporterInterface `json:"interfaces"`
}

// ExporterInterface is the recent traffic of one interface of an exporter.
type ExporterInterface struct {
	Index       uint32  `json:"index"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Speed       uint64  `json:"speed"`
	Boundary    string  `json:"boundary"`
	Provider    string  `json:"provider"`
	InBps       float64 `json:"in_bps"`
	OutBps      float64 `json:"out_bps"`
}

// ValidationError is a bad request (HTTP 400). Filter syntax errors are
// returned as *filter.Error instead.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Message) }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}
