// Package schema is the single registry of flow columns. The ClickHouse DDL,
// the writer, the filter language, the visualize query builder and the web
// console (via GET /api/schema) are all derived from it.
package schema

// Kind tells the filter language which operators and literals a column takes.
type Kind string

const (
	KindString Kind = "string" // =, !=, IN, LIKE, ILIKE, UNLIKE
	KindIP     Kind = "ip"     // =, !=, IN, << (in prefix); stored as IPv6 (IPv4-mapped)
	KindPrefix Kind = "prefix" // =, !=, IN
	KindUint   Kind = "uint"   // =, !=, <, <=, >, >=, IN
	KindTime   Kind = "time"
)

// Column describes one column of the flows table.
type Column struct {
	Name string // column name in ClickHouse, in the filter language and in the API
	Type string // ClickHouse type
	Kind Kind
	// Dimension: can be used to group by in the console.
	Dimension bool
	// Rollup: kept in the flows_1m / flows_5m / flows_1h aggregates. Columns
	// without Rollup are only in the raw table (high cardinality: addresses, ports).
	Rollup bool
	// Reverse: the column with the opposite direction (SrcAS <-> DstAS), used
	// by the bidirectional mode. Empty for direction-less columns.
	Reverse string
	// Metric: summed value, not a dimension (Bytes, Packets).
	Metric bool
}

// Columns in table order. Keep the order stable: new columns go to the end of
// their group, and the ClickHouse migrations add them with ALTER TABLE.
var Columns = []Column{
	{Name: "TimeReceived", Type: "DateTime", Kind: KindTime},
	{Name: "SamplingRate", Type: "UInt64", Kind: KindUint},
	{Name: "FlowType", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},

	{Name: "ExporterAddress", Type: "IPv6", Kind: KindIP, Dimension: true, Rollup: true},
	{Name: "ExporterName", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterRef", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterSite", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterRegion", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterRole", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterGroup", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},
	{Name: "ExporterTenant", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},

	{Name: "InIfIndex", Type: "UInt32", Kind: KindUint, Rollup: true},
	{Name: "InIfName", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfName"},
	{Name: "InIfDescription", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfDescription"},
	{Name: "InIfSpeed", Type: "UInt64", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "OutIfSpeed"},
	{Name: "InIfBoundary", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfBoundary"},
	{Name: "InIfConnectivity", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfConnectivity"},
	{Name: "InIfProvider", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfProvider"},
	{Name: "InIfCircuit", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "OutIfCircuit"},
	{Name: "OutIfIndex", Type: "UInt32", Kind: KindUint, Rollup: true},
	{Name: "OutIfName", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfName"},
	{Name: "OutIfDescription", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfDescription"},
	{Name: "OutIfSpeed", Type: "UInt64", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "InIfSpeed"},
	{Name: "OutIfBoundary", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfBoundary"},
	{Name: "OutIfConnectivity", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfConnectivity"},
	{Name: "OutIfProvider", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfProvider"},
	{Name: "OutIfCircuit", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "InIfCircuit"},

	{Name: "SrcAddr", Type: "IPv6", Kind: KindIP, Dimension: true, Reverse: "DstAddr"},
	{Name: "DstAddr", Type: "IPv6", Kind: KindIP, Dimension: true, Reverse: "SrcAddr"},
	{Name: "SrcNetMask", Type: "UInt8", Kind: KindUint, Reverse: "DstNetMask"},
	{Name: "DstNetMask", Type: "UInt8", Kind: KindUint, Reverse: "SrcNetMask"},
	{Name: "NextHop", Type: "IPv6", Kind: KindIP, Dimension: true, Rollup: true},
	{Name: "SrcAS", Type: "UInt32", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "DstAS"},
	{Name: "DstAS", Type: "UInt32", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "SrcAS"},
	{Name: "SrcNetPrefix", Type: "LowCardinality(String)", Kind: KindPrefix, Dimension: true, Rollup: true, Reverse: "DstNetPrefix"},
	{Name: "SrcNetName", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstNetName"},
	{Name: "SrcNetRole", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstNetRole"},
	{Name: "SrcNetSite", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstNetSite"},
	{Name: "SrcNetTenant", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstNetTenant"},
	{Name: "SrcNetVRF", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstNetVRF"},
	{Name: "SrcHost", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Reverse: "DstHost"},
	{Name: "SrcCI", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstCI"},
	{Name: "SrcCountry", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "DstCountry"},
	{Name: "SrcCity", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Reverse: "DstCity"},
	{Name: "DstNetPrefix", Type: "LowCardinality(String)", Kind: KindPrefix, Dimension: true, Rollup: true, Reverse: "SrcNetPrefix"},
	{Name: "DstNetName", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcNetName"},
	{Name: "DstNetRole", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcNetRole"},
	{Name: "DstNetSite", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcNetSite"},
	{Name: "DstNetTenant", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcNetTenant"},
	{Name: "DstNetVRF", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcNetVRF"},
	{Name: "DstHost", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Reverse: "SrcHost"},
	{Name: "DstCI", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcCI"},
	{Name: "DstCountry", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true, Reverse: "SrcCountry"},
	{Name: "DstCity", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Reverse: "SrcCity"},

	{Name: "SrcPort", Type: "UInt16", Kind: KindUint, Dimension: true, Reverse: "DstPort"},
	{Name: "DstPort", Type: "UInt16", Kind: KindUint, Dimension: true, Reverse: "SrcPort"},
	{Name: "Proto", Type: "UInt8", Kind: KindUint, Dimension: true, Rollup: true},
	{Name: "EType", Type: "UInt16", Kind: KindUint, Dimension: true, Rollup: true},
	{Name: "TCPFlags", Type: "UInt8", Kind: KindUint},
	{Name: "IPTos", Type: "UInt8", Kind: KindUint, Dimension: true},
	{Name: "ICMPType", Type: "UInt8", Kind: KindUint, Dimension: true},
	{Name: "ICMPCode", Type: "UInt8", Kind: KindUint, Dimension: true},
	{Name: "SrcVlan", Type: "UInt16", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "DstVlan"},
	{Name: "DstVlan", Type: "UInt16", Kind: KindUint, Dimension: true, Rollup: true, Reverse: "SrcVlan"},
	{Name: "ForwardingStatus", Type: "UInt8", Kind: KindUint, Dimension: true, Rollup: true},
	{Name: "App", Type: "LowCardinality(String)", Kind: KindString, Dimension: true, Rollup: true},

	{Name: "Bytes", Type: "UInt64", Kind: KindUint, Metric: true},
	{Name: "Packets", Type: "UInt64", Kind: KindUint, Metric: true},
}

// ByName returns the column with the given name (case-sensitive).
func ByName(name string) (Column, bool) {
	for _, c := range Columns {
		if c.Name == name {
			return c, true
		}
	}
	return Column{}, false
}
