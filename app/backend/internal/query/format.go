package query

import (
	"strconv"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Labels of the synthetic rows.
const (
	LabelOther   = "Other"
	LabelTotal   = "Total"
	LabelUnknown = "Unknown"
)

var protoNames = map[string]string{
	"1": "icmp", "2": "igmp", "4": "ipip", "6": "tcp", "17": "udp", "41": "ipv6",
	"47": "gre", "50": "esp", "51": "ah", "58": "ipv6-icmp", "88": "eigrp",
	"89": "ospf", "103": "pim", "112": "vrrp", "115": "l2tp", "132": "sctp",
}

var etypeNames = map[string]string{"2048": "IPv4", "34525": "IPv6", "2054": "ARP", "33024": "802.1Q", "34887": "MPLS"}

// ASNamer returns the name of an AS ("" when unknown). Hook for the AS
// database of the enricher.
type ASNamer func(asn uint32) string

// formatValue turns the text form of a dimension value (as produced by
// dimExpr) into its display label.
func (q *Querier) formatValue(column, v string) string {
	if v == "" {
		return LabelUnknown
	}
	col, _ := schema.ByName(column)
	switch {
	case column == "SrcAS" || column == "DstAS":
		label := "AS" + v
		if q != nil && q.asName != nil {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				if name := q.asName(uint32(n)); name != "" {
					label += " " + name
				}
			}
		}
		return label
	case column == "Proto":
		if n, ok := protoNames[v]; ok {
			return n
		}
	case column == "EType":
		if n, ok := etypeNames[v]; ok {
			return n
		}
	case col.Kind == schema.KindIP:
		if v == "::" {
			return LabelUnknown
		}
	}
	return v
}

// quoteString returns s as a ClickHouse string literal.
func quoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '\'':
			b.WriteByte('\\')
			b.WriteByte(c)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// quoteIdent quotes a column name. Column names always come from the
// registry; quoting is defensive.
func quoteIdent(s string) string {
	return "`" + strings.NewReplacer("\\", "\\\\", "`", "\\`").Replace(s) + "`"
}
