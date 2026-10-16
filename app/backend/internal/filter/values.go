package filter

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/schema"
)

// Operators in their canonical spelling.
const (
	opEq      = "="
	opNe      = "!="
	opLt      = "<"
	opLe      = "<="
	opGt      = ">"
	opGe      = ">="
	opIn      = "IN"
	opNotIn   = "NOTIN"
	opLike    = "LIKE"
	opUnlike  = "UNLIKE"
	opILike   = "ILIKE"
	opIUnlike = "IUNLIKE"
	opInNet   = "<<"
)

// operatorsByKind lists the operators allowed for each column kind, in the
// order they are offered for completion.
var operatorsByKind = map[schema.Kind][]string{
	schema.KindString: {opEq, opNe, opIn, opNotIn, opLike, opUnlike, opILike, opIUnlike},
	schema.KindIP:     {opEq, opNe, opInNet, opIn, opNotIn},
	schema.KindPrefix: {opEq, opNe, opIn, opNotIn},
	schema.KindUint:   {opEq, opNe, opLt, opLe, opGt, opGe, opIn, opNotIn},
	schema.KindTime:   {opEq, opNe, opLt, opLe, opGt, opGe},
	// arrays: = / != contain / do not contain the element, IN / NOTIN any / none
	schema.KindUintArray:   {opEq, opNe, opIn, opNotIn},
	schema.KindStringArray: {opEq, opNe, opIn, opNotIn},
}

var operatorDetail = map[string]string{
	opEq:      "equals",
	opNe:      "differs from",
	opLt:      "less than",
	opLe:      "less than or equal",
	opGt:      "greater than",
	opGe:      "greater than or equal",
	opIn:      "one of (a, b, …)",
	opNotIn:   "none of (a, b, …)",
	opLike:    "matches pattern (% and _ wildcards)",
	opUnlike:  "does not match pattern",
	opILike:   "matches pattern, case-insensitive",
	opIUnlike: "does not match pattern, case-insensitive",
	opInNet:   "in prefix (SrcAddr << 10.0.0.0/8)",
}

func opAllowed(k schema.Kind, op string) bool {
	for _, o := range operatorsByKind[k] {
		if o == op {
			return true
		}
	}
	return false
}

// keywords that cannot be used as bare values.
var keywords = map[string]bool{
	"AND": true, "OR": true, "NOT": true, "IN": true, "NOTIN": true,
	"LIKE": true, "UNLIKE": true, "ILIKE": true, "IUNLIKE": true,
}

// protocols maps IP protocol names to numbers (Proto column).
var protocols = map[string]uint64{
	"icmp": 1, "igmp": 2, "ipip": 4, "tcp": 6, "egp": 8, "udp": 17, "ipv6": 41,
	"rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58,
	"eigrp": 88, "ospf": 89, "pim": 103, "vrrp": 112, "l2tp": 115, "sctp": 132,
}

// etypes maps EtherType names to numbers (EType column).
var etypes = map[string]uint64{
	"ipv4": 0x0800, "arp": 0x0806, "ipv6": 0x86dd, "mpls": 0x8847,
}

// boundaries are the values of the *IfBoundary columns, offered as static
// completions.
var boundaries = []string{"external", "internal"}

// value is a validated literal.
type value struct {
	kind schema.Kind
	str  string // KindString
	u    uint64 // KindUint
	ip   netip.Addr
	pfx  netip.Prefix // KindPrefix, or KindIP with <<
	t    time.Time    // KindTime, UTC
}

// uintBits returns the width of a ClickHouse UIntN type, ignoring
// LowCardinality/Nullable wrappers. 64 when unknown.
func uintBits(chType string) int {
	t := chType
	for _, w := range []string{"LowCardinality(", "Nullable("} {
		if strings.HasPrefix(t, w) && strings.HasSuffix(t, ")") {
			t = t[len(w) : len(t)-1]
		}
	}
	switch t {
	case "UInt8":
		return 8
	case "UInt16":
		return 16
	case "UInt32":
		return 32
	default:
		return 64
	}
}

func isASColumn(c schema.Column) bool {
	return c.Kind == schema.KindUint && strings.HasSuffix(c.Name, "AS")
}

// parseUint parses decimal or 0x-prefixed hexadecimal numbers (no octal: a
// leading zero is decimal).
func parseUint(s string, bits int) (uint64, error) {
	base := 10
	digits := s
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		base, digits = 16, s[2:]
	}
	if digits == "" || strings.ContainsAny(digits, "_+-") {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseUint(digits, base, bits)
}

// parseValue validates the literal tok for column c used with operator op.
func parseValue(c schema.Column, op string, tok token) (value, string) {
	switch c.Kind {
	case schema.KindUintArray:
		return parseArrayElement(c, tok)
	case schema.KindStringArray:
		return value{kind: schema.KindString, str: tok.val}, ""
	}
	v := value{kind: c.Kind}
	text := tok.val
	quoted := tok.kind == tString
	switch c.Kind {
	case schema.KindString:
		v.str = text
		return v, ""

	case schema.KindUint:
		if quoted {
			return v, fmt.Sprintf("%s expects a number, not a string", c.Name)
		}
		bits := uintBits(c.Type)
		if isASColumn(c) && len(text) > 2 && strings.EqualFold(text[:2], "AS") {
			text = text[2:]
		}
		if n, ok := protocols[strings.ToLower(text)]; ok && c.Name == "Proto" {
			v.u = n
			return v, ""
		}
		if n, ok := etypes[strings.ToLower(text)]; ok && c.Name == "EType" {
			v.u = n
			return v, ""
		}
		n, err := parseUint(text, bits)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return v, fmt.Sprintf("%s is out of range for %s (%s, max %d)",
					tok.val, c.Name, c.Type, ^uint64(0)>>(64-bits))
			}
			hint := ""
			switch {
			case c.Name == "Proto":
				hint = " or a protocol name (tcp, udp, icmp, …)"
			case c.Name == "EType":
				hint = " or ipv4/ipv6"
			case isASColumn(c):
				hint = " or AS<number>"
			}
			return v, fmt.Sprintf("%s expects a number%s, got %s", c.Name, hint, tok.describe())
		}
		v.u = n
		return v, ""

	case schema.KindIP:
		if op == opInNet {
			p, err := netip.ParsePrefix(text)
			if err != nil {
				return v, fmt.Sprintf("%s << expects a prefix like 10.0.0.0/8 or 2001:db8::/32, got %s", c.Name, tok.describe())
			}
			v.pfx = p.Masked()
			return v, ""
		}
		a, err := netip.ParseAddr(text)
		if err != nil || a.Zone() != "" {
			if _, perr := netip.ParsePrefix(text); perr == nil {
				return v, fmt.Sprintf("%s expects an address; use %s << %s to match a prefix", c.Name, c.Name, text)
			}
			return v, fmt.Sprintf("%s expects an IP address, got %s", c.Name, tok.describe())
		}
		v.ip = a
		return v, ""

	case schema.KindPrefix:
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return v, fmt.Sprintf("%s expects a prefix like 10.0.0.0/8, got %s", c.Name, tok.describe())
		}
		v.pfx = p.Masked()
		return v, ""

	case schema.KindTime:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
			if t, err := time.Parse(layout, text); err == nil {
				t = t.UTC()
				if t.Year() < 1970 || t.Year() > 2105 {
					return v, fmt.Sprintf("%s is out of range for %s", tok.describe(), c.Name)
				}
				v.t = t.Truncate(time.Second)
				return v, ""
			}
		}
		return v, fmt.Sprintf("%s expects a time like '2024-01-31 12:00:00' (UTC) or RFC 3339, got %s", c.Name, tok.describe())
	}
	return v, fmt.Sprintf("column %s cannot be filtered", c.Name)
}

// parseArrayElement parses an element of an Array(UInt32) column: a number,
// AS<number> for AS paths, or <as>:<value> for standard communities.
func parseArrayElement(c schema.Column, tok token) (value, string) {
	v := value{kind: schema.KindUint}
	if tok.kind == tString {
		return v, fmt.Sprintf("%s expects a number, not a string", c.Name)
	}
	text := tok.val
	if strings.Contains(c.Name, "Communities") {
		if hi, lo, ok := strings.Cut(text, ":"); ok {
			h, err1 := parseUint(hi, 16)
			l, err2 := parseUint(lo, 16)
			if err1 != nil || err2 != nil {
				return v, fmt.Sprintf("%s expects a community like 65000:100, got %s", c.Name, tok.describe())
			}
			v.u = h<<16 | l
			return v, ""
		}
	} else if len(text) > 2 && strings.EqualFold(text[:2], "AS") {
		text = text[2:]
	}
	n, err := parseUint(text, 32)
	if err != nil {
		return v, fmt.Sprintf("%s expects a 32-bit number, got %s", c.Name, tok.describe())
	}
	v.u = n
	return v, ""
}
