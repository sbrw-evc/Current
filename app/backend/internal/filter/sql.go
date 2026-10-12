package filter

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// quoteSQL returns s as a ClickHouse single-quoted string literal. Quotes and
// backslashes are escaped, control bytes are written as \xHH, so the literal
// can never terminate early whatever s contains.
func quoteSQL(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// quoteNormalized returns s as a filter-language string literal.
func quoteNormalized(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// as16 returns a in IPv6 form (IPv4 as IPv4-mapped ::ffff:a.b.c.d), the way
// addresses are stored in the IPv6 columns.
func as16(a netip.Addr) netip.Addr { return netip.AddrFrom16(a.As16()) }

// prefixRange returns the first and last addresses of p in IPv6 form.
func prefixRange(p netip.Prefix) (lo, hi netip.Addr) {
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	b := as16(p.Masked().Addr()).As16()
	lo = netip.AddrFrom16(b)
	for i := bits; i < 128; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return lo, netip.AddrFrom16(b)
}

func ipSQL(a netip.Addr) string { return "toIPv6(" + quoteSQL(as16(a).String()) + ")" }

func valueSQL(v value) string {
	switch v.kind {
	case schema.KindUint:
		return strconv.FormatUint(v.u, 10)
	case schema.KindIP:
		return ipSQL(v.ip)
	case schema.KindPrefix:
		return quoteSQL(v.pfx.String())
	case schema.KindTime:
		return "toDateTime(" + quoteSQL(v.t.Format("2006-01-02 15:04:05")) + ", 'UTC')"
	default:
		return quoteSQL(v.str)
	}
}

func valueNormalized(v value) string {
	switch v.kind {
	case schema.KindUint:
		return strconv.FormatUint(v.u, 10)
	case schema.KindIP:
		if v.pfx.IsValid() {
			return v.pfx.String()
		}
		return v.ip.Unmap().String()
	case schema.KindPrefix:
		return v.pfx.String()
	case schema.KindTime:
		return quoteNormalized(v.t.Format("2006-01-02 15:04:05"))
	default:
		return quoteNormalized(v.str)
	}
}

// renderSQL writes n as a ClickHouse expression. With reverse, columns are
// replaced by their Reverse counterpart.
func renderSQL(b *strings.Builder, n node, reverse bool) {
	switch n := n.(type) {
	case *binaryNode:
		b.WriteByte('(')
		renderChain(b, n, n.op, reverse)
		b.WriteByte(')')
	case *notNode:
		b.WriteString("NOT ")
		if _, ok := n.x.(*binaryNode); ok {
			renderSQL(b, n.x, reverse)
		} else {
			b.WriteByte('(')
			renderSQL(b, n.x, reverse)
			b.WriteByte(')')
		}
	case *cmpNode:
		renderCmpSQL(b, n, reverse)
	}
}

// renderChain flattens a chain of the same operator: (a AND b AND c).
func renderChain(b *strings.Builder, n node, op string, reverse bool) {
	if bn, ok := n.(*binaryNode); ok && bn.op == op {
		renderChain(b, bn.l, op, reverse)
		b.WriteString(" " + op + " ")
		renderChain(b, bn.r, op, reverse)
		return
	}
	renderSQL(b, n, reverse)
}

func renderCmpSQL(b *strings.Builder, n *cmpNode, reverse bool) {
	col := n.col.Name
	if reverse && n.col.Reverse != "" {
		col = n.col.Reverse
	}
	if n.col.Kind == schema.KindUintArray || n.col.Kind == schema.KindStringArray {
		renderArraySQL(b, col, n)
		return
	}
	switch n.op {
	case opIn, opNotIn:
		b.WriteString(col)
		if n.op == opIn {
			b.WriteString(" IN (")
		} else {
			b.WriteString(" NOT IN (")
		}
		for i, v := range n.vals {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(valueSQL(v))
		}
		b.WriteByte(')')
	case opLike, opUnlike, opILike, opIUnlike:
		fn := map[string]string{opLike: "like", opUnlike: "notLike", opILike: "ilike", opIUnlike: "notILike"}[n.op]
		b.WriteString(fn + "(" + col + ", " + valueSQL(n.vals[0]) + ")")
	case opInNet:
		// Explicit bounds keep the primary key / skip indexes usable, unlike
		// isIPAddressInRange(IPv6NumToString(col), …). IPv6 values compare
		// as big-endian 128-bit numbers, so a prefix is a contiguous range.
		lo, hi := prefixRange(n.vals[0].pfx)
		b.WriteString("(" + col + " BETWEEN " + ipSQL(lo) + " AND " + ipSQL(hi) + ")")
	default:
		b.WriteString(col + " " + n.op + " " + valueSQL(n.vals[0]))
	}
}

// precedence for minimal parentheses in the normalized form.
func precedence(n node) int {
	switch n := n.(type) {
	case *binaryNode:
		if n.op == "OR" {
			return 1
		}
		return 2
	case *notNode:
		return 3
	}
	return 4
}

func renderNormalized(b *strings.Builder, n node) {
	child := func(c node, min int) {
		if precedence(c) < min {
			b.WriteByte('(')
			renderNormalized(b, c)
			b.WriteByte(')')
		} else {
			renderNormalized(b, c)
		}
	}
	switch n := n.(type) {
	case *binaryNode:
		p := precedence(n)
		child(n.l, p)
		b.WriteString(" " + n.op + " ")
		child(n.r, p)
	case *notNode:
		b.WriteString("NOT ")
		child(n.x, 3)
	case *cmpNode:
		b.WriteString(n.col.Name + " " + n.op + " ")
		if n.op == opIn || n.op == opNotIn {
			b.WriteByte('(')
			for i, v := range n.vals {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(valueNormalized(v))
			}
			b.WriteByte(')')
		} else {
			b.WriteString(valueNormalized(n.vals[0]))
		}
	}
}

// renderArraySQL matches elements of an array column with has / hasAny.
func renderArraySQL(b *strings.Builder, col string, n *cmpNode) {
	if n.op == opNe || n.op == opNotIn {
		b.WriteString("NOT ")
	}
	if n.op == opIn || n.op == opNotIn {
		b.WriteString("hasAny(" + col + ", [")
		for i, v := range n.vals {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(valueSQL(v))
		}
		b.WriteString("])")
		return
	}
	b.WriteString("has(" + col + ", " + valueSQL(n.vals[0]) + ")")
}
