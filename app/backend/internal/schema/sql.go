package schema

import "fmt"

// IPText is the ClickHouse expression of an IPv6 value (a column or an
// expression) as text, with IPv4-mapped addresses unmapped: "10.0.0.1",
// "2001:db8::1".
//
// It avoids replaceRegexpOne with a pattern anchored at both ends:
// ClickHouse 25.8 returns "" for the rows of a column that do not match one.
func IPText(expr string) string {
	s := "toString(" + expr + ")"
	return fmt.Sprintf("if(startsWith(%[1]s, '::ffff:'), substring(%[1]s, 8), %[1]s)", s)
}
