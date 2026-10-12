package filter

import (
	"sort"
	"strconv"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Completion is one suggestion for /api/filter/complete.
type Completion struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
	// Quoted: the label is a string value that must be inserted in quotes.
	Quoted bool `json:"quoted"`
}

// filterable reports whether a column can appear in a filter.
func filterable(c schema.Column) bool {
	_, ok := operatorsByKind[c.Kind]
	return ok
}

// CompleteColumns returns the columns whose name starts with prefix
// (case-insensitive), in schema order.
func CompleteColumns(prefix string) []Completion {
	out := []Completion{}
	lp := strings.ToLower(prefix)
	for _, c := range schema.Columns {
		if filterable(c) && strings.HasPrefix(strings.ToLower(c.Name), lp) {
			out = append(out, Completion{Label: c.Name, Detail: string(c.Kind) + " · " + c.Type})
		}
	}
	return out
}

// CompleteOperators returns the operators valid for column (matched
// case-insensitively); nil for an unknown column.
func CompleteOperators(column string) []Completion {
	c, ok := lookupColumn(column)
	if !ok || !filterable(c) {
		return nil
	}
	ops := operatorsByKind[c.Kind]
	out := make([]Completion, 0, len(ops))
	for _, op := range ops {
		out = append(out, Completion{Label: op, Detail: operatorDetail[op]})
	}
	return out
}

// ValueColumnKind returns the canonical column's kind for value completion
// (done by the query layer from ClickHouse). ok is false for unknown columns.
func ValueColumnKind(column string) (schema.Kind, bool) {
	c, ok := lookupColumn(column)
	if !ok || !filterable(c) {
		return "", false
	}
	return c.Kind, true
}

// CanonicalColumn returns the canonical spelling of a column name.
func CanonicalColumn(column string) (string, bool) {
	c, ok := lookupColumn(column)
	return c.Name, ok
}

// StaticValues returns the built-in symbolic values for a column that start
// with prefix (case-insensitive): protocol names for Proto, ipv4/ipv6 for
// EType, internal/external for *IfBoundary. The query layer can merge them
// with values read from ClickHouse.
func StaticValues(column, prefix string) []Completion {
	c, ok := lookupColumn(column)
	if !ok {
		return nil
	}
	lp := strings.ToLower(prefix)
	var out []Completion
	addMap := func(m map[string]uint64, hex bool) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if strings.HasPrefix(k, lp) {
				d := strconv.FormatUint(m[k], 10)
				if hex {
					d = "0x" + strconv.FormatUint(m[k], 16)
				}
				out = append(out, Completion{Label: k, Detail: d})
			}
		}
	}
	switch {
	case c.Name == "Proto":
		addMap(protocols, false)
	case c.Name == "EType":
		addMap(etypes, true)
	case strings.HasSuffix(c.Name, "IfBoundary"):
		for _, v := range boundaries {
			if strings.HasPrefix(v, lp) {
				out = append(out, Completion{Label: v, Detail: "interface boundary", Quoted: true})
			}
		}
	}
	return out
}
