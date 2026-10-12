// Package filter implements the console filter language (see docs/api.md) and
// compiles it to a ClickHouse boolean expression.
//
// The parser is a hand-written recursive descent parser (grammar in
// parser.go). Literals are validated against the column kind from
// internal/schema and inlined in the SQL with escaping (quoteSQL), so the
// output never carries user text outside a string literal: column names come
// from the schema registry and operators from a fixed set.
package filter

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// Result of compiling a filter.
type Result struct {
	// SQL is a ClickHouse boolean expression with literals inlined and
	// escaped, usable in a WHERE clause. "1" for an empty filter.
	SQL string
	// ReverseSQL is the same filter with direction swapped (Src<->Dst,
	// In<->Out, using schema.Column.Reverse), for the bidirectional mode.
	ReverseSQL string
	// Columns referenced by the filter (to choose the resolution table),
	// canonical names, deduplicated, in order of first appearance.
	Columns []string
	// Normalized is the filter re-printed in canonical form: canonical column
	// names, upper-case keywords, single-quoted strings, numeric values
	// (AS65000 → 65000, tcp → 6), minimal parentheses, no comments. It
	// compiles to the same SQL.
	Normalized string
}

// ErrNotImplemented was returned by the stub; kept for compatibility.
var ErrNotImplemented = errors.New("filter: not implemented")

// Compile parses text and returns its SQL form. An empty or blank text gives
// SQL "1". Parse errors are returned as *Error (the first one; use Validate
// to get all of them).
func Compile(text string) (Result, error) {
	r, errs := Validate(text)
	if len(errs) > 0 {
		return Result{}, errs[0]
	}
	return r, nil
}

// Validate parses text and returns its SQL form, or every error found
// (sorted by position). Lexical errors are all reported; after a syntax
// error parsing stops, but the semantic errors found before it (unknown
// column, operator not valid for the column, bad value) are kept.
func Validate(text string) (Result, []*Error) {
	toks, lexErrs := lex(text)
	if len(lexErrs) > 0 {
		return Result{}, toErrors(text, lexErrs)
	}
	p := &parser{toks: toks}
	n, errs := p.parse()
	if len(errs) > 0 {
		return Result{}, toErrors(text, errs)
	}
	if n == nil {
		return Result{SQL: "1", ReverseSQL: "1", Columns: []string{}}, nil
	}
	var sql, rev, norm strings.Builder
	renderSQL(&sql, n, false)
	renderSQL(&rev, n, true)
	renderNormalized(&norm, n)
	return Result{SQL: sql.String(), ReverseSQL: rev.String(), Columns: p.cols, Normalized: norm.String()}, nil
}

// Error is a parse or validation error with its position in the input.
// Line and Column are 1-based, Column counts Unicode code points; Offset is
// the 0-based byte offset in the input.
type Error struct {
	Line, Column, Offset int
	Message              string
}

func (e *Error) Error() string { return e.Message }

func toErrors(text string, pes []posError) []*Error {
	sort.SliceStable(pes, func(i, j int) bool { return pes[i].off < pes[j].off })
	out := make([]*Error, 0, len(pes))
	for _, pe := range pes {
		line, col := position(text, pe.off)
		out = append(out, &Error{Line: line, Column: col, Offset: pe.off, Message: pe.msg})
	}
	return out
}

// position converts a byte offset to a 1-based line and column (in runes).
func position(text string, off int) (line, col int) {
	if off > len(text) {
		off = len(text)
	}
	before := text[:off]
	line = strings.Count(before, "\n") + 1
	if i := strings.LastIndexByte(before, '\n'); i >= 0 {
		before = before[i+1:]
	}
	return line, utf8.RuneCountInString(before) + 1
}
