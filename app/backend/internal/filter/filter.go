// Package filter implements the console filter language (see docs/api.md) and
// compiles it to a ClickHouse boolean expression.
package filter

import "errors"

// Result of compiling a filter.
type Result struct {
	// SQL is a ClickHouse boolean expression with literals inlined and
	// escaped, usable in a WHERE clause. "1" for an empty filter.
	SQL string
	// ReverseSQL is the same filter with direction swapped (Src<->Dst,
	// In<->Out, using schema.Column.Reverse), for the bidirectional mode.
	ReverseSQL string
	// Columns referenced by the filter (to choose the resolution table).
	Columns []string
	// Normalized is the filter re-printed in canonical form.
	Normalized string
}

// ErrNotImplemented is returned by the stub until the parser lands.
var ErrNotImplemented = errors.New("filter: not implemented")

// Compile parses text and returns its SQL form. An empty or blank text gives
// SQL "1". Parse errors are returned as *Error.
func Compile(text string) (Result, error) {
	return Result{SQL: "1", ReverseSQL: "1", Normalized: ""}, nil
}

// Error is a parse or validation error with its position in the input.
type Error struct {
	Line, Column, Offset int
	Message              string
}

func (e *Error) Error() string { return e.Message }
