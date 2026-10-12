package filter

import (
	"fmt"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

// Grammar (hand-written recursive descent; keywords are case-insensitive):
//
//	filter     = [ or ] EOF
//	or         = and { ( "OR" | "||" ) and }
//	and        = not { ( "AND" | "&&" ) not }
//	not        = ( "NOT" | "!" ) not | primary
//	primary    = "(" or ")" | comparison
//	comparison = Column op value
//	           | Column ( "IN" | "NOTIN" | "NOT" "IN" ) "(" value { "," value } ")"
//	op         = "=" | "==" | "!=" | "<>" | "<" | "<=" | ">" | ">=" | "<<"
//	           | "LIKE" | "UNLIKE" | "ILIKE" | "IUNLIKE" | "NOT" "LIKE" | "NOT" "ILIKE"
//	value      = 'string' | "string" | bare word (number, IP, prefix, AS65000, tcp, identifier)
//
// Comments: "-- …" to end of line and "/* … */".

type node interface{ isNode() }

type binaryNode struct {
	op   string // "AND" or "OR"
	l, r node
}

type notNode struct{ x node }

type cmpNode struct {
	col  schema.Column
	op   string
	vals []value
}

func (*binaryNode) isNode() {}
func (*notNode) isNode()    {}
func (*cmpNode) isNode()    {}

// posError is an error at a byte offset, converted to *Error at the end.
type posError struct {
	off int
	msg string
}

// syntaxError aborts parsing (panic/recover inside the parser only).
type syntaxError struct{ posError }

type parser struct {
	toks []token
	i    int
	errs []posError // semantic errors: parsing goes on
	cols []string   // referenced columns, canonical, deduped
	seen map[string]bool
	// depth of nested NOT and parentheses, bounded to keep the recursion
	// (and the generated SQL) reasonable.
	depth int
}

const maxDepth = 64

func (p *parser) enter(t token) {
	p.depth++
	if p.depth > maxDepth {
		p.fail(t, "filter is nested too deeply (more than %d levels)", maxDepth)
	}
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) fail(t token, format string, args ...any) {
	panic(syntaxError{posError{t.pos, fmt.Sprintf(format, args...)}})
}

func (p *parser) semantic(t token, format string, args ...any) {
	p.errs = append(p.errs, posError{t.pos, fmt.Sprintf(format, args...)})
}

func isKeyword(t token, kw string) bool {
	return t.kind == tWord && strings.EqualFold(t.val, kw)
}

// parse returns the AST (nil for an empty filter), the semantic errors and
// the syntax error if any.
func (p *parser) parse() (n node, errs []posError) {
	defer func() {
		if r := recover(); r != nil {
			se, ok := r.(syntaxError)
			if !ok {
				panic(r)
			}
			n, errs = nil, append(p.errs, se.posError)
		}
	}()
	if p.peek().kind == tEOF {
		return nil, nil
	}
	n = p.parseOr()
	if t := p.peek(); t.kind != tEOF {
		if t.kind == tRParen {
			p.fail(t, "unmatched ')'")
		}
		p.fail(t, "unexpected %s, expected AND, OR or end of filter", t.describe())
	}
	return n, p.errs
}

func (p *parser) parseOr() node {
	n := p.parseAnd()
	for t := p.peek(); t.kind == tOr || isKeyword(t, "OR"); t = p.peek() {
		p.next()
		n = &binaryNode{"OR", n, p.parseAnd()}
	}
	return n
}

func (p *parser) parseAnd() node {
	n := p.parseNot()
	for t := p.peek(); t.kind == tAnd || isKeyword(t, "AND"); t = p.peek() {
		p.next()
		n = &binaryNode{"AND", n, p.parseNot()}
	}
	return n
}

func (p *parser) parseNot() node {
	if t := p.peek(); t.kind == tBang || isKeyword(t, "NOT") {
		p.next()
		p.enter(t)
		defer func() { p.depth-- }()
		return &notNode{p.parseNot()}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() node {
	t := p.next()
	if t.kind == tLParen {
		p.enter(t)
		defer func() { p.depth-- }()
		n := p.parseOr()
		if c := p.peek(); c.kind != tRParen {
			p.fail(c, "expected ')' to close '(', got %s", c.describe())
		}
		p.next()
		return n
	}
	if t.kind != tWord || keywords[strings.ToUpper(t.val)] {
		p.fail(t, "expected column name, NOT or '(', got %s", t.describe())
	}
	return p.parseComparison(t)
}

// lookupColumn finds a column case-insensitively.
func lookupColumn(name string) (schema.Column, bool) {
	if c, ok := schema.ByName(name); ok {
		return c, true
	}
	for _, c := range schema.Columns {
		if strings.EqualFold(c.Name, name) {
			return c, true
		}
	}
	return schema.Column{}, false
}

func (p *parser) parseComparison(colTok token) node {
	col, known := lookupColumn(colTok.val)
	if !known {
		msg := fmt.Sprintf("unknown column %q", colTok.val)
		if s := suggestColumn(colTok.val); s != "" {
			msg += fmt.Sprintf(" (did you mean %s?)", s)
		}
		p.semantic(colTok, "%s", msg)
	} else if !p.seen[col.Name] {
		if p.seen == nil {
			p.seen = map[string]bool{}
		}
		p.seen[col.Name] = true
		p.cols = append(p.cols, col.Name)
	}

	opTok, op := p.parseOperator(colTok)
	if known && !opAllowed(col.Kind, op) {
		p.semantic(opTok, "operator %s is not valid for %s (%s); use one of: %s",
			op, col.Name, col.Kind, strings.Join(operatorsByKind[col.Kind], ", "))
		known = false // don't pile up value errors
	}

	var valToks []token
	if op == opIn || op == opNotIn {
		if t := p.next(); t.kind != tLParen {
			p.fail(t, "expected '(' after %s, got %s", op, t.describe())
		}
		for {
			valToks = append(valToks, p.parseValueToken(col, known))
			t := p.next()
			if t.kind == tRParen {
				break
			}
			if t.kind != tComma {
				p.fail(t, "expected ',' or ')' in %s list, got %s", op, t.describe())
			}
		}
	} else {
		valToks = append(valToks, p.parseValueToken(col, known))
	}

	n := &cmpNode{col: col, op: op}
	for _, vt := range valToks {
		if !known {
			continue
		}
		v, msg := parseValue(col, op, vt)
		if msg != "" {
			p.errs = append(p.errs, posError{vt.pos, msg})
			continue
		}
		n.vals = append(n.vals, v)
	}
	return n
}

func (p *parser) parseOperator(colTok token) (token, string) {
	t := p.next()
	if t.kind == tOp {
		return t, t.val
	}
	if t.kind == tWord {
		switch kw := strings.ToUpper(t.val); kw {
		case opIn, opNotIn, opLike, opUnlike, opILike, opIUnlike:
			return t, kw
		case "NOT":
			n := p.peek()
			switch {
			case isKeyword(n, "IN"):
				p.next()
				return t, opNotIn
			case isKeyword(n, "LIKE"):
				p.next()
				return t, opUnlike
			case isKeyword(n, "ILIKE"):
				p.next()
				return t, opIUnlike
			}
		}
	}
	p.fail(t, "expected operator after %s, got %s", colTok.val, t.describe())
	return t, ""
}

func (p *parser) parseValueToken(col schema.Column, known bool) token {
	t := p.next()
	if t.kind == tString {
		return t
	}
	if t.kind == tWord && !keywords[strings.ToUpper(t.val)] {
		return t
	}
	what := "a value"
	if known {
		switch col.Kind {
		case schema.KindUint:
			what = "a number"
		case schema.KindIP:
			what = "an IP address"
		case schema.KindPrefix:
			what = "a prefix"
		case schema.KindString, schema.KindTime:
			what = "a quoted string"
		}
	}
	p.fail(t, "expected %s, got %s", what, t.describe())
	return t
}

// suggestColumn returns the closest column name, if close enough.
func suggestColumn(name string) string {
	best, bestD := "", 3
	ln := strings.ToLower(name)
	for _, c := range schema.Columns {
		if d := editDistance(ln, strings.ToLower(c.Name), bestD); d < bestD {
			best, bestD = c.Name, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance, capped at max.
func editDistance(a, b string, max int) int {
	if len(a)-len(b) >= max || len(b)-len(a) >= max {
		return max
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
