package filter

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type tokKind int

const (
	tEOF    tokKind = iota
	tWord           // bare word: column, keyword, number, IP, prefix, bare value
	tString         // quoted string, val holds the unescaped content
	tLParen
	tRParen
	tComma
	tOp   // = != < <= > >= <<
	tAnd  // &&
	tOr   // ||
	tBang // !
)

type token struct {
	kind tokKind
	val  string // unescaped value (strings), operator text, or word
	pos  int    // byte offset of the first character
	end  int    // byte offset just after the token
}

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "end of filter"
	case tString:
		return "string " + quoteNormalized(t.val)
	case tLParen:
		return "'('"
	case tRParen:
		return "')'"
	case tComma:
		return "','"
	default:
		return fmt.Sprintf("%q", t.val)
	}
}

// isWordByte reports whether b may appear in a bare word. Bare words cover
// identifiers, numbers, IPv4/IPv6 addresses and CIDR prefixes.
func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '_' || b == '.' || b == ':' || b == '/'
}

// lex splits the input into tokens, skipping blanks and comments. It reports
// every lexical error it finds and keeps going.
func lex(src string) ([]token, []posError) {
	var toks []token
	var errs []posError
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				errs = append(errs, posError{i, "unterminated comment"})
				i = len(src)
			} else {
				i += 2 + end + 2
			}
		case c == '\'' || c == '"':
			t, e, n := lexString(src, i)
			toks = append(toks, t)
			errs = append(errs, e...)
			i = n
		case c == '(':
			toks = append(toks, token{tLParen, "(", i, i + 1})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")", i, i + 1})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ",", i, i + 1})
			i++
		case c == '=':
			n := 1
			if i+1 < len(src) && src[i+1] == '=' {
				n = 2 // accept "==" as "="
			}
			toks = append(toks, token{tOp, "=", i, i + n})
			i += n
		case c == '!':
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{tOp, "!=", i, i + 2})
				i += 2
			} else {
				toks = append(toks, token{tBang, "!", i, i + 1})
				i++
			}
		case c == '<':
			switch {
			case i+1 < len(src) && src[i+1] == '=':
				toks = append(toks, token{tOp, "<=", i, i + 2})
				i += 2
			case i+1 < len(src) && src[i+1] == '<':
				toks = append(toks, token{tOp, "<<", i, i + 2})
				i += 2
			case i+1 < len(src) && src[i+1] == '>':
				toks = append(toks, token{tOp, "!=", i, i + 2})
				i += 2
			default:
				toks = append(toks, token{tOp, "<", i, i + 1})
				i++
			}
		case c == '>':
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{tOp, ">=", i, i + 2})
				i += 2
			} else {
				toks = append(toks, token{tOp, ">", i, i + 1})
				i++
			}
		case c == '&' && i+1 < len(src) && src[i+1] == '&':
			toks = append(toks, token{tAnd, "&&", i, i + 2})
			i += 2
		case c == '|' && i+1 < len(src) && src[i+1] == '|':
			toks = append(toks, token{tOr, "||", i, i + 2})
			i += 2
		case isWordByte(c):
			start := i
			for i < len(src) && isWordByte(src[i]) && !(src[i] == '/' && i+1 < len(src) && src[i+1] == '*') {
				i++
			}
			toks = append(toks, token{tWord, src[start:i], start, i})
		default:
			r, size := utf8.DecodeRuneInString(src[i:])
			if r == utf8.RuneError && size <= 1 {
				errs = append(errs, posError{i, "invalid UTF-8 byte"})
				size = 1
			} else {
				msg := fmt.Sprintf("unexpected character %q", r)
				if c == '&' || c == '|' {
					msg += fmt.Sprintf(" (did you mean %q?)", string([]byte{c, c}))
				}
				errs = append(errs, posError{i, msg})
			}
			i += size
		}
	}
	toks = append(toks, token{tEOF, "", len(src), len(src)})
	return toks, errs
}

// lexString reads a quoted string starting at src[start] and returns the
// token, the errors and the offset just after the string.
func lexString(src string, start int) (token, []posError, int) {
	quote := src[start]
	var b strings.Builder
	var errs []posError
	i := start + 1
	for i < len(src) {
		c := src[i]
		switch {
		case c == quote:
			return token{tString, b.String(), start, i + 1}, errs, i + 1
		case c == '\\':
			if i+1 >= len(src) {
				i++
				continue
			}
			switch e := src[i+1]; e {
			case '\\', '\'', '"':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			default:
				r, _ := utf8.DecodeRuneInString(src[i+1:])
				errs = append(errs, posError{i, fmt.Sprintf("unknown escape sequence \\%c", r)})
			}
			i += 2
		default:
			r, size := utf8.DecodeRuneInString(src[i:])
			if r == utf8.RuneError && size <= 1 {
				errs = append(errs, posError{i, "invalid UTF-8 byte in string"})
				i++
				continue
			}
			b.WriteString(src[i : i+size])
			i += size
		}
	}
	errs = append(errs, posError{start, "unterminated string"})
	return token{tString, b.String(), start, len(src)}, errs, len(src)
}
