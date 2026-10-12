// A lexer of the console filter language (docs/api.md), used by the editor to find what to
// complete and by the mock server to validate. The backend owns the real parser.

export type TokType = 'ws' | 'comment' | 'string' | 'lparen' | 'rparen' | 'comma' | 'op' | 'word' | 'error'
export type Token = { type: TokType; text: string; from: number; to: number; unterminated?: boolean }

export const KEYWORDS = ['AND', 'OR', 'NOT', 'IN', 'NOTIN', 'LIKE', 'UNLIKE', 'ILIKE', 'IUNLIKE'] as const
export const LOGIC = ['AND', 'OR', 'NOT']
export const LIST_OPS = ['IN', 'NOTIN']
export const MATCH_OPS = ['LIKE', 'UNLIKE', 'ILIKE', 'IUNLIKE']

export function isKeyword(w: string) {
  return (KEYWORDS as readonly string[]).includes(w.toUpperCase())
}

const WORD = /[A-Za-z0-9_.:/\-*%]/

export function lex(text: string): Token[] {
  const out: Token[] = []
  let i = 0
  while (i < text.length) {
    const c = text[i]
    const start = i
    if (/\s/.test(c)) {
      while (i < text.length && /\s/.test(text[i])) i++
      out.push({ type: 'ws', text: text.slice(start, i), from: start, to: i })
    } else if (c === '-' && text[i + 1] === '-') {
      while (i < text.length && text[i] !== '\n') i++
      out.push({ type: 'comment', text: text.slice(start, i), from: start, to: i })
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 2
      out.push({ type: 'comment', text: text.slice(start, i), from: start, to: i, unterminated: end < 0 })
    } else if (c === "'" || c === '"') {
      i++
      let closed = false
      while (i < text.length) {
        if (text[i] === '\\') i += 2
        else if (text[i] === c) {
          i++
          closed = true
          break
        } else i++
      }
      i = Math.min(i, text.length)
      out.push({ type: 'string', text: text.slice(start, i), from: start, to: i, unterminated: !closed })
    } else if (c === '(') {
      i++
      out.push({ type: 'lparen', text: c, from: start, to: i })
    } else if (c === ')') {
      i++
      out.push({ type: 'rparen', text: c, from: start, to: i })
    } else if (c === ',') {
      i++
      out.push({ type: 'comma', text: c, from: start, to: i })
    } else if (c === '<' && text[i + 1] === '<') {
      i += 2
      out.push({ type: 'op', text: '<<', from: start, to: i })
    } else if ('=!<>'.includes(c)) {
      i++
      if (text[i] === '=') i++
      const op = text.slice(start, i)
      out.push({ type: op === '!' ? 'error' : 'op', text: op, from: start, to: i })
    } else if (WORD.test(c)) {
      while (i < text.length && WORD.test(text[i]) && !(text[i] === '-' && text[i + 1] === '-')) i++
      out.push({ type: 'word', text: text.slice(start, i), from: start, to: i })
    } else {
      i++
      out.push({ type: 'error', text: c, from: start, to: i })
    }
  }
  return out
}

export type CompletionContext = { what: 'column' | 'operator' | 'value' | 'logic'; column?: string; from: number; prefix: string }

// completionContext tells what is expected at `pos`: a column, an operator after a column, a
// value after an operator (with the column it compares), or AND / OR after a whole condition.
export function completionContext(text: string, pos: number): CompletionContext {
  const before = text.slice(0, pos)
  const tokens = lex(before).filter((t) => t.type !== 'ws' && t.type !== 'comment')
  let from = pos
  let prefix = ''
  const last = tokens[tokens.length - 1]
  // The token the cursor is in, unless whitespace follows it.
  if (last && last.to === pos && (last.type === 'word' || (last.type === 'string' && last.unterminated))) {
    tokens.pop()
    from = last.from
    prefix = last.text
  }
  const prev = tokens[tokens.length - 1]
  if (!prev || prev.type === 'lparen' && !isListOpen(tokens) || (prev.type === 'word' && LOGIC.includes(prev.text.toUpperCase()))) {
    return { what: 'column', from, prefix }
  }
  if (prev.type === 'op' || (prev.type === 'word' && [...LIST_OPS, ...MATCH_OPS].includes(prev.text.toUpperCase())) || (prev.type === 'lparen' && isListOpen(tokens)) || (prev.type === 'comma' && isListOpen(tokens))) {
    return { what: 'value', column: columnOf(tokens), from, prefix }
  }
  if (prev.type === 'word' && !isKeyword(prev.text)) {
    const p2 = tokens[tokens.length - 2]
    // A word right after a column-start position is the column: an operator comes next.
    if (!p2 || p2.type === 'lparen' || (p2.type === 'word' && LOGIC.includes(p2.text.toUpperCase()))) return { what: 'operator', column: prev.text, from, prefix }
  }
  return { what: 'logic', from, prefix }
}

// isListOpen: the tokens end inside "Column IN (" … without the closing parenthesis.
function isListOpen(tokens: Token[]) {
  let depth = 0
  for (let i = tokens.length - 1; i >= 0; i--) {
    const t = tokens[i]
    if (t.type === 'rparen') depth++
    else if (t.type === 'lparen') {
      if (depth === 0) {
        const op = tokens[i - 1]
        return !!op && op.type === 'word' && LIST_OPS.includes(op.text.toUpperCase())
      }
      depth--
    }
  }
  return false
}

// columnOf finds the column of the condition the tokens end in.
function columnOf(tokens: Token[]) {
  for (let i = tokens.length - 1; i >= 0; i--) {
    const t = tokens[i]
    if (t.type === 'op' || (t.type === 'word' && [...LIST_OPS, ...MATCH_OPS].includes(t.text.toUpperCase()))) {
      const c = tokens[i - 1]
      return c && c.type === 'word' ? c.text : undefined
    }
  }
  return undefined
}
