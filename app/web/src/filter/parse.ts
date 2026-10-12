import type { Column, FilterError, ValidateResult } from '../api/types'
import { LIST_OPS, LOGIC, MATCH_OPS, lex, type Token } from './lexer'

// A validating parser of the filter language for the mock server and tests; it returns the
// first error with its position, like POST /api/filter/validate.

const OPS: Record<string, string[]> = {
  string: ['=', '!=', ...LIST_OPS, ...MATCH_OPS],
  ip: ['=', '!=', '<<', ...LIST_OPS],
  prefix: ['=', '!=', ...LIST_OPS],
  uint: ['=', '!=', '<', '<=', '>', '>=', ...LIST_OPS],
  time: ['=', '!=', '<', '<=', '>', '>='],
}

export function operatorsFor(kind: string) {
  return OPS[kind] ?? OPS.string
}

class Fail extends Error {
  constructor(
    public at: number,
    msg: string,
  ) {
    super(msg)
  }
}

export function validate(text: string, columns: Column[]): ValidateResult {
  const toks = lex(text).filter((t) => t.type !== 'ws' && t.type !== 'comment')
  const byName = new Map(columns.map((c) => [c.name.toLowerCase(), c]))
  let i = 0
  const peek = (): Token | undefined => toks[i]
  const up = (t?: Token) => (t?.type === 'word' ? t.text.toUpperCase() : '')
  const end = text.length
  const parts: string[] = []

  const value = (kind: string) => {
    const t = peek()
    if (!t || t.type === 'rparen' || t.type === 'comma' || t.type === 'op') throw new Fail(t?.from ?? end, 'value expected')
    if (t.type === 'string' && t.unterminated) throw new Fail(t.from, 'unterminated string')
    if (t.type === 'word' && (LOGIC.includes(up(t)) || LIST_OPS.includes(up(t)))) throw new Fail(t.from, 'value expected')
    if (t.type === 'word' && kind === 'uint' && !/^(\d+|AS\d+|tcp|udp|icmp|gre|icmpv6|esp)$/i.test(t.text)) throw new Fail(t.from, `number expected, got "${t.text}"`)
    if (t.type === 'word' && kind === 'ip' && !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(t.text)) throw new Fail(t.from, `IP address expected, got "${t.text}"`)
    i++
    return t.text
  }

  const condition = () => {
    const t = peek()
    if (!t) throw new Fail(end, 'column expected')
    if (t.type !== 'word') throw new Fail(t.from, 'column expected')
    const col = byName.get(t.text.toLowerCase())
    if (!col) throw new Fail(t.from, `unknown column "${t.text}"`)
    i++
    const op = peek()
    const opText = op?.type === 'op' ? op.text : up(op)
    if (!op || !opText) throw new Fail(op?.from ?? end, 'operator expected')
    if (!operatorsFor(col.kind).includes(opText)) throw new Fail(op.from, `operator "${op.text}" is not valid for ${col.name}`)
    i++
    if (LIST_OPS.includes(opText)) {
      if (peek()?.type !== 'lparen') throw new Fail(peek()?.from ?? end, '"(" expected')
      i++
      const vals = [value(col.kind)]
      while (peek()?.type === 'comma') {
        i++
        vals.push(value(col.kind))
      }
      if (peek()?.type !== 'rparen') throw new Fail(peek()?.from ?? end, '")" expected')
      i++
      parts.push(`${col.name} ${opText} (${vals.join(', ')})`)
    } else {
      parts.push(`${col.name} ${opText} ${value(col.kind)}`)
    }
  }

  const term = (): void => {
    const t = peek()
    if (up(t) === 'NOT') {
      i++
      parts.push('NOT')
      return term()
    }
    if (t?.type === 'lparen') {
      i++
      parts.push('(')
      expr()
      if (peek()?.type !== 'rparen') throw new Fail(peek()?.from ?? end, '")" expected')
      i++
      parts.push(')')
      return
    }
    condition()
  }

  const expr = () => {
    term()
    while (up(peek()) === 'AND' || up(peek()) === 'OR') {
      parts.push(up(peek()))
      i++
      term()
    }
  }

  try {
    const bad = lex(text).find((t) => t.type === 'error' || (t.type === 'comment' && t.unterminated))
    if (bad) throw new Fail(bad.from, bad.type === 'comment' ? 'unterminated comment' : `unexpected "${bad.text}"`)
    if (toks.length > 0) {
      expr()
      if (i < toks.length) throw new Fail(toks[i].from, `unexpected "${toks[i].text}"`)
    }
    return { valid: true, errors: [], parsed: parts.join(' ').replace(/\( /g, '(').replace(/ \)/g, ')') }
  } catch (e) {
    if (!(e instanceof Fail)) throw e
    return { valid: false, errors: [position(text, e.at, e.message)], parsed: '' }
  }
}

function position(text: string, offset: number, message: string): FilterError {
  const before = text.slice(0, offset).split('\n')
  return { line: before.length, column: before[before.length - 1].length + 1, offset, message }
}
