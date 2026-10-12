import { describe, expect, it } from 'vitest'
import { columns } from '../mock/schema'
import { completionContext, lex } from './lexer'
import { validate } from './parse'

describe('lexer', () => {
  it('splits a filter', () => {
    const toks = lex("SrcAddr << 10.0.0.0/8 AND App IN ('dns', \"ssh\") -- note").filter((t) => t.type !== 'ws')
    expect(toks.map((t) => t.type)).toEqual(['word', 'op', 'word', 'word', 'word', 'word', 'lparen', 'string', 'comma', 'string', 'rparen', 'comment'])
  })
})

describe('completion context', () => {
  const at = (s: string) => completionContext(s.replace('|', ''), s.indexOf('|'))
  it('expects a column at the start and after logic', () => {
    expect(at('|')).toMatchObject({ what: 'column', prefix: '' })
    expect(at('Src|')).toMatchObject({ what: 'column', prefix: 'Src', from: 0 })
    expect(at('Proto = 6 AND (Dst|')).toMatchObject({ what: 'column', prefix: 'Dst' })
  })
  it('expects an operator after a column', () => {
    expect(at('SrcAS |')).toMatchObject({ what: 'operator', column: 'SrcAS' })
  })
  it('expects a value after an operator', () => {
    expect(at("InIfBoundary = 'ext|")).toMatchObject({ what: 'value', column: 'InIfBoundary', prefix: "'ext" })
    expect(at('App IN (dns, |')).toMatchObject({ what: 'value', column: 'App' })
  })
  it('expects AND / OR after a condition', () => {
    expect(at('Proto = tcp |')).toMatchObject({ what: 'logic' })
  })
})

describe('validate (mock)', () => {
  it('accepts valid filters', () => {
    expect(validate("InIfBoundary = 'external' AND (Proto = tcp OR DstPort IN (53, 123))", columns).valid).toBe(true)
    expect(validate('NOT SrcAddr << 10.0.0.0/8', columns).valid).toBe(true)
    expect(validate('', columns).valid).toBe(true)
  })
  it('reports the position of an error', () => {
    const r = validate('Proto = 6 AND Foo = 1', columns)
    expect(r.valid).toBe(false)
    expect(r.errors[0]).toMatchObject({ offset: 14, line: 1, column: 15 })
    expect(validate("SrcAS << 'x'", columns).errors[0].offset).toBe(6)
    expect(validate('(Proto = 6', columns).errors[0].message).toContain(')')
  })
})
