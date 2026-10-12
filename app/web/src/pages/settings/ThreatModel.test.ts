import { describe, expect, it } from 'vitest'
import { listState, parseExclude, validateLists, validPrefix } from './ThreatModel'

describe('threat intelligence settings', () => {
  const l = { name: 'feodo', url: 'https://feodo.example/ipblocklist.txt', enabled: true }
  it('derives the list state', () => {
    expect(listState(l, undefined, true)).toBe('pending')
    expect(listState(l, { ...l, prefixes: 0, skipped: 0, error: 'HTTP 503' }, true)).toBe('error')
    expect(listState(l, { ...l, prefixes: 10, skipped: 0, updated_at: '2026-10-12T10:00:00Z' }, true)).toBe('ok')
    expect(listState(l, undefined, false)).toBe('disabled')
    expect(listState({ ...l, enabled: false }, undefined, true)).toBe('disabled')
    expect(listState(l, { ...l, url: 'https://old.example/x', prefixes: 1, skipped: 0, updated_at: 'x' }, true)).toBe('pending')
  })
  it('validates lists', () => {
    expect(validateLists([l])).toEqual([])
    expect(validateLists([{ ...l, name: 'a b' }])).toContain('thr.err.name')
    expect(validateLists([l, l])).toContain('thr.err.dup')
    expect(validateLists([{ ...l, url: 'ftp://x' }])).toContain('thr.err.url')
  })
  it('parses exclusions', () => {
    expect(parseExclude('10.0.0.0/8\n 192.0.2.1, 2001:db8::/32 ')).toEqual(['10.0.0.0/8', '192.0.2.1', '2001:db8::/32'])
    expect(validPrefix('10.0.0.0/8')).toBe(true)
    expect(validPrefix('2001:db8::/32')).toBe(true)
    expect(validPrefix('300.0.0.1')).toBe(false)
    expect(validPrefix('10.0.0.0/33')).toBe(false)
    expect(validPrefix('host.example')).toBe(false)
  })
})
