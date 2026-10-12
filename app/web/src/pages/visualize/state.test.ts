import { describe, expect, it } from 'vitest'
import { decodeState, DEFAULT_STATE, encodeState, fromSaved, normalize, toRequest, toSaved } from './state'

describe('visualize state', () => {
  it('round-trips through the URL', () => {
    const s = { ...DEFAULT_STATE, graph: 'sankey' as const, dimensions: ['SrcAS', 'InIfProvider'], filter: "SrcCountry = 'RU' -- юникод", limit: 7, bidirectional: true }
    const q = encodeState(s)
    expect(q).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(decodeState(q)).toEqual(s)
  })
  it('keeps a fixed range', () => {
    const s = { ...DEFAULT_STATE, range: { start: '2026-10-12T09:00:00Z', end: '2026-10-12T10:00:00Z' } }
    expect(decodeState(encodeState(s)).range).toEqual(s.range)
  })
  it('falls back to defaults on garbage', () => {
    expect(decodeState('%%%')).toEqual(DEFAULT_STATE)
    expect(decodeState(null)).toEqual(DEFAULT_STATE)
    expect(normalize({ g: 'pie', u: 'furlongs', l: 500 } as never)).toMatchObject({ graph: 'stacked', units: 'l3bps', limit: 10 })
  })
  it('reads saved views', () => {
    const s = { ...DEFAULT_STATE, dimensions: ['App'] }
    expect(fromSaved(toSaved(s))).toEqual(s)
  })
  it('builds the API request', () => {
    const now = Date.parse('2026-10-12T10:00:30Z')
    const r = toRequest({ ...DEFAULT_STATE, range: { preset: '1h' }, graph: 'sankey', bidirectional: true }, now)
    expect(r).toMatchObject({ start: '2026-10-12T09:00:00Z', end: '2026-10-12T10:00:00Z', graph: 'sankey', bidirectional: false, points: 200 })
  })
})
