import { describe, expect, it } from 'vitest'
import type { SankeyResult, TimeSeriesResult } from '../api/types'
import { handle } from './server'

const base = { start: '2026-10-12T09:00:00Z', end: '2026-10-12T10:00:00Z', points: 60, limit: 5, filter: '', units: 'l3bps', bidirectional: false }

describe('mock server', () => {
  it('answers visualize with consistent series', async () => {
    const r = await handle('POST', '/api/visualize', { ...base, dimensions: ['SrcAS'], graph: 'stacked', bidirectional: true })
    const d = r.body as TimeSeriesResult
    expect(r.status).toBe(200)
    expect(d.rows.length).toBe(d.points.length)
    expect(d.axis.filter((a) => a === 2).length).toBe(d.rows.length / 2)
    expect(d.points[0].length).toBe(d.t.length)
    expect(d.rows.some((row) => row[0] === 'Other')).toBe(true)
  })
  it('answers sankey with links between nodes', async () => {
    const d = (await handle('POST', '/api/visualize', { ...base, dimensions: ['SrcAS', 'ExporterName'], graph: 'sankey' })).body as SankeyResult
    const nodes = new Set(d.nodes)
    expect(d.links.every((l) => nodes.has(l.source) && nodes.has(l.target))).toBe(true)
  })
  it('rejects an invalid filter', async () => {
    const r = await handle('POST', '/api/visualize', { ...base, dimensions: [], graph: 'lines', filter: 'Nope = 1' })
    expect(r.status).toBe(400)
  })
})
