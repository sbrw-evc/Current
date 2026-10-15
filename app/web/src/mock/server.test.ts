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
  it('answers the settings pages added later', async () => {
    const paths = [
      '/api/roles', '/api/service-accounts', '/api/tokens', '/api/settings/spa', '/api/users', '/api/auth/spa', '/api/inventory-db/integration',
      '/api/settings/umbrella/api', '/api/umbrella/scope', '/api/dependencies', '/api/settings/threat', '/api/settings/rdns', '/api/settings/flowlogs',
    ]
    for (const p of paths) expect((await handle('GET', p, undefined)).status, p).toBe(200)
    expect((await handle('POST', '/api/settings/openbao/probe', { addr: 'http://bao2:8200', mount: 'flow' })).status).toBe(200)
    expect((await handle('POST', '/api/settings/openbao/migrate', { target: { addr: 'http://openbao:8200', mount: 'flow' } })).status).toBe(400)
  })
  it('keeps secrets write-only', async () => {
    const issued = await handle('POST', '/api/tokens', { service_account_id: 1, name: 't' })
    expect(issued.status).toBe(201)
    const plain = (issued.body as { token: string }).token
    expect(JSON.stringify((await handle('GET', '/api/tokens', undefined)).body)).not.toContain(plain)
    expect((await handle('PUT', '/api/settings/flowlogs', { gcp: { enabled: true } })).status).toBe(400)
    const r = await handle('PUT', '/api/settings/flowlogs', { gcp: { enabled: true, token: 'x'.repeat(20) } })
    expect(JSON.stringify(r.body)).not.toContain('x'.repeat(20))
    expect((r.body as { gcp: { token_set: boolean } }).gcp.token_set).toBe(true)
  })
})
