import { describe, expect, it } from 'vitest'
import type { DependencyRun, Proposal } from '../../api/beacon'
import { endLabel, filterProposals, isUrl, runState, serviceLabel, sortProposals } from './logic'

const p = (from: string, to: string, port: number, bytes: number, flows: number, days: number, app = ''): Proposal => ({
  key: `flow:${from}->${to}:tcp/${port}`,
  from: { source_ref: `inventory-db:dcim.device:${from}`, name: from === '1' ? 'app-01' : '', ip: `10.0.0.${from}` },
  to: { source_ref: `inventory-db:dcim.device:${to}`, name: to === '2' ? 'db-01' : '' },
  type: 'depends_on',
  evidence: { protocol: 'tcp', port, app, bytes_7d: bytes, flows_7d: flows, days_seen: days, first_seen: '', last_seen: '' },
})

const list = [p('1', '2', 5432, 100, 10, 7, 'postgres'), p('3', '4', 443, 300, 5, 3), p('5', '2', 5432, 50, 99, 7)]

describe('umbrella logic', () => {
  it('labels', () => {
    expect(endLabel(list[0].from)).toBe('app-01')
    expect(endLabel(list[1].from)).toBe('10.0.0.3')
    expect(endLabel(list[1].to)).toBe('inventory-db:dcim.device:4')
    expect(serviceLabel(list[0])).toBe('tcp/5432 · postgres')
    expect(serviceLabel(list[1])).toBe('tcp/443')
  })
  it('filters', () => {
    expect(filterProposals(list, 'DB-01').map((x) => x.key)).toEqual([list[0].key, list[2].key])
    expect(filterProposals(list, 'postgres')).toHaveLength(1)
    expect(filterProposals(list, 'tcp/443')).toHaveLength(1)
    expect(filterProposals(list, '  ')).toHaveLength(3)
  })
  it('sorts', () => {
    expect(sortProposals(list, 'bytes').map((x) => x.evidence.bytes_7d)).toEqual([300, 100, 50])
    expect(sortProposals(list, 'flows').map((x) => x.evidence.flows_7d)).toEqual([99, 10, 5])
    expect(sortProposals(list, 'days').map((x) => x.evidence.bytes_7d)).toEqual([100, 50, 300])
    expect(list[0].evidence.bytes_7d).toBe(100) // not mutated
  })
  it('run state', () => {
    const r: DependencyRun = { id: 1, trigger: 'manual', actor: 'a', dry_run: false, started_at: '', finished_at: null, ok: null, error: '', pairs: 0, sent: 0, accepted: 0, updated: 0, ignored: 0, params: {} }
    expect(runState(r)).toBe('running')
    expect(runState({ ...r, finished_at: 'x', ok: true })).toBe('ok')
    expect(runState({ ...r, finished_at: 'x', ok: true, dry_run: true })).toBe('preview')
    expect(runState({ ...r, finished_at: null, ok: false })).toBe('failed')
  })
  it('urls', () => {
    expect(isUrl('https://umbrella.corp')).toBe(true)
    expect(isUrl('umbrella.corp')).toBe(false)
  })
})
