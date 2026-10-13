import { describe, expect, it } from 'vitest'
import type { Exporter } from '../../api/types'
import type { AlertState, Rule } from '../detector/model'
import { attention, steps, stepsDone } from './model'

const now = Date.parse('2026-10-13T12:00:00Z')
const exp = (name: string, ageMin: number, ref = 'dcim.device:1'): Exporter => ({
  address: '10.0.0.1',
  name,
  ref,
  site: '',
  role: '',
  last_seen: new Date(now - ageMin * 60e3).toISOString(),
  flows_per_second: 1,
  sampling_rates: [],
  interfaces: [],
})
const alert = (state: AlertState['state']): AlertState => ({ rule_id: 'r', key: 'k', state, since: '', value: 0 })

describe('attention', () => {
  it('lists only problems, the most urgent first', () => {
    const a = attention([alert('firing'), alert('pending'), alert('firing')], [exp('a', 1), exp('b', 10), exp('c', 1, '')], now)
    expect(a.map((x) => [x.id, x.count])).toEqual([
      ['alerts', 2],
      ['silent', 1],
      ['noinventory', 1],
    ])
  })
  it('is empty when all is well or nothing is known', () => {
    expect(attention([alert('pending')], [exp('a', 1)], now)).toEqual([])
    expect(attention(undefined, undefined, now)).toEqual([])
  })
})

describe('steps', () => {
  const rule = { enabled: true } as Rule
  it('leaves out what the role cannot read', () => {
    expect(steps({ exporters: [] }).map((s) => s.id)).toEqual(['exporters'])
  })
  it('is done when every required step is, optional ones aside', () => {
    const s = steps({
      exporters: [exp('a', 1)],
      rules: { rules: [rule], default: false },
      inventory: { hook_secret_set: true, write_token_set: false, hook_url: '', inventory_url: '' },
      umbrella: { ingest: { enabled: false, ingest_url: '', token_set: false }, api: { url: 'https://umbrella', token_set: true } },
      bmp: { enabled: false, policy: 'prefer-post', routers: [], as_providers: [] },
    })
    expect(s.map((x) => [x.id, x.done])).toEqual([
      ['exporters', true],
      ['detector', true],
      ['inventory', true],
      ['umbrella', true],
      ['bmp', false],
    ])
    expect(stepsDone(s)).toBe(true)
  })
  it('is not done while a required step is open', () => {
    const s = steps({ exporters: [], rules: { rules: [{ ...rule, enabled: false }], default: true } })
    expect(s.every((x) => !x.done)).toBe(true)
    expect(stepsDone(s)).toBe(false)
  })
})
