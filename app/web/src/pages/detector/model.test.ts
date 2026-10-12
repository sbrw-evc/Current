import { describe, expect, it } from 'vitest'
import { checkRule, DEFAULT_RULES } from '../../mock/detector'
import { formatRate, fromDraft, newDraft, parseDuration, parseRate, serverProblems, slug, toDraft, validateDraft } from './model'

describe('detector rule model', () => {
  it('parses rates and durations like the server', () => {
    expect(parseRate('1G')).toBe(1e9)
    expect(parseRate('1.5 M')).toBe(1.5e6)
    expect(parseRate('250k')).toBe(250e3)
    expect(parseRate('100000')).toBe(1e5)
    expect(Number.isNaN(parseRate('1X'))).toBe(true)
    expect(formatRate(1e9)).toBe('1G')
    expect(formatRate(123456789)).toBe('123456789')
    expect(parseDuration('90s')).toBe(90e3)
    expect(parseDuration('1h30m')).toBe(5400e3)
    expect(parseDuration('7d')).toBe(7 * 86400e3)
    expect(parseDuration('')).toBe(0)
    expect(Number.isNaN(parseDuration('5 minutes'))).toBe(true)
  })

  it('round-trips every built-in rule through the form draft', () => {
    for (const r of DEFAULT_RULES) {
      const back = fromDraft(toDraft(r))
      expect(back).toEqual(r)
      expect(validateDraft(toDraft(r))).toEqual({})
      expect(checkRule(back)).toEqual([])
    }
  })

  it('checks the fields of each kind', () => {
    const d = newDraft('link_utilization')
    expect(validateDraft(d)).toMatchObject({ name: 'v.required', id: 'v.id', 't.percent': 'v.required' })
    d.name = 'Uplinks'
    d.id = slug('Загрузка аплинков')
    expect(d.id).toBe('zagruzka-aplinkov')
    d.t.percent = '90'
    d.interval = '5s'
    expect(validateDraft(d)).toEqual({ interval: 'v.interval' })
    d.interval = '1m'
    expect(validateDraft(d, ['zagruzka-aplinkov'])).toEqual({ id: 'v.id.taken' })

    const c = newDraft('custom')
    c.name = 'DNS'
    c.id = 'dns'
    expect(validateDraft(c)).toEqual({ signal: 'v.signal', 't.bps': 'v.metric' })
    c.metric = 'pps'
    c.signal = 'red.traffic.dns'
    c.t.bps = '1G' // not the chosen metric: ignored
    expect(validateDraft(c)).toEqual({ 't.pps': 'v.metric' })
    c.t.pps = '50k'
    expect(validateDraft(c)).toEqual({})
    const r = fromDraft(c)
    expect(r.thresholds).toEqual({ pps: 50000 })
    expect(r).toMatchObject({ kind: 'custom', metric: 'pps', operator: '>', signal: 'red.traffic.dns' })

    const drop = newDraft('traffic_drop')
    Object.assign(drop, { name: 'x', id: 'x' })
    drop.t.ratio = '1'
    drop.b.weeks = '2'
    drop.b.min_samples = '3'
    expect(validateDraft(drop)).toEqual({ 't.ratio': 'v.ratio01open', 'b.min_samples': 'v.min_samples' })
  })

  it('maps server errors to fields', () => {
    const sp = serverProblems('rule 3: thresholds.percent is required\nfilter: unknown column Foo\ndimension "X" is unknown\nsomething else', 'bps')
    expect(sp.fields).toEqual({ 't.percent': 'thresholds.percent is required', filter: 'filter: unknown column Foo', dimensions: 'dimension "X" is unknown' })
    expect(sp.other).toEqual(['something else'])
    expect(serverProblems('rule 1: threshold of the metric is required', 'pps').fields).toEqual({ 't.pps': 'threshold of the metric is required' })
  })
})
