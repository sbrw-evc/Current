import { describe, expect, it } from 'vitest'
import { body, move, toDraft, toggle, validate, validRD } from './BmpModel'

describe('BMP settings', () => {
  it('round-trips and validates', () => {
    const d = toDraft({ enabled: true, policy: 'prefer-post', routers: ['192.0.2.0/24'], as_providers: ['routing', 'flow', 'geoip'] })
    expect(validate(d)).toEqual([])
    expect(body(d)).toEqual({ enabled: true, policy: 'prefer-post', routers: ['192.0.2.0/24'], as_providers: ['routing', 'flow', 'geoip'] })
    d.routers = 'rtr1'
    expect(validate(d)).toContain('bmp.err.router')
    expect(validate({ ...d, routers: '', as_providers: [] })).toEqual(['bmp.err.providers'])
  })
  it('orders AS providers', () => {
    expect(move(['routing', 'flow'], 1, -1)).toEqual(['flow', 'routing'])
    expect(move(['routing', 'flow'], 0, -1)).toEqual(['routing', 'flow'])
    expect(toggle(['routing'], 'geoip')).toEqual(['routing', 'geoip'])
    expect(toggle(['routing', 'geoip'], 'routing')).toEqual(['geoip'])
  })
})

describe('validRD', () => {
  it('accepts the three RD types', () => {
    for (const s of ['65000:100', '192.0.2.1:7', '4200000000:12', ' 0:0 ']) expect(validRD(s), s).toBe(true)
  })
  it('rejects malformed or out of range values', () => {
    for (const s of ['', '65000', ':1', 'x:1', '192.0.2.1:70000', '300.0.0.1:1', '4200000000:70000', '5000000000:1']) expect(validRD(s), s).toBe(false)
  })
})
