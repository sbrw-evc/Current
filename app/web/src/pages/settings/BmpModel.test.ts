import { describe, expect, it } from 'vitest'
import { body, move, toDraft, toggle, validate } from './BmpModel'

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
