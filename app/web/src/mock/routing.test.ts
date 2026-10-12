import { describe, expect, it } from 'vitest'
import type { BmpView } from '../pages/settings/BmpModel'
import type { SnmpView } from '../pages/settings/SnmpModel'
import { routingMock } from './routing'

describe('SNMP / BMP mock', () => {
  it('keeps SNMP secrets write-only', () => {
    const v = routingMock('GET', '/api/settings/snmp', null)!.body as SnmpView
    expect(v.profiles[0]).not.toHaveProperty('auth_ref')
    const legacy = v.profiles.find((p) => p.version === '2c')!
    const r = routingMock('PUT', '/api/settings/snmp', { ...v, profiles: [{ ...legacy, community: '' }] })!
    expect(r.status).toBe(200)
    expect((r.body as SnmpView).profiles[0].community_set).toBe(false)
    expect(routingMock('PUT', '/api/settings/snmp', { ...v, devices: ['nope'] })!.status).toBe(400)
  })

  it('answers BMP settings and lookups', () => {
    const v = routingMock('GET', '/api/settings/bmp', null)!.body as BmpView
    expect(v.status?.listen).toBe(':10179')
    expect(routingMock('PUT', '/api/settings/bmp', { ...v, as_providers: [] })!.status).toBe(400)
    expect(routingMock('GET', '/api/bmp/lookup', null, new URLSearchParams('address=8.8.8.8'))!.status).toBe(200)
    expect(routingMock('GET', '/api/bmp/lookup', null, new URLSearchParams('address=10.1.1.1'))!.status).toBe(404)
    expect(routingMock('GET', '/api/unknown', null)).toBeNull()
  })
})
