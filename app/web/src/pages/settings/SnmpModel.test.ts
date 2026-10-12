import { describe, expect, it } from 'vitest'
import { body, newProfile, toDraft, validAddress, validate, validPrefixOrAddress, type SnmpView } from './SnmpModel'

const view: SnmpView = {
  enabled: true,
  poll_exporters: true,
  devices: ['192.0.2.1'],
  interval_minutes: 30,
  ttl_minutes: 360,
  timeout_seconds: 3,
  retries: 1,
  concurrency: 8,
  profiles: [{ id: 'pa', name: 'core', prefixes: ['10.0.0.0/8'], version: '2c', port: 161, community_set: true, auth_password_set: false, priv_password_set: false }],
  auth_protocols: ['SHA'],
  priv_protocols: ['AES'],
}

describe('SNMP settings', () => {
  it('validates addresses and prefixes', () => {
    expect(validAddress('10.0.0.1')).toBe(true)
    expect(validAddress('2001:db8::1')).toBe(true)
    expect(validAddress('10.0.0.256')).toBe(false)
    expect(validAddress('router1')).toBe(false)
    expect(validPrefixOrAddress('10.0.0.0/8')).toBe(true)
    expect(validPrefixOrAddress('2001:db8::/129')).toBe(false)
  })
  it('keeps saved secrets and sends typed ones only', () => {
    const d = toDraft(view)
    expect(validate(d)).toEqual([])
    expect(body(d).profiles[0]).toEqual({ id: 'pa', name: 'core', prefixes: ['10.0.0.0/8'], version: '2c', port: 161 })
    d.profiles[0].community = 'new'
    expect(body(d).profiles[0].community).toBe('new')
  })
  it('reports missing credentials', () => {
    const d = toDraft(view)
    const p = { ...newProfile(), name: 'v3', version: '3' as const, username: 'flow' }
    d.profiles.push(p)
    expect(validate(d)).toEqual(expect.arrayContaining(['snmp.err.auth', 'snmp.err.priv']))
    p.security_level = 'noAuthNoPriv'
    expect(validate(d)).toEqual([])
    expect(body(d).profiles[1]).toMatchObject({ version: '3', username: 'flow', security_level: 'noAuthNoPriv' })
    d.profiles.push({ ...newProfile(), name: 'core' })
    expect(validate(d)).toEqual(expect.arrayContaining(['snmp.err.dup', 'snmp.err.community']))
    d.devices = 'not-an-ip'
    expect(validate(d)).toContain('snmp.err.device')
  })
})
