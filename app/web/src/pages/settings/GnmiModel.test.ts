import { describe, expect, it } from 'vitest'
import { gnmiBody, newGnmiProfile, toGnmiDraft, validateGnmi, type GnmiView } from './GnmiModel'

const view: GnmiView = {
  enabled: true,
  poll_exporters: true,
  devices: ['192.0.2.1'],
  interval_minutes: 30,
  ttl_minutes: 360,
  timeout_seconds: 10,
  concurrency: 8,
  profiles: [{ id: 'pa', name: 'core', prefixes: ['10.0.0.0/8'], port: 57400, username: 'flow', tls: true, encoding: 'json_ietf', mode: 'get', password_set: true, ca_set: true, cert_set: true }],
  encodings: ['json_ietf', 'json'],
  modes: ['get', 'subscribe'],
}

const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'
const keyPem = '-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----'

describe('gNMI settings', () => {
  it('keeps saved secrets and sends typed ones only', () => {
    const d = toGnmiDraft(view)
    expect(validateGnmi(d)).toEqual([])
    expect(gnmiBody(d).profiles[0]).toEqual({ id: 'pa', name: 'core', prefixes: ['10.0.0.0/8'], port: 57400, tls: true, encoding: 'json_ietf', mode: 'get', username: 'flow', skip_verify: false })
    d.profiles[0].password = 'new'
    d.profiles[0].ca_pem = ` ${pem}\n`
    expect(gnmiBody(d).profiles[0]).toMatchObject({ password: 'new', ca_pem: pem })
  })
  it('removes the CA and drops TLS-only fields without TLS', () => {
    const d = toGnmiDraft(view)
    d.profiles[0].ca_remove = true
    expect(gnmiBody(d).profiles[0].ca_pem).toBe('')
    d.profiles[0].tls = false
    d.profiles[0].server_name = 'router.lab'
    const b = gnmiBody(d).profiles[0]
    expect(b).not.toHaveProperty('ca_pem')
    expect(b).not.toHaveProperty('server_name')
    expect(b).not.toHaveProperty('skip_verify')
  })
  it('reports missing credentials and bad input', () => {
    const d = toGnmiDraft(view)
    const p = { ...newGnmiProfile(), name: 'lab', username: 'admin' }
    d.profiles.push(p)
    expect(p.port).toBe(57400)
    expect(validateGnmi(d)).toEqual(['gnmi.err.password'])
    p.username = ''
    expect(validateGnmi(d)).toEqual([])
    expect(gnmiBody(d).profiles[1]).not.toHaveProperty('username')
    p.ca_pem = 'not a certificate'
    p.port = 0
    d.profiles.push({ ...newGnmiProfile(), name: 'Core ' })
    d.devices = 'router1'
    d.ttl_minutes = 10
    expect(validateGnmi(d)).toEqual(expect.arrayContaining(['gnmi.err.ca', 'gnmi.err.port', 'gnmi.err.dup', 'gnmi.err.device', 'gnmi.err.ttl']))
  })
  it('sends the client certificate and key together', () => {
    const d = toGnmiDraft(view)
    const p = d.profiles[0]
    p.mode = 'subscribe'
    p.cert_pem = pem
    expect(validateGnmi(d)).toEqual(['gnmi.err.pair'])
    expect(gnmiBody(d).profiles[0]).not.toHaveProperty('cert_pem')
    p.key_pem = `${keyPem}\n`
    expect(validateGnmi(d)).toEqual([])
    expect(gnmiBody(d).profiles[0]).toMatchObject({ mode: 'subscribe', cert_pem: pem, key_pem: keyPem })
    p.key_pem = 'nope'
    expect(validateGnmi(d)).toEqual(['gnmi.err.key'])
    p.cert_pem = p.key_pem = ''
    p.cert_remove = true
    expect(gnmiBody(d).profiles[0]).toMatchObject({ cert_pem: '', key_pem: '' })
  })
})
