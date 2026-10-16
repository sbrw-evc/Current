import { describe, expect, it } from 'vitest'
import { devicesMock } from '../../mock/devices'
import { attention, steps } from '../home/model'
import {
  credentialFields,
  deviceCounts,
  draftOf,
  edgeWidth,
  emptyDraft,
  fromCandidate,
  graphOf,
  inputOf,
  isHost,
  isIP,
  matchClient,
  matchDevice,
  positionsOf,
  statusTone,
  uptimeText,
  validateDraft,
  visibleActions,
  type Device,
  type DeviceDetail,
  type Platform,
  type PlatformsView,
  type Topology,
} from './model'

const mock = <T>(method: string, path: string, body?: unknown) => {
  const url = new URL(path, 'http://mock')
  const r = devicesMock(method, url.pathname, body, url.searchParams)
  if (!r) throw new Error(`no mock for ${path}`)
  return r as { status: number; body: T }
}
const platforms = mock<PlatformsView>('GET', '/api/devices/platforms').body.platforms
const plat = (k: string) => platforms.find((p) => p.key === k) as Platform
const devices = () => mock<{ results: Device[] }>('GET', '/api/devices').body.results

describe('device form', () => {
  it('validates the address, port, interval and Inventory DB binding', () => {
    const d = { ...emptyDraft('mikrotik'), host: '10.0.0.9', transport: 'api' }
    expect(validateDraft(d, { inventory: false, creating: true, platform: plat('mikrotik') })).toEqual([])
    expect(validateDraft({ ...d, host: 'bad host;' }, { inventory: false, creating: true })).toContain('form.err.host')
    expect(validateDraft({ ...d, port: '70000' }, { inventory: false, creating: true })).toContain('form.err.port')
    expect(validateDraft({ ...d, poll_seconds: 30 }, { inventory: false, creating: true })).toContain('form.err.poll')
    expect(validateDraft({ ...d, flow_exporter_ip: 'router' }, { inventory: false, creating: true })).toContain('form.err.exporter')
    expect(validateDraft(d, { inventory: true, creating: true })).toContain('form.err.inventory')
    expect(validateDraft(d, { inventory: true, creating: false })).not.toContain('form.err.inventory')
    expect(validateDraft({ ...d, transport: 'telnet' }, { inventory: false, creating: true, platform: plat('mikrotik') })).toContain('form.err.transport')
    expect(isIP('2001:db8::1') && isIP('192.0.2.1') && !isIP('300.1.1.1') && isHost('core-01.example.net') && !isHost('-x')).toBe(true)
  })

  it('sends secrets only when typed and name / site / role only for a standalone device', () => {
    const d = { ...emptyDraft('mikrotik'), host: ' 10.0.0.9 ', name: 'r1', site: 'HQ', role: 'router', tags: 'a, b,,', plain: { username: 'admin' }, secrets: { password: '', api_key: 'k' } }
    const body = inputOf(d, { bound: false, creating: true })
    expect(body).toMatchObject({ host: '10.0.0.9', name: 'r1', site: 'HQ', role: 'router', tags: ['a', 'b'], port: 0, credentials: { username: 'admin', api_key: 'k' } })
    expect((body.credentials as Record<string, string>).password).toBeUndefined()
    const bound = inputOf({ ...d, inventory_id: 7 }, { bound: true, creating: true })
    expect(bound.inventory_id).toBe(7)
    expect(bound.name).toBeUndefined()
    expect(bound.site).toBeUndefined()
    const edit = inputOf({ ...d, clear: ['api_secret'] }, { bound: true, creating: false })
    expect(edit.clear_credentials).toEqual(['api_secret'])
    expect(edit.inventory_id).toBeUndefined()
  })

  it('fills the form from an Inventory DB candidate and from a device', () => {
    const c = { id: 210, name: 'core-spb-01', ref: 'r', site: 'SPB', role: 'switch', status: 'active', manufacturer: 'Cisco', model: 'C9500', platform: 'IOS-XE', host: '10.1.0.2', platform_guess: 'cisco_ios' }
    const d = fromCandidate(c, platforms)
    expect(d).toMatchObject({ inventory_id: 210, platform: 'cisco_ios', transport: 'ssh', host: '10.1.0.2', name: 'core-spb-01' })
    const dev = devices()[0]
    const back = draftOf(dev)
    expect(back.host).toBe(dev.host)
    expect(back.secrets).toEqual({})
  })

  it('shows the credential fields of the transport', () => {
    expect(credentialFields(plat('mikrotik'), 'api', 'own')).toEqual(['username', 'password', 'private_key'])
    expect(credentialFields(plat('mikrotik'), 'snmp', 'own')).toContain('snmp_community')
    expect(credentialFields(plat('mikrotik'), 'snmp', 'profile')).toEqual([])
    expect(credentialFields(plat('tplink'), 'snmp', 'own')).toContain('snmp_version')
    expect(credentialFields(undefined, 'api', 'own')).toEqual([])
  })
})

describe('devices', () => {
  it('counts, searches and colours', () => {
    const list = devices()
    const c = deviceCounts(list)
    expect(c.total).toBe(list.length)
    expect(c.down).toBe(1)
    expect(c.error).toBe(1)
    expect(list.filter((d) => matchDevice(d, 'mx204')).map((d) => d.name)).toEqual(['edge-msk-01'])
    expect(list.filter((d) => matchDevice(d, 'BORDER'))).toHaveLength(1)
    expect([statusTone('up'), statusTone('down'), statusTone('error'), statusTone('unknown'), statusTone('offline')]).toEqual(['ok', 'error', 'warn', 'low', 'off'])
    expect(uptimeText(86400 * 2 + 3600 * 5, 'en')).toBe('2 d 5 h')
    expect(uptimeText(125, 'ru')).toBe('2 мин')
    expect(uptimeText(null, 'en')).toBe('—')
  })

  it('offers the actions the role may run', () => {
    const caps = ['hostname', 'dns', 'reboot', 'command', 'backup', 'endpoint_block']
    const admin = ['reboot', 'command', 'backup']
    expect(visibleActions(caps, admin, { operate: true, admin: false })).toEqual(['hostname', 'dns'])
    expect(visibleActions(caps, admin, { operate: false, admin: true })).toEqual(['hostname', 'dns', 'reboot', 'command'])
    expect(visibleActions(caps, admin, { operate: false, admin: false })).toEqual([])
  })

  it('finds clients and puts down devices and the devices step on the Overview', () => {
    const cl = mock<{ results: DeviceDetail['endpoints'] }>('GET', '/api/endpoints').body.results
    expect(cl.filter((c) => matchClient(c, 'office')).length).toBeGreaterThan(0)
    expect(cl.filter((c) => matchClient(c, 'printer, 2nd')).map((c) => c.note)).toEqual(['Room 214'])
    const items = attention([], [], Date.now(), devices())
    expect(items[0]).toMatchObject({ id: 'devicesdown', count: 1, path: '/devices' })
    expect(attention([], [], Date.now(), [{ status: 'down', enabled: false }])).toEqual([])
    expect(steps({ devices: [] })).toEqual([{ id: 'devices', path: '/devices', done: false, optional: true }])
  })
})

describe('mock API', () => {
  it('keeps Inventory DB the source of truth and refuses duplicates', () => {
    expect(mock('POST', '/api/devices', { platform: 'mikrotik', host: '10.9.9.9' }).status).toBe(400)
    const created = mock<Device>('POST', '/api/devices', { platform: 'cisco_ios', host: '10.1.0.2', inventory_id: 210, credentials: { password: 'x' } })
    expect(created.status).toBe(201)
    expect(created.body).toMatchObject({ name: 'core-spb-01', bound: true, credentials: { set: { password: true } } })
    expect(JSON.stringify(created.body)).not.toContain('"x"')
    expect(mock('POST', '/api/devices', { platform: 'cisco_ios', host: '10.1.0.2', inventory_id: 211 }).status).toBe(409)
    expect(mock('PATCH', `/api/devices/${created.body.id}`, { name: 'renamed' }).status).toBe(400)
    const cand = mock<{ devices: { id: number }[] }>('GET', '/api/devices/inventory-candidates').body.devices
    expect(cand.some((c) => c.id === 210)).toBe(false)
  })
})

describe('network map', () => {
  const topo = mock<Topology>('GET', '/api/topology').body

  it('builds the graph with pinned positions, optional clients and link widths', () => {
    const all = graphOf(topo, { clients: true, labels: true })
    const bare = graphOf(topo, { clients: false, labels: true })
    expect(all.nodes.length).toBeGreaterThan(bare.nodes.length)
    expect(bare.nodes.some((n) => n.id.startsWith('ep:'))).toBe(false)
    expect(bare.links.every((l) => bare.nodes.some((n) => n.id === l.source) && bare.nodes.some((n) => n.id === l.target))).toBe(true)
    const down = all.nodes.find((n) => n.id === 'dev:6')
    expect(down?.itemStyle.color).toBe('#dc2626')
    expect(all.nodes.find((n) => n.id.startsWith('ep:'))?.label.show).toBe(false)
    expect(edgeWidth({ source: 'a', target: 'b', kind: 'link', utilization: 100 })).toBe(5.5)
    expect(edgeWidth({ source: 'a', target: 'b', kind: 'wifi', utilization: 100 })).toBe(1)
  })

  it('stores dragged device positions only', () => {
    expect(positionsOf([{ id: 'dev:3', x: 10.4, y: -2.6 }, { id: 'ep:aa', x: 1, y: 1 }, { id: 'dev:4', x: NaN, y: 0 }])).toEqual({ 'dev:3': [10, -3] })
    mock('PUT', '/api/topology/positions', { 'dev:2': [5, 6] })
    const n = graphOf(mock<Topology>('GET', '/api/topology').body, { clients: false, labels: false }).nodes.find((x) => x.id === 'dev:2')
    expect(n).toMatchObject({ x: 5, y: 6, fixed: true })
  })
})
