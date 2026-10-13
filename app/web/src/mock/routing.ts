import { validRD, type BmpRoute, type BmpView } from '../pages/settings/BmpModel'
import type { GnmiView } from '../pages/settings/GnmiModel'
import type { SnmpView } from '../pages/settings/SnmpModel'

// Mock handlers of Settings → gNMI, Settings → SNMP and Settings → BMP (VITE_MOCK=1), shaped like
// internal/app/gnmi.go and internal/app/routing.go. Secrets are write-only: only the *_set flags come back.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown): Reply => ({ status: 200, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })

const ago = (min: number) => new Date(Date.now() - min * 60e3).toISOString()
const isAddr = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(s)
const isPrefixOrAddr = (s: string) => isAddr(s) || (/^[0-9a-f:.]+\/\d{1,3}$/i.test(s) && isAddr(s.split('/')[0]))

const snmp: Omit<SnmpView, 'auth_protocols' | 'priv_protocols' | 'status'> = {
  enabled: true,
  poll_exporters: true,
  devices: ['10.0.9.20'],
  interval_minutes: 30,
  ttl_minutes: 180,
  timeout_seconds: 5,
  retries: 1,
  concurrency: 8,
  profiles: [
    { id: 'p-core', name: 'Core v3', prefixes: ['10.0.0.0/16'], version: '3', port: 161, username: 'flow', security_level: 'authPriv', auth_protocol: 'SHA256', priv_protocol: 'AES', context_name: '', community_set: false, auth_password_set: true, priv_password_set: true },
    { id: 'p-legacy', name: 'Legacy v2c', prefixes: [], version: '2c', port: 161, community_set: true, auth_password_set: false, priv_password_set: false },
  ],
}

const snmpView = (): SnmpView => ({
  ...snmp,
  auth_protocols: ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
  priv_protocols: ['DES', 'AES', 'AES192', 'AES256', 'AES192C', 'AES256C'],
  status: snmp.enabled
    ? {
        enabled: true,
        failing: 1,
        devices: [
          { address: '10.0.0.1', profile: 'p-core', interfaces: 48, polled: ago(7), configured: false },
          { address: '10.0.0.2', profile: 'p-core', interfaces: 52, polled: ago(7), configured: false },
          { address: '10.0.9.20', profile: 'p-legacy', interfaces: 0, polled: ago(7), error: 'request timeout (after 1 retries)', configured: true },
        ],
      }
    : null,
})

const gnmi: Omit<GnmiView, 'encodings' | 'status'> = {
  enabled: true,
  poll_exporters: true,
  devices: [],
  interval_minutes: 30,
  ttl_minutes: 360,
  timeout_seconds: 10,
  concurrency: 8,
  profiles: [
    { id: 'g-dc', name: 'DC fabric', prefixes: ['10.0.1.0/24'], port: 57400, username: 'flow', tls: true, skip_verify: false, server_name: '', encoding: 'json_ietf', password_set: true, ca_set: true },
    { id: 'g-lab', name: 'Lab (no TLS)', prefixes: ['10.0.200.0/24'], port: 6030, username: '', tls: false, encoding: 'json', password_set: false, ca_set: false },
  ],
}

const gnmiView = (): GnmiView => ({
  ...gnmi,
  encodings: ['json_ietf', 'json'],
  status: gnmi.enabled
    ? {
        enabled: true,
        failing: 1,
        devices: [
          { address: '10.0.1.11', profile: 'DC fabric', interfaces: 66, polled: ago(4), configured: false },
          { address: '10.0.1.12', profile: 'DC fabric', interfaces: 66, polled: ago(4), configured: false },
          { address: '10.0.200.5', profile: 'Lab (no TLS)', interfaces: 0, error: 'Unavailable: connection error: desc = "transport: Error while dialing: dial tcp 10.0.200.5:6030: i/o timeout"', configured: false },
        ],
      }
    : null,
})

type GnmiProfileIn = GnmiView['profiles'][number] & { password?: string | null; ca_pem?: string | null }

const bmp: Omit<BmpView, 'status'> = { enabled: true, policy: 'prefer-post', routers: ['10.0.0.0/24'], as_providers: ['routing', 'flow', 'geoip'] }

const bmpView = (): BmpView => ({
  ...bmp,
  status: bmp.enabled
    ? {
        enabled: true,
        listen: ':10179',
        rib: { prefixes_v4: 1012345, prefixes_v6: 212345, vpn_prefixes: 4210, vrfs: 1, routes: 2453590, attribute_sets: 412000, peers: 2, bytes: 318 << 20 },
        replication: { enabled: true, caught_up: true, routers: [{ router: '10.0.0.2', peers_up: 2, last_record: ago(0.2) }] },
        sessions: [{ router: '10.0.0.1', sys_name: 'edge-msk-1', sys_descr: 'Cisco IOS XR', since: ago(3 * 1440), peers_up: 2, messages: 9_812_331, errors: 0 }],
        peers: [
          { router: '10.0.0.1', address: '203.0.113.1', as: 9002, post_policy: true, routes: 1224690, since: ago(3 * 1440), last_update: ago(0.2) },
          { router: '10.0.0.1', address: '2001:db8::1', as: 9002, post_policy: true, routes: 1224690, since: ago(3 * 1440), last_update: ago(0.3) },
          { router: '10.0.0.1', address: '10.255.0.2', as: 65000, post_policy: true, routes: 4210, since: ago(3 * 1440), last_update: ago(1) },
        ],
      }
    : null,
})

type ProfileIn = SnmpView['profiles'][number] & { community?: string | null; auth_password?: string | null; priv_password?: string | null }

export function routingMock(method: string, p: string, body: unknown, query?: URLSearchParams): Reply | null {
  if (p === '/api/settings/gnmi' && method === 'GET') return ok(gnmiView())
  if (p === '/api/settings/gnmi' && method === 'PUT') {
    const b = (body ?? {}) as Partial<Omit<typeof gnmi, 'profiles'>> & { profiles?: GnmiProfileIn[] }
    for (const d of b.devices ?? []) if (!isAddr(d)) return fail(400, 'gnmi_invalid', `device "${d}" is not an IP address`)
    const set = (v: string | null | undefined, was: boolean | undefined) => (v === undefined || v === null ? !!was : v !== '')
    const profiles = (b.profiles ?? []).map((pr, i) => {
      const old = gnmi.profiles.find((o) => o.id === pr.id)
      const user = pr.username?.trim() ?? ''
      return {
        id: old ? pr.id : `g-${Date.now().toString(36)}-${i}`,
        name: pr.name,
        prefixes: pr.prefixes ?? [],
        port: pr.port || 57400,
        username: user,
        tls: !!pr.tls,
        skip_verify: pr.tls ? !!pr.skip_verify : false,
        server_name: pr.tls ? (pr.server_name ?? '') : '',
        encoding: pr.encoding || 'json_ietf',
        password_set: user !== '' && set(pr.password, old?.password_set),
        ca_set: !!pr.tls && set(pr.ca_pem, old?.ca_set),
      }
    })
    if (profiles.some((pr) => !pr.name?.trim())) return fail(400, 'gnmi_invalid', 'every profile needs a name')
    const noPw = profiles.find((pr) => pr.username && !pr.password_set)
    if (noPw) return fail(400, 'gnmi_invalid', `profile "${noPw.name}": the password is required with a user name`)
    Object.assign(gnmi, { ...b, profiles })
    return ok(gnmiView())
  }
  if (p === '/api/settings/gnmi/test') {
    const b = (body ?? {}) as { address?: string }
    if (!isAddr(b.address ?? '')) return fail(400, 'invalid_address', 'address must be an IP address')
    if (b.address?.startsWith('10.0.200.')) return ok({ ok: false, error: 'Unavailable: connection error: desc = "transport: Error while dialing: dial tcp: i/o timeout"' })
    const sample = [
      ...Array.from({ length: 4 }, (_, i) => ({ index: 1 + i, name: `Ethernet${1 + i}`, descr: i === 0 ? 'spine-1 Ethernet3' : '', speed: 100e9 })),
      { index: 1000001, name: 'Port-Channel1', descr: 'peer link', speed: 200e9 },
      { index: 5000100, name: 'Ethernet1.100', descr: 'tenant A', speed: 100e9 },
    ]
    return ok({ ok: true, details: { interfaces: 66, sample } })
  }
  if (p === '/api/settings/snmp' && method === 'GET') return ok(snmpView())
  if (p === '/api/settings/snmp' && method === 'PUT') {
    const b = (body ?? {}) as Partial<Omit<typeof snmp, 'profiles'>> & { profiles?: ProfileIn[] }
    for (const d of b.devices ?? []) if (!isPrefixOrAddr(d)) return fail(400, 'snmp_invalid', `device ${d}: not an address or CIDR`)
    const profiles = (b.profiles ?? []).map((pr, i) => {
      const old = snmp.profiles.find((o) => o.id === pr.id)
      const set = (v: string | null | undefined, was: boolean | undefined) => (v === undefined || v === null ? !!was : v !== '')
      return {
        id: pr.id || `p-${Date.now().toString(36)}-${i}`,
        name: pr.name,
        prefixes: pr.prefixes ?? [],
        version: pr.version,
        port: pr.port || 161,
        username: pr.username,
        security_level: pr.security_level,
        auth_protocol: pr.auth_protocol,
        priv_protocol: pr.priv_protocol,
        context_name: pr.context_name,
        community_set: set(pr.community, old?.community_set),
        auth_password_set: set(pr.auth_password, old?.auth_password_set),
        priv_password_set: set(pr.priv_password, old?.priv_password_set),
      }
    })
    if (profiles.some((pr) => !pr.name?.trim())) return fail(400, 'snmp_invalid', 'every profile needs a name')
    Object.assign(snmp, { ...b, profiles })
    return ok(snmpView())
  }
  if (p === '/api/settings/snmp/test') {
    const b = (body ?? {}) as { address?: string }
    if (!isAddr(b.address ?? '')) return fail(400, 'invalid_address', 'address must be an IP address')
    if (b.address?.endsWith('.20')) return ok({ ok: false, error: 'request timeout (after 1 retries)' })
    const sample = Array.from({ length: 6 }, (_, i) => ({ index: 501 + i, name: `Hu0/0/0/${i}`, descr: i === 3 ? 'Transit: RETN 100G' : '', speed: 100e9 }))
    return ok({ ok: true, details: { interfaces: 48, sample } })
  }
  if (p === '/api/settings/bmp' && method === 'GET') return ok(bmpView())
  if (p === '/api/settings/bmp' && method === 'PUT') {
    const b = (body ?? {}) as Partial<typeof bmp>
    for (const r of b.routers ?? []) if (!isPrefixOrAddr(r)) return fail(400, 'bmp_invalid', `router ${r}: not an address or CIDR`)
    if (!b.as_providers?.length) return fail(400, 'bmp_invalid', 'at least one AS provider')
    Object.assign(bmp, b)
    return ok(bmpView())
  }
  if (p === '/api/bmp/lookup') {
    const a = (query?.get('address') ?? '').trim()
    if (!isAddr(a)) return fail(400, 'invalid_address', 'address must be an IP address')
    if (!bmp.enabled) return fail(501, 'not_implemented', 'the BMP routing table (it runs with the enricher)')
    const rd = (query?.get('rd') ?? '').trim()
    if (rd && !validRD(rd)) return fail(400, 'invalid_rd', `route distinguisher "${rd}": want admin:number`)
    if (!rd && (a.startsWith('10.') || a.startsWith('192.168.'))) return fail(404, 'no_route', 'no route covers ' + a)
    const v6 = a.includes(':')
    const route: BmpRoute = {
      prefix: v6 ? '2a00:1450::/32' : `${a.split('.').slice(0, 2).join('.')}.0.0/16`,
      rd: rd === '65000:1' ? rd : '',
      origin_as: 15169,
      as_path: [9002, 3356, 15169],
      communities: ['9002:64601', '65000:100'],
      large_communities: ['9002:1:2'],
      next_hop: v6 ? '2001:db8::1' : '203.0.113.1',
      peer: { router: '10.0.0.1', address: v6 ? '2001:db8::1' : '203.0.113.1', as: 9002, post_policy: true },
    }
    return ok(route)
  }
  return null
}
