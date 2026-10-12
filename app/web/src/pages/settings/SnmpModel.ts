// Settings → SNMP: types of GET/PUT /api/settings/snmp and the pure helpers of the page.

export type SnmpVersion = '2c' | '3'
export type SecurityLevel = 'noAuthNoPriv' | 'authNoPriv' | 'authPriv'

export type SnmpProfileView = {
  id: string
  name: string
  prefixes: string[]
  version: SnmpVersion
  port: number
  username?: string
  security_level?: SecurityLevel
  auth_protocol?: string
  priv_protocol?: string
  context_name?: string
  community_set: boolean
  auth_password_set: boolean
  priv_password_set: boolean
}

export type SnmpDeviceStatus = { address: string; profile?: string; interfaces: number; polled?: string; error?: string; configured: boolean }

export type SnmpView = {
  enabled: boolean
  poll_exporters: boolean
  devices: string[]
  interval_minutes: number
  ttl_minutes: number
  timeout_seconds: number
  retries: number
  concurrency: number
  profiles: SnmpProfileView[]
  auth_protocols: string[]
  priv_protocols: string[]
  status?: { enabled: boolean; devices: SnmpDeviceStatus[]; failing: number } | null
}

// A profile being edited: secrets are write-only ('' = keep the saved one).
export type ProfileDraft = Omit<SnmpProfileView, 'prefixes'> & { prefixes: string; community: string; auth_password: string; priv_password: string; key: string }

export type SnmpDraft = Omit<SnmpView, 'devices' | 'profiles' | 'auth_protocols' | 'priv_protocols' | 'status'> & { devices: string; profiles: ProfileDraft[] }

let seq = 0
export function newProfile(): ProfileDraft {
  seq++
  return {
    key: `new-${seq}`,
    id: '',
    name: '',
    prefixes: '',
    version: '2c',
    port: 161,
    username: '',
    security_level: 'authPriv',
    auth_protocol: 'SHA256',
    priv_protocol: 'AES',
    context_name: '',
    community_set: false,
    auth_password_set: false,
    priv_password_set: false,
    community: '',
    auth_password: '',
    priv_password: '',
  }
}

export function toDraft(v: SnmpView): SnmpDraft {
  return {
    enabled: v.enabled,
    poll_exporters: v.poll_exporters,
    devices: v.devices.join('\n'),
    interval_minutes: v.interval_minutes,
    ttl_minutes: v.ttl_minutes,
    timeout_seconds: v.timeout_seconds,
    retries: v.retries,
    concurrency: v.concurrency,
    profiles: v.profiles.map((p) => ({
      ...p,
      key: p.id,
      prefixes: p.prefixes.join('\n'),
      username: p.username ?? '',
      security_level: p.security_level ?? 'authPriv',
      auth_protocol: p.auth_protocol || 'SHA256',
      priv_protocol: p.priv_protocol || 'AES',
      context_name: p.context_name ?? '',
      community: '',
      auth_password: '',
      priv_password: '',
    })),
  }
}

export function splitList(s: string): string[] {
  return s
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

export function validAddress(s: string): boolean {
  if (ipv4.test(s)) return true
  if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false
  const parts = s.split('::')
  if (parts.length > 2) return false
  const groups = s.split(':').filter((g) => g !== '')
  return groups.length <= 8 && groups.every((g) => ipv4.test(g) || /^[0-9a-fA-F]{1,4}$/.test(g))
}

export function validPrefixOrAddress(s: string): boolean {
  const [a, bits, extra] = s.split('/')
  if (extra !== undefined) return false
  if (!validAddress(a)) return false
  if (bits === undefined) return true
  if (!/^\d{1,3}$/.test(bits)) return false
  return Number(bits) <= (a.includes(':') ? 128 : 32)
}

// validate returns i18n keys of the problems (empty = valid).
export function validate(d: SnmpDraft): string[] {
  const out = new Set<string>()
  if (splitList(d.devices).some((x) => !validAddress(x))) out.add('snmp.err.device')
  if (d.ttl_minutes < d.interval_minutes) out.add('snmp.err.ttl')
  for (const p of d.profiles) {
    if (!p.name.trim()) out.add('snmp.err.name')
    if (splitList(p.prefixes).some((x) => !validPrefixOrAddress(x))) out.add('snmp.err.prefix')
    if (p.port < 1 || p.port > 65535) out.add('snmp.err.port')
    if (p.version === '2c' && !p.community_set && !p.community) out.add('snmp.err.community')
    if (p.version === '3') {
      if (!p.username?.trim()) out.add('snmp.err.user')
      if (p.security_level !== 'noAuthNoPriv' && !p.auth_password_set && !p.auth_password) out.add('snmp.err.auth')
      if (p.security_level === 'authPriv' && !p.priv_password_set && !p.priv_password) out.add('snmp.err.priv')
    }
  }
  const names = d.profiles.map((p) => p.name.trim().toLowerCase())
  if (new Set(names).size !== names.length) out.add('snmp.err.dup')
  return [...out]
}

export type ProfileBody = {
  id: string
  name: string
  prefixes: string[]
  version: SnmpVersion
  port: number
  username?: string
  security_level?: SecurityLevel
  auth_protocol?: string
  priv_protocol?: string
  context_name?: string
  community?: string
  auth_password?: string
  priv_password?: string
}

// profileBody: secrets are sent only when typed (absent = keep the saved one).
export function profileBody(p: ProfileDraft): ProfileBody {
  const b: ProfileBody = { id: p.id, name: p.name.trim(), prefixes: splitList(p.prefixes), version: p.version, port: p.port }
  if (p.version === '2c') {
    if (p.community) b.community = p.community
  } else {
    b.username = p.username?.trim()
    b.security_level = p.security_level
    b.context_name = p.context_name?.trim() || undefined
    if (p.security_level !== 'noAuthNoPriv') {
      b.auth_protocol = p.auth_protocol
      if (p.auth_password) b.auth_password = p.auth_password
    }
    if (p.security_level === 'authPriv') {
      b.priv_protocol = p.priv_protocol
      if (p.priv_password) b.priv_password = p.priv_password
    }
  }
  return b
}

export function body(d: SnmpDraft) {
  return {
    enabled: d.enabled,
    poll_exporters: d.poll_exporters,
    devices: splitList(d.devices),
    interval_minutes: d.interval_minutes,
    ttl_minutes: d.ttl_minutes,
    timeout_seconds: d.timeout_seconds,
    retries: d.retries,
    concurrency: d.concurrency,
    profiles: d.profiles.map(profileBody),
  }
}
