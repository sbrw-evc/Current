// Settings → gNMI: types of GET/PUT /api/settings/gnmi and the pure helpers of the page.
import { splitList, validAddress, validPrefixOrAddress } from './SnmpModel'

export type GnmiEncoding = 'json_ietf' | 'json'

export type GnmiProfileView = {
  id: string
  name: string
  prefixes: string[]
  port: number
  username?: string
  tls: boolean
  skip_verify?: boolean
  server_name?: string
  encoding: GnmiEncoding
  password_set: boolean
  ca_set: boolean
}

export type GnmiDeviceStatus = { address: string; profile?: string; interfaces: number; polled?: string; error?: string; configured: boolean }

export type GnmiView = {
  enabled: boolean
  poll_exporters: boolean
  devices: string[]
  interval_minutes: number
  ttl_minutes: number
  timeout_seconds: number
  concurrency: number
  profiles: GnmiProfileView[]
  encodings: GnmiEncoding[]
  status?: { enabled: boolean; devices: GnmiDeviceStatus[]; failing: number } | null
}

// A profile being edited: secrets are write-only ('' = keep the saved one; ca_remove drops the saved CA).
export type GnmiProfileDraft = Omit<GnmiProfileView, 'prefixes'> & {
  prefixes: string
  username: string
  skip_verify: boolean
  server_name: string
  password: string
  ca_pem: string
  ca_remove: boolean
  key: string
}

export type GnmiDraft = Omit<GnmiView, 'devices' | 'profiles' | 'encodings' | 'status'> & { devices: string; profiles: GnmiProfileDraft[] }

export const GNMI_PORT = 57400

let seq = 0
export function newGnmiProfile(): GnmiProfileDraft {
  seq++
  return {
    key: `new-${seq}`,
    id: '',
    name: '',
    prefixes: '',
    port: GNMI_PORT,
    username: '',
    tls: true,
    skip_verify: false,
    server_name: '',
    encoding: 'json_ietf',
    password_set: false,
    ca_set: false,
    password: '',
    ca_pem: '',
    ca_remove: false,
  }
}

export function toGnmiDraft(v: GnmiView): GnmiDraft {
  return {
    enabled: v.enabled,
    poll_exporters: v.poll_exporters,
    devices: v.devices.join('\n'),
    interval_minutes: v.interval_minutes,
    ttl_minutes: v.ttl_minutes,
    timeout_seconds: v.timeout_seconds,
    concurrency: v.concurrency,
    profiles: v.profiles.map((p) => ({
      ...p,
      key: p.id,
      prefixes: p.prefixes.join('\n'),
      username: p.username ?? '',
      skip_verify: !!p.skip_verify,
      server_name: p.server_name ?? '',
      encoding: p.encoding || 'json_ietf',
      password: '',
      ca_pem: '',
      ca_remove: false,
    })),
  }
}

const pemCert = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/

// validateGnmi returns i18n keys of the problems (empty = valid).
export function validateGnmi(d: GnmiDraft): string[] {
  const out = new Set<string>()
  if (splitList(d.devices).some((x) => !validAddress(x))) out.add('gnmi.err.device')
  if (d.ttl_minutes < d.interval_minutes) out.add('gnmi.err.ttl')
  for (const p of d.profiles) {
    if (!p.name.trim()) out.add('gnmi.err.name')
    if (splitList(p.prefixes).some((x) => !validPrefixOrAddress(x))) out.add('gnmi.err.prefix')
    if (p.port < 1 || p.port > 65535) out.add('gnmi.err.port')
    if (p.username.trim() && !p.password_set && !p.password) out.add('gnmi.err.password')
    if (p.tls && p.ca_pem.trim() && !pemCert.test(p.ca_pem)) out.add('gnmi.err.ca')
  }
  const names = d.profiles.map((p) => p.name.trim().toLowerCase())
  if (new Set(names).size !== names.length) out.add('gnmi.err.dup')
  return [...out]
}

export type GnmiProfileBody = {
  id: string
  name: string
  prefixes: string[]
  port: number
  username?: string
  tls: boolean
  skip_verify?: boolean
  server_name?: string
  encoding: GnmiEncoding
  password?: string
  ca_pem?: string
}

// gnmiProfileBody: secrets are sent only when typed or removed (absent = keep the saved one).
export function gnmiProfileBody(p: GnmiProfileDraft): GnmiProfileBody {
  const b: GnmiProfileBody = { id: p.id, name: p.name.trim(), prefixes: splitList(p.prefixes), port: p.port, tls: p.tls, encoding: p.encoding }
  const user = p.username.trim()
  if (user) {
    b.username = user
    if (p.password) b.password = p.password
  }
  if (p.tls) {
    b.skip_verify = p.skip_verify
    if (p.server_name.trim()) b.server_name = p.server_name.trim()
    if (p.ca_pem.trim()) b.ca_pem = p.ca_pem.trim()
    else if (p.ca_remove) b.ca_pem = ''
  }
  return b
}

export function gnmiBody(d: GnmiDraft) {
  return {
    enabled: d.enabled,
    poll_exporters: d.poll_exporters,
    devices: splitList(d.devices),
    interval_minutes: d.interval_minutes,
    ttl_minutes: d.ttl_minutes,
    timeout_seconds: d.timeout_seconds,
    concurrency: d.concurrency,
    profiles: d.profiles.map(gnmiProfileBody),
  }
}
