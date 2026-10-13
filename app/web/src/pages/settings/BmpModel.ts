// Settings → BMP: types of GET/PUT /api/settings/bmp, GET /api/bmp/lookup and helpers.
import { splitList, validPrefixOrAddress } from './SnmpModel'

export type BmpPolicy = 'prefer-post' | 'post' | 'pre'
export const AS_PROVIDERS = ['routing', 'flow', 'flow-except-private', 'geoip'] as const

export type BmpSession = { router: string; sys_name?: string; sys_descr?: string; since: string; peers_up: number; messages: number; errors: number; last_error?: string }
export type BmpPeer = { router: string; address: string; as: number; distinguisher?: number; rd?: string; post_policy: boolean; routes: number; since: string; last_update: string }
export type RibStats = { prefixes_v4: number; prefixes_v6: number; vpn_prefixes?: number; vrfs?: number; routes: number; attribute_sets: number; peers: number; bytes: number }

export type BmpView = {
  enabled: boolean
  policy: BmpPolicy
  routers: string[]
  as_providers: string[]
  status?: { enabled: boolean; listen: string; error?: string; rib: RibStats; sessions: BmpSession[]; peers: BmpPeer[] } | null
}

export type BmpRoute = {
  prefix: string
  rd?: string // VPN table the route was found in; empty for the global table
  origin_as: number
  as_path: number[]
  communities: string[]
  large_communities: string[]
  next_hop: string
  peer: { router: string; address: string; as: number; post_policy: boolean }
}

export type BmpDraft = { enabled: boolean; policy: BmpPolicy; routers: string; as_providers: string[] }

export function toDraft(v: BmpView): BmpDraft {
  return { enabled: v.enabled, policy: v.policy, routers: v.routers.join('\n'), as_providers: [...v.as_providers] }
}

// validRD accepts a route distinguisher as Inventory DB VRFs write it:
// 65000:100, 192.0.2.1:100 or 4200000000:100.
export function validRD(s: string): boolean {
  const m = /^(\d+|\d+\.\d+\.\d+\.\d+):(\d+)$/.exec(s.trim())
  if (!m) return false
  const n = Number(m[2])
  if (m[1].includes('.')) return m[1].split('.').every((o) => Number(o) <= 255) && n <= 0xffff
  const asn = Number(m[1])
  if (asn > 0xffffffff) return false
  return asn <= 0xffff ? n <= 0xffffffff : n <= 0xffff
}

export function validate(d: BmpDraft): string[] {
  const out: string[] = []
  if (splitList(d.routers).some((r) => !validPrefixOrAddress(r))) out.push('bmp.err.router')
  if (d.as_providers.length === 0) out.push('bmp.err.providers')
  return out
}

export function body(d: BmpDraft) {
  return { enabled: d.enabled, policy: d.policy, routers: splitList(d.routers), as_providers: d.as_providers }
}

// move shifts the provider at i by delta (-1 up, +1 down).
export function move(list: string[], i: number, delta: number): string[] {
  const j = i + delta
  if (j < 0 || j >= list.length) return list
  const out = [...list]
  ;[out[i], out[j]] = [out[j], out[i]]
  return out
}

// toggle adds a provider at the end or removes it.
export function toggle(list: string[], p: string): string[] {
  return list.includes(p) ? list.filter((x) => x !== p) : [...list, p]
}
