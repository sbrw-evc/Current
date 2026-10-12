import type { GraphType, Units, VisualizeRequest } from '../../api/types'
import { isPreset, resolve, type Range } from '../../lib/time'

// The state of the Visualize page. It lives in the URL as ?q=<base64url(JSON)> with short keys,
// so a link reproduces the view; saved views store the same object.
export type VisState = {
  range: Range
  graph: GraphType
  units: Units
  dimensions: string[]
  limit: number
  bidirectional: boolean
  filter: string
}

export const GRAPHS: GraphType[] = ['stacked', 'lines', 'grid', 'sankey']
export const UNITS: Units[] = ['l3bps', 'l2bps', 'pps', 'inl2%', 'outl2%']

export const DEFAULT_STATE: VisState = {
  range: { preset: '6h' },
  graph: 'stacked',
  units: 'l3bps',
  dimensions: ['SrcAS', 'ExporterName'],
  limit: 10,
  bidirectional: false,
  filter: "InIfBoundary = 'external'",
}

type Compact = { r?: string | [string, string]; g?: string; u?: string; d?: string[]; l?: number; b?: 1; f?: string }

function b64urlEncode(s: string) {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlDecode(s: string) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

export function encodeState(s: VisState): string {
  const c: Compact = {
    r: 'preset' in s.range ? s.range.preset : [s.range.start, s.range.end],
    g: s.graph,
    u: s.units,
    d: s.dimensions,
    l: s.limit,
    f: s.filter,
  }
  if (s.bidirectional) c.b = 1
  return b64urlEncode(JSON.stringify(c))
}

// normalize turns any object (decoded link, saved view) into a valid state, keeping defaults
// for what is missing or wrong.
export function normalize(c: Compact | null | undefined): VisState {
  const s: VisState = { ...DEFAULT_STATE, dimensions: [...DEFAULT_STATE.dimensions] }
  if (!c || typeof c !== 'object') return s
  if (isPreset(c.r)) s.range = { preset: c.r }
  else if (Array.isArray(c.r) && c.r.length === 2 && c.r.every((v) => typeof v === 'string' && !Number.isNaN(Date.parse(v)))) s.range = { start: c.r[0], end: c.r[1] }
  if (GRAPHS.includes(c.g as GraphType)) s.graph = c.g as GraphType
  if (UNITS.includes(c.u as Units)) s.units = c.u as Units
  if (Array.isArray(c.d)) s.dimensions = c.d.filter((d) => typeof d === 'string').slice(0, 10)
  if (typeof c.l === 'number' && c.l >= 1 && c.l <= 50) s.limit = Math.trunc(c.l)
  s.bidirectional = c.b === 1
  if (typeof c.f === 'string') s.filter = c.f
  return s
}

export function decodeState(q: string | null): VisState {
  if (!q) return normalize(null)
  try {
    return normalize(JSON.parse(b64urlDecode(q)) as Compact)
  } catch {
    return normalize(null)
  }
}

// fromSaved reads the `request` of a saved view (a compact state, see encodeState).
export function fromSaved(request: unknown): VisState {
  if (typeof request === 'string') return decodeState(request)
  return normalize(request as Compact)
}

export function toSaved(s: VisState): Compact {
  return JSON.parse(b64urlDecode(encodeState(s))) as Compact
}

export function visualizeLink(s: VisState) {
  return `/visualize?q=${encodeState(s)}`
}

export function toRequest(s: VisState, now = Date.now(), points = 200): VisualizeRequest {
  const { start, end } = resolve(s.range, now)
  return {
    start,
    end,
    points,
    dimensions: s.dimensions,
    limit: s.limit,
    filter: s.filter,
    units: s.units,
    bidirectional: s.bidirectional && s.graph !== 'sankey',
    graph: s.graph,
  }
}
