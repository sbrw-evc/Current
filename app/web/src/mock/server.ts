import type {
  Classifiers,
  CompleteRequest,
  FlowsRequest,
  InventoryDB,
  SankeyResult,
  SavedView,
  TimeSeriesResult,
  User,
  VisualizeRequest,
} from '../api/types'
import { LIST_OPS, MATCH_OPS } from '../filter/lexer'
import { operatorsFor, validate } from '../filter/parse'
import { diurnal, hash, mockExporters, rng, values, valuesFor } from './data'
import { columns } from './schema'

// An in-browser stand-in for the backend (VITE_MOCK=1): every endpoint of docs/api.md answers
// with synthetic data, so the console can be developed and screenshot-tested without ClickHouse.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown): Reply => ({ status: 200, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })

const ALL_PERMISSIONS = [
  'visualize:view',
  'flows:view',
  'exporters:view',
  'settings.inventory:view',
  'settings.inventory:edit',
  'settings.classifiers:view',
  'settings.classifiers:edit',
  'settings.openbao:view',
  'settings.openbao:test',
]

const user: User = { id: 'u1', username: 'admin', name: 'Анна Смирнова', role: 'admin', permissions: ALL_PERMISSIONS }

// The wizard is shown when the page was opened with ?mock-setup (kept for the browser tab).
function mockSetup() {
  try {
    if (new URLSearchParams(window.location.search).has('mock-setup')) sessionStorage.setItem('flow.mock.setup', '1')
    return sessionStorage.getItem('flow.mock.setup') === '1'
  } catch {
    return false
  }
}

const SETUP_CODE = '123456'

// Secrets are write-only, as in the real server: the mock keeps only whether one is set.
const setupDefaults = {
  language: 'ru',
  theme: 'system',
  timezone: 'Europe/Moscow',
  public_url: '',
  openbao: { addr: 'http://openbao:8200', mount: 'flow', auth: 'approle', role_id: '6f1c2a9e-flow-role', secret_id_set: true, token_set: false },
  postgres: { host: 'postgres', port: 5432, database: 'flow', username: 'flow', sslmode: 'disable', password_set: true },
  clickhouse: { addr: 'clickhouse:9000', database: 'flow', username: 'flow', secure: false, password_set: true },
  nats: { url: 'nats://nats:4222' },
  collector: { netflow_addr: ':2055', sflow_addr: ':6343', default_sampling_rate: 1 },
}

function setupTest(step: string, b: Record<string, unknown>) {
  const str = (k: string) => String(b[k] ?? '').trim()
  const bad = (error: string) => ({ ok: false, error })
  switch (step) {
    case 'openbao':
      if (!/^https?:\/\//.test(str('addr'))) return bad('address must start with http:// or https://')
      if (str('addr').includes('bad')) return bad('dial tcp: lookup openbao-bad: no such host')
      return { ok: true, details: { version: '2.2.0', mount: str('mount') || 'flow', policies: ['flow'], token_ttl: '768h' } }
    case 'postgres':
      if (!str('host')) return bad('host is required')
      if (str('host').includes('bad')) return bad('dial tcp 10.0.0.9:5432: connect: connection refused')
      if (!b.password && !setupDefaults.postgres.password_set) return bad('password authentication failed for user "flow"')
      return { ok: true, details: { version: 'PostgreSQL 17.2', has_state: str('database').includes('old'), saved_at: str('database').includes('old') ? '2026-09-30T08:12:00Z' : undefined } }
    case 'clickhouse':
      if (str('addr').includes('bad')) return bad('code: 516, message: flow: Authentication failed')
      return { ok: true, details: { version: '25.8.3.66', tables: 'flows, flows_1m, flows_5m, flows_1h — will be created' } }
    case 'nats':
      if (!/^nats:\/\//.test(str('url'))) return bad('URL must start with nats://')
      return { ok: true, details: { server: 'nats-server 2.11.4', jetstream: true } }
    case 'inventory':
      if (!b.token) return bad('401 Unauthorized: token is missing')
      return { ok: true, details: { version: 'Inventory DB 1.8.0', devices: 214, prefixes: 1342, circuits: 38 } }
    case 'umbrella':
      if (!b.token) return bad('401 Unauthorized')
      return { ok: true, details: { connector: 'umbrella-flow', event: 'accepted (flow.setup.test)' } }
    case 'geoip': {
      const files = (b.databases as string[]) ?? []
      const wrong = files.find((f) => !f.endsWith('.mmdb'))
      if (wrong) return bad(`${wrong}: not a MaxMind database`)
      return { ok: true, details: { files: files.length, build: '2026-10-07' } }
    }
  }
  return bad('unknown step')
}

const state = {
  signedIn: true,
  setupRequired: mockSetup(),
  savedViews: [
    { id: 'v1', name: 'Внешний трафик по AS', owner: 'admin', shared: true, request: { r: '24h', g: 'stacked', u: 'l3bps', d: ['SrcAS'], l: 10, f: "InIfBoundary = 'external'" } },
    { id: 'v2', name: 'Провайдеры (in/out)', owner: 'admin', shared: false, request: { r: '7d', g: 'stacked', u: 'l3bps', d: ['InIfProvider'], l: 8, b: 1, f: "InIfBoundary = 'external'" } },
    { id: 'v3', name: 'AS → экспортёр (sankey)', owner: 'noc', shared: true, request: { r: '1h', g: 'sankey', u: 'l3bps', d: ['SrcAS', 'ExporterName', 'InIfProvider'], l: 8, f: '' } },
  ] as SavedView[],
  inventory: {
    enabled: true,
    url: 'https://inventory.example.net',
    token_set: true,
    interval: '15m',
    last_sync: { at: new Date(Date.now() - 7 * 60e3).toISOString(), ok: true, devices: 214, interfaces: 6812, prefixes: 1342, circuits: 38 },
  } as InventoryDB,
  classifiers: {
    exporter: [
      'Exporter.Name.startsWith("edge-") ? ClassifyRole("border") : false',
      'Exporter.Name.matches("-msk-") ? ClassifySite("MSK-DC1") : false',
      'ClassifyGroup("default")',
    ],
    interface: [
      'Interface.Description.startsWith("Transit:") ? ClassifyExternal() && ClassifyConnectivity("transit") && ClassifyProvider(Interface.Description.split(":")[1].trim().split(" ")[0]) : false',
      'Interface.Description.startsWith("IX:") ? ClassifyExternal() && ClassifyConnectivity("ix") : false',
      'ClassifyInternal()',
    ],
  } as Classifiers,
}

const SCALE: Record<string, number> = { l3bps: 182e9, l2bps: 188e9, pps: 21.5e6, 'inl2%': 58, 'outl2%': 24 }

function filterFactor(filter: string) {
  if (!filter.trim()) return 1
  return 0.25 + (hash(filter) % 1000) / 1400
}

function combos(dims: string[], seed: number, limit: number) {
  // The heaviest combinations of the dimension values, with their share.
  const r = rng(seed)
  let list: { row: string[]; w: number }[] = [{ row: [], w: 1 }]
  for (const d of dims) {
    const vals = valuesFor(d)
    const total = vals.reduce((a, [, w]) => a + w, 0)
    const next: { row: string[]; w: number }[] = []
    for (const c of list)
      for (const [v, w] of vals) next.push({ row: [...c.row, v], w: c.w * (w / total) * (0.55 + r() * 0.9) })
    next.sort((a, b) => b.w - a.w)
    list = next.slice(0, 400)
  }
  const sum = list.reduce((a, c) => a + c.w, 0)
  return list.map((c) => ({ row: c.row, w: c.w / sum })).slice(0, limit + 1000)
}

function p95(a: number[]) {
  const s = [...a].sort((x, y) => x - y)
  return s[Math.min(s.length - 1, Math.floor(s.length * 0.95))] ?? 0
}

function timeseries(req: VisualizeRequest): TimeSeriesResult {
  const start = Date.parse(req.start)
  const end = Date.parse(req.end)
  const span = Math.max(60e3, end - start)
  const step = Math.max(60e3, Math.ceil(span / Math.max(10, req.points) / 60e3) * 60e3)
  const t: number[] = []
  for (let x = Math.ceil(start / step) * step; x <= end; x += step) t.push(x)
  const scale = SCALE[req.units] * filterFactor(req.filter)
  const dims = req.dimensions
  const list = dims.length === 0 ? [{ row: ['Total'], w: 1 }] : combos(dims, hash(dims.join(',') + req.filter), req.limit)
  const top = list.slice(0, dims.length === 0 ? 1 : req.limit)
  const otherW = 1 - top.reduce((a, c) => a + c.w, 0)
  const series = otherW > 0.002 ? [...top, { row: dims.map(() => 'Other'), w: otherW }] : top
  const rows: string[][] = []
  const points: number[][] = []
  const axis: number[] = []
  const dirs = req.bidirectional ? [1, 2] : [1]
  for (const dir of dirs) {
    for (const s of series) {
      const r = rng(hash(s.row.join('|') + dir))
      const phase = r() * 6
      const noise = 0.06 + r() * 0.08
      const ratio = dir === 2 ? 0.16 + r() * 0.2 : 1
      const pts = t.map((x, i) => {
        const base = diurnal(x + phase * 3600e3 * 0.15) * s.w * scale * ratio
        const wobble = 1 + noise * Math.sin(i / 3 + phase) + noise * (r() - 0.5)
        const spike = r() < 0.006 ? 1.6 : 1
        return Math.max(0, base * wobble * spike)
      })
      rows.push(s.row)
      points.push(pts)
      axis.push(dir)
    }
  }
  const average = points.map((p) => p.reduce((a, b) => a + b, 0) / (p.length || 1))
  const resolution = span <= 3 * 3600e3 ? 'raw' : span <= 2 * 86400e3 ? '1m' : span <= 10 * 86400e3 ? '5m' : '1h'
  const table = resolution === 'raw' ? 'flows' : `flows_${resolution}`
  return {
    t: t.map((x) => new Date(x).toISOString().replace('.000Z', 'Z')),
    rows,
    points,
    axis,
    average,
    min: points.map((p) => Math.min(...p)),
    max: points.map((p) => Math.max(...p)),
    p95: points.map(p95),
    resolution,
    sql: `WITH\n  toStartOfInterval(TimeReceived, INTERVAL ${step / 1000} second) AS time,\n  rows AS (SELECT ${dims.join(', ') || "'Total'"} FROM ${table}\n           WHERE TimeReceived BETWEEN toDateTime('${req.start}') AND toDateTime('${req.end}')\n             AND (${req.filter || '1'})\n           GROUP BY ${dims.join(', ') || '1'} ORDER BY SUM(Bytes) DESC LIMIT ${req.limit})\nSELECT time, SUM(Bytes * SamplingRate * 8) / ${step / 1000} AS xps,\n       if((${dims.join(', ') || "'Total'"}) IN rows, [${dims.map((d) => `toString(${d})`).join(', ') || "'Total'"}], [${dims.map(() => "'Other'").join(', ') || "'Total'"}]) AS dimensions\nFROM ${table}\nWHERE TimeReceived BETWEEN toDateTime('${req.start}') AND toDateTime('${req.end}') AND (${req.filter || '1'})\nGROUP BY time, dimensions\nORDER BY time WITH FILL STEP ${step / 1000}`,
  }
}

function sankey(req: VisualizeRequest): SankeyResult {
  const dims = req.dimensions.length >= 2 ? req.dimensions : [...req.dimensions, 'ExporterName'].slice(0, 2)
  const scale = SCALE[req.units] * filterFactor(req.filter) * 0.7
  const list = combos(dims, hash(dims.join(',') + req.filter + 's'), req.limit)
  // Akvorado keeps the top `limit` values of each dimension; the rest become Other.
  const keep = dims.map((_, i) => {
    const sums = new Map<string, number>()
    for (const c of list) sums.set(c.row[i], (sums.get(c.row[i]) ?? 0) + c.w)
    return new Set([...sums.entries()].sort((a, b) => b[1] - a[1]).slice(0, req.limit).map(([v]) => v))
  })
  const merged = new Map<string, number>()
  for (const c of list.slice(0, 300)) {
    const row = c.row.map((v, i) => (keep[i].has(v) ? v : 'Other'))
    const k = row.join('\u0000')
    merged.set(k, (merged.get(k) ?? 0) + c.w * scale)
  }
  const rows = [...merged.keys()].map((k) => k.split('\u0000'))
  const xps = [...merged.values()]
  const nodes = new Set<string>()
  const links = new Map<string, number>()
  rows.forEach((row, ri) => {
    for (let i = 0; i < row.length; i++) {
      nodes.add(`${dims[i]}: ${row[i]}`)
      if (i > 0) {
        const k = `${dims[i - 1]}: ${row[i - 1]}\u0000${dims[i]}: ${row[i]}`
        links.set(k, (links.get(k) ?? 0) + xps[ri])
      }
    }
  })
  return {
    rows,
    xps,
    nodes: [...nodes],
    links: [...links.entries()].map(([k, v]) => {
      const [source, target] = k.split('\u0000')
      return { source, target, xps: v }
    }),
    sql: `SELECT ${dims.join(', ')}, SUM(Bytes * SamplingRate * 8) / ${(Date.parse(req.end) - Date.parse(req.start)) / 1000} AS xps FROM flows_1m WHERE ${req.filter || '1'} GROUP BY ${dims.join(', ')} ORDER BY xps DESC`,
  }
}

function complete(req: CompleteRequest) {
  const p = req.prefix.replace(/^['"]/, '').toLowerCase()
  if (req.what === 'column') {
    return {
      completions: columns
        .filter((c) => !c.metric && c.name.toLowerCase().startsWith(p))
        .map((c) => ({ label: c.name, detail: c.kind, quoted: false })),
    }
  }
  const col = columns.find((c) => c.name.toLowerCase() === (req.column ?? '').toLowerCase())
  if (req.what === 'operator') {
    return { completions: operatorsFor(col?.kind ?? 'string').filter((o) => o.toLowerCase().startsWith(p)).map((o) => ({ label: o, detail: LIST_OPS.includes(o) ? 'list' : MATCH_OPS.includes(o) ? 'pattern' : 'comparison' })) }
  }
  if (!col) return { completions: [] }
  const quoted = col.kind === 'string' || col.kind === 'prefix'
  return {
    completions: valuesFor(col.name)
      .map(([v]) => (col.name.endsWith('AS') ? v.split(' ')[0] : col.name === 'Proto' ? v.toLowerCase() : v))
      .filter((v, i, a) => a.indexOf(v) === i && v.toLowerCase().startsWith(p))
      .slice(0, 30)
      .map((v) => ({ label: v, detail: col.name.endsWith('AS') ? valuesFor(col.name).find(([x]) => x.startsWith(v + ' '))?.[0].slice(v.length + 1) : undefined, quoted })),
  }
}

function flows(req: FlowsRequest) {
  const r = rng(hash(req.filter + req.start))
  const cols = ['TimeReceived', 'ExporterName', 'InIfName', 'OutIfName', 'SrcAddr', 'DstAddr', 'SrcAS', 'DstAS', 'SrcPort', 'DstPort', 'Proto', 'App', 'SrcCountry', 'DstCountry', 'InIfBoundary', 'InIfProvider', 'Bytes', 'Packets', 'SamplingRate']
  const pick = (c: string) => {
    const vals = valuesFor(c)
    return vals[Math.floor(r() ** 1.8 * vals.length)][0]
  }
  const end = Date.parse(req.end)
  const span = end - Date.parse(req.start)
  const rows = Array.from({ length: Math.min(req.limit, 1000) }, (_, i) => {
    const t = end - Math.floor((i / req.limit) * Math.min(span, 120e3)) - Math.floor(r() * 400)
    const packets = Math.floor(1 + r() ** 3 * 900)
    return cols.map((c) => {
      switch (c) {
        case 'TimeReceived':
          return new Date(t).toISOString()
        case 'Bytes':
          return packets * Math.floor(64 + r() * 1400)
        case 'Packets':
          return packets
        case 'SamplingRate':
          return 1000
        case 'SrcAS':
        case 'DstAS':
          return Number(pick(c).split(' ')[0].slice(2))
        case 'SrcPort':
          return r() < 0.5 ? Number(pick(c)) : 1024 + Math.floor(r() * 60000)
        case 'DstPort':
          return Number(pick(c))
        case 'Proto':
          return pick(c).toLowerCase()
        default:
          return pick(c)
      }
    })
  })
  if (req.order === 'bytes') rows.sort((a, b) => Number(b[16]) - Number(a[16]))
  return { columns: cols, rows }
}

function top(what: string) {
  const key: Record<string, string> = {
    'src-as': 'AS',
    'dst-as': 'AS',
    'src-country': 'Country',
    'dst-country': 'Country',
    app: 'App',
    exporter: 'Exporter',
    'src-port': 'Port',
    'dst-port': 'Port',
  }
  const list = values[key[what]]
  if (!list) return null
  const r = rng(hash(what))
  const w = list.map(([n, x]) => [n, x * (0.6 + r() * 0.8)] as const).sort((a, b) => b[1] - a[1])
  const total = w.reduce((a, [, x]) => a + x, 0)
  return { top: w.slice(0, 6).map(([name, x]) => ({ name: what.endsWith('port') ? `${name}` : name, percent: Math.round((x / total) * 1000) / 10 })) }
}

export async function handle(method: string, path: string, body: unknown): Promise<Reply> {
  const url = new URL(path, 'http://mock')
  const p = url.pathname
  await new Promise((r) => setTimeout(r, p.startsWith('/api/visualize') ? 260 + Math.random() * 200 : 60 + Math.random() * 80))

  if (p === '/api/version') return ok({ version: '0.1.0-mock', commit: 'mock', built_at: new Date().toISOString() })
  if (p.startsWith('/api/setup')) {
    if (!state.setupRequired) return fail(404, 'not_found')
    if (p === '/api/setup' && method === 'GET') return ok({ required: true, defaults: setupDefaults })
    const b = (body ?? {}) as Record<string, unknown>
    if (b.setup_code !== SETUP_CODE) return fail(401, 'setup_code_invalid', 'Mock mode: the code is 123456.')
    if (p === '/api/setup/check-code') return ok({ ok: true })
    if (p.startsWith('/api/setup/test/')) {
      await new Promise((r) => setTimeout(r, 450))
      return ok(setupTest(p.split('/').pop() ?? '', b))
    }
    if (p === '/api/setup' && method === 'POST') {
      await new Promise((r) => setTimeout(r, 900))
      state.setupRequired = false
      try {
        sessionStorage.removeItem('flow.mock.setup')
      } catch {
        // Nothing to clear.
      }
      state.signedIn = false
      return ok({ ok: true })
    }
  }
  if (p === '/api/auth/login') {
    const b = body as { username?: string; password?: string }
    if (!b.username || !b.password || b.password === 'wrong') return fail(401, 'invalid_credentials')
    state.signedIn = true
    return ok({ user, csrf: 'mock-csrf' })
  }
  if (p === '/api/auth/logout') {
    state.signedIn = false
    return { status: 204 }
  }
  if (state.setupRequired) return fail(503, 'setup_required')
  if (!state.signedIn) return fail(401, 'unauthenticated')
  if (p === '/api/auth/me') return ok({ user, csrf: 'mock-csrf' })
  if (p === '/api/schema') return ok({ columns })
  if (p === '/api/visualize') {
    const req = body as VisualizeRequest
    const v = validate(req.filter ?? '', columns)
    if (!v.valid) return fail(400, 'invalid_filter', v.errors[0].message)
    return ok(req.graph === 'sankey' ? sankey(req) : timeseries(req))
  }
  if (p === '/api/filter/validate') return ok(validate((body as { filter: string }).filter ?? '', columns))
  if (p === '/api/filter/complete') return ok(complete(body as CompleteRequest))
  if (p === '/api/saved-views' && method === 'GET') return ok({ results: state.savedViews })
  if (p === '/api/saved-views' && method === 'POST') {
    const b = body as Omit<SavedView, 'id' | 'owner'>
    const v = { ...b, id: `v${Date.now().toString(36)}`, owner: user.username }
    state.savedViews = [...state.savedViews, v]
    return ok(v)
  }
  if (p.startsWith('/api/saved-views/') && method === 'DELETE') {
    state.savedViews = state.savedViews.filter((v) => v.id !== p.split('/').pop())
    return { status: 204 }
  }
  if (p === '/api/exporters') return ok({ results: mockExporters })
  if (p === '/api/widgets/summary') {
    const ext = mockExporters.flatMap((e) => e.interfaces).filter((i) => i.boundary === 'external')
    return ok({
      flows_per_second: mockExporters.reduce((a, e) => a + e.flows_per_second, 0),
      exporters: mockExporters.length,
      bps_in_external: ext.reduce((a, i) => a + i.in_bps, 0),
      bps_out_external: ext.reduce((a, i) => a + i.out_bps, 0),
    })
  }
  if (p.startsWith('/api/widgets/top/')) {
    const r = top(p.split('/').pop() ?? '')
    return r ? ok(r) : fail(404, 'not_found')
  }
  if (p === '/api/widgets/graph') {
    const n = Number(url.searchParams.get('points') ?? 200)
    const end = Math.floor(Date.now() / 60e3) * 60e3
    const step = (24 * 3600e3) / n
    const r = rng(7)
    const t = Array.from({ length: n }, (_, i) => end - (n - 1 - i) * step)
    return ok({ t: t.map((x) => new Date(x).toISOString()), gbps: t.map((x) => Math.round(diurnal(x) * 182 * (0.96 + r() * 0.08) * 10) / 10) })
  }
  if (p === '/api/widgets/last-flow') {
    const f = flows({ start: new Date(Date.now() - 60e3).toISOString(), end: new Date().toISOString(), filter: String(Math.floor(Date.now() / 10e3)), limit: 1, order: 'time' })
    return ok(Object.fromEntries(f.columns.map((c, i) => [c, f.rows[0][i]])))
  }
  if (p === '/api/flows/search') return ok(flows(body as FlowsRequest))
  if (p === '/api/inventory-db' && method === 'GET') return ok(state.inventory)
  if (p === '/api/inventory-db' && method === 'PUT') {
    const b = body as { enabled: boolean; url: string; token?: string; interval: string }
    state.inventory = { ...state.inventory, enabled: b.enabled, url: b.url, interval: b.interval, token_set: state.inventory.token_set || !!b.token }
    return ok(state.inventory)
  }
  if (p === '/api/inventory-db/test') {
    if (!/^https?:\/\//.test(state.inventory.url)) return ok({ ok: false, error: 'URL must start with http:// or https://' })
    return ok({ ok: true })
  }
  if (p === '/api/inventory-db/sync') {
    const stats = { devices: 214 + Math.floor(Math.random() * 3), interfaces: 6812 + Math.floor(Math.random() * 20), prefixes: 1342, circuits: 38 }
    state.inventory = { ...state.inventory, last_sync: { at: new Date().toISOString(), ok: true, ...stats } }
    return ok({ ok: true, stats })
  }
  if (p === '/api/inventory-db/unknown') {
    return ok({
      exporters: [
        { address: '10.2.0.1', last_seen: new Date(Date.now() - 410e3).toISOString() },
        { address: '172.16.40.2', last_seen: new Date(Date.now() - 3 * 3600e3).toISOString() },
      ],
      addresses: [
        { address: '10.20.14.77', bytes: 48_213_000_000 },
        { address: '10.20.201.3', bytes: 12_840_000_000 },
        { address: '10.30.7.19', bytes: 5_120_000_000 },
        { address: '185.12.66.140', bytes: 2_310_000_000 },
        { address: '10.20.99.250', bytes: 640_000_000 },
      ],
    })
  }
  if (p === '/api/settings/openbao') {
    return ok({
      addr: 'http://openbao:8200',
      mount: 'flow',
      auth: 'approle',
      role_id: '6f1c2a9e-flow-role',
      status: { ok: true, version: '2.2.0', token_expires: new Date(Date.now() + 26 * 86400e3).toISOString(), renewable: true, policies: ['default', 'flow'] },
      secrets: 6,
    })
  }
  if (p === '/api/settings/openbao/test') return ok({ ok: true, details: { version: '2.2.0' } })
  if (p === '/api/classifiers' && method === 'GET') return ok(state.classifiers)
  if (p === '/api/classifiers' && method === 'PUT') {
    state.classifiers = body as Classifiers
    return ok(state.classifiers)
  }
  if (p === '/api/classifiers/preview') {
    // Same shape as the server (internal/classifier.PreviewResult).
    const b = body as { kind: string; rules: string[]; sample: Record<string, unknown> }
    const bad = b.rules.findIndex((r) => (r.match(/\(/g)?.length ?? 0) !== (r.match(/\)/g)?.length ?? 0))
    if (bad >= 0) return ok({ valid: false, errors: [{ kind: b.kind, index: bad, line: 1, column: b.rules[bad].length, offset: b.rules[bad].length, message: "Syntax error: missing ')'" }], steps: null })
    const name = String((b.sample as { name?: string }).name ?? '')
    const desc = String((b.sample as { description?: string }).description ?? '')
    if (b.kind === 'exporter') {
      const out = { role: name.startsWith('edge-') ? 'border' : '', site: name.includes('-msk-') ? 'MSK-DC1' : '', group: 'default' }
      return ok({ valid: true, errors: null, steps: b.rules.map((_, i) => ({ index: i, output: i === 0 ? out : {} })), exporter: { ...b.sample, ...out } })
    }
    const transit = desc.startsWith('Transit:')
    const out = { boundary: transit || desc.startsWith('IX:') ? 'external' : 'internal', connectivity: transit ? 'transit' : desc.startsWith('IX:') ? 'ix' : '', provider: transit ? desc.split(':')[1]?.trim().split(' ')[0] ?? '' : '' }
    const { exporter: _e, ...itf } = b.sample
    return ok({ valid: true, errors: null, steps: b.rules.map((_, i) => ({ index: i, output: i === 0 ? out : {} })), interface: { ...itf, ...out } })
  }
  return fail(404, 'not_found', `${method} ${p}`)
}
