import type { ApiToken, IssuedToken, ServiceAccount } from '../pages/settings/ApiTokensModel'
import { roles, rolesMock } from './roles'
import type { SpaView } from '../pages/spa/model'
import type { InventoryIntegration } from '../pages/settings/InventoryDbModel'
import type { ThreatList, ThreatView } from '../pages/settings/ThreatModel'
import type { RdnsSettings, RdnsView } from '../pages/settings/RdnsModel'
import type { FlowLogsView, Provider } from '../pages/settings/FlowLogsModel'
import type { Dependencies, DependencyRun, Proposal, ScopeView, UmbrellaAPI } from '../api/umbrella'

// Mock handlers (VITE_MOCK=1) of the settings added after the first console: API tokens and
// service accounts, SPA (sign-in and people), moving OpenBao, the Inventory DB integration, the Umbrella API
// connection, visibility scope and dependencies, threat intelligence, reverse DNS and cloud flow
// logs. Secrets are write-only, as on the server: only *_set flags come back.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown, status = 200): Reply => ({ status, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })
const now = () => new Date().toISOString()
const ago = (ms: number) => new Date(Date.now() - ms).toISOString()

const spaUsers = [
  { id: 1, username: 'admin', name: 'Administrator', email: 'admin@example.net', source: 'spa', role: 'Administrator', role_ident: 'admin', disabled: false, last_login_at: ago(60e3) },
  { id: 2, username: 'noc', name: 'NOC engineer', email: 'noc@example.net', source: 'spa', role: 'NOC (Umbrella scope)', role_ident: 'noc-umbrella-scope', disabled: false, last_login_at: ago(3 * 3600e3) },
  { id: 3, username: 'jdoe', name: 'John Doe', email: 'jdoe@example.net', source: 'legacy', role: 'Viewer', role_ident: 'viewer', disabled: true },
]

function spaView(): SpaView {
  return {
    connected: true, key_source: 'env', redirect_uri: 'https://flow.example.net/api/auth/spa/callback', post_logout_redirect_uri: 'https://flow.example.net/',
    issuer: 'https://spa.example.net', client_id: 'app_7f3c', application: { id: 'app_7f3c', name: 'Umbrella Flow', type: 'umbrella-flow' },
    account_url: 'https://spa.example.net/profile', sign_out_url: 'https://spa.example.net/oauth2/logout',
    methods: [{ id: 'passkey', title: 'Passkey' }, { id: 'ldap', title: 'Active Directory' }, { id: 'password', title: 'Password' }],
    last_sync: state.spaSynced, ok: true, users: 2, created: 0, updated: 2, bound: 0, disabled: 0, conflicts: [], no_role: [],
    catalogue: { at: ago(86400e3), roles: roles.length }, counts: { enabled: 2, disabled: 1, legacy: 1 },
    roles: roles.map((r) => ({ id: r.ident, name: r.name, description: r.description || undefined })),
    interval: '5m0s',
  }
}

const DEFAULT_LISTS: ThreatList[] = [
  { name: 'firehol_level1', url: 'https://iplists.firehol.org/files/firehol_level1.netset', enabled: true, terms: 'https://iplists.firehol.org/' },
  { name: 'spamhaus_drop', url: 'https://www.spamhaus.org/drop/drop_v4.json', enabled: true, terms: 'https://www.spamhaus.org/drop/' },
  { name: 'spamhaus_drop_v6', url: 'https://www.spamhaus.org/drop/drop_v6.json', enabled: true, terms: 'https://www.spamhaus.org/drop/' },
  { name: 'feodo', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', enabled: true, terms: 'https://abuse.ch/' },
]

const proposal = (from: [number, string, string], to: [number, string, string], port: number, app: string, bytes: number, flows: number, days: number): Proposal => ({
  key: `flow:inventory-db:dcim.device:${from[0]}->inventory-db:dcim.device:${to[0]}:tcp/${port}`,
  from: { source_ref: `inventory-db:dcim.device:${from[0]}`, name: from[1], ip: from[2] },
  to: { source_ref: `inventory-db:dcim.device:${to[0]}`, name: to[1], ip: to[2] },
  type: 'depends_on',
  evidence: { protocol: 'tcp', port, app, bytes_7d: bytes, flows_7d: flows, days_seen: days, first_seen: ago(days * 86400e3), last_seen: ago(120e3), flow_url: '/visualize' },
})

const PROPOSALS: Proposal[] = [
  proposal([101, 'app-01', '10.20.1.11'], [201, 'db-01', '10.20.2.21'], 5432, 'postgres', 182e9, 48210, 7),
  proposal([102, 'app-02', '10.20.1.12'], [201, 'db-01', '10.20.2.21'], 5432, 'postgres', 96e9, 31877, 7),
  proposal([101, 'app-01', '10.20.1.11'], [301, 'cache-01', '10.20.3.5'], 6379, 'redis', 41e9, 120400, 6),
  proposal([401, 'web-01', '10.20.0.10'], [101, 'app-01', '10.20.1.11'], 8443, 'https', 12e9, 9120, 5),
]

const run = (id: number, ms: number, dry: boolean, accepted: number): DependencyRun => ({
  id,
  trigger: dry ? 'manual' : 'schedule',
  actor: dry ? 'admin' : '',
  dry_run: dry,
  started_at: ago(ms),
  finished_at: ago(ms - 4000),
  ok: true,
  error: '',
  pairs: PROPOSALS.length,
  sent: dry ? 0 : PROPOSALS.length,
  accepted,
  updated: dry ? 0 : PROPOSALS.length - accepted,
  ignored: 0,
  params: { days: 7, min_flows: 100, min_days: 3, limit: 500 },
})

const state = {
  accounts: [
    { id: 1, name: 'inventory-db', description: 'Inventory DB: traffic chips and prefix addresses', role_id: 3, role: 'Inventory DB integration', disabled: false, tokens: 1, created_by: 'admin', created_at: ago(20 * 86400e3), updated_at: ago(20 * 86400e3) },
  ] as ServiceAccount[],
  tokens: [
    { id: 1, service_account_id: 1, service_account: 'inventory-db', name: 'production', display: 'flow_Xq7R…', expires_at: null, last_used_at: ago(40e3), last_used_from: '10.10.0.21', created_by: 'admin', created_at: ago(20 * 86400e3), revoked_at: null, revoked_by: '', active: true },
  ] as ApiToken[],
  spaSynced: ago(120e3),
  inventoryIntegration: { hook_secret_set: true, write_token_set: false, hook_url: 'https://flow.example.net/api/integrations/inventory-db/hook', inventory_url: 'https://inventory.example.net' } as InventoryIntegration,
  umbrellaApi: { url: 'https://umbrella.example.net', token_set: true } as UmbrellaAPI,
  deps: {
    settings: { enabled: true, hour: 3, min_flows: 100, min_days: 3, max_proposals: 500 },
    runs: [run(2, 3600e3, true, 0), run(1, 26 * 3600e3, false, 3)],
  },
  threat: {
    settings: { enabled: true, lists: DEFAULT_LISTS, refresh_minutes: 360, exclude: ['198.51.100.0/24'] },
    status: {
      updated_at: ago(42 * 60e3),
      prefixes: 9132,
      lists: DEFAULT_LISTS.map((l, i) => ({ name: l.name, url: l.url, enabled: true, prefixes: [4511, 1484, 83, 3054][i], skipped: i === 0 ? 12 : 0, updated_at: ago(42 * 60e3), checked_at: ago(42 * 60e3), error: i === 3 ? undefined : undefined })),
    },
    default_lists: DEFAULT_LISTS,
  } as ThreatView,
  rdns: {
    enabled: true,
    servers: ['10.10.0.53', '10.10.1.53'],
    scope: 'private',
    workers: 8,
    rate_limit: 200,
    positive_ttl: 3600,
    negative_ttl: 600,
    timeout_ms: 2000,
    cache_size: 100000,
    queue_size: 10000,
  } as RdnsSettings,
  flowlogs: {
    available: true,
    public_url: 'https://flow.example.net',
    aws: { enabled: true, token_set: true, endpoint: '/api/ingest/flowlogs/aws', url: 'https://flow.example.net/api/ingest/flowlogs/aws' },
    azure: { enabled: false, token_set: false, endpoint: '/api/ingest/flowlogs/azure', url: 'https://flow.example.net/api/ingest/flowlogs/azure' },
    gcp: { enabled: false, token_set: false, endpoint: '/api/ingest/flowlogs/gcp', url: 'https://flow.example.net/api/ingest/flowlogs/gcp' },
  } as FlowLogsView,
}

function depsView(): Dependencies {
  const last = state.deps.runs[0] ?? null
  return {
    settings: state.deps.settings,
    configured: state.umbrellaApi.token_set && !!state.umbrellaApi.url,
    available: true,
    running: false,
    next_run: state.deps.settings.enabled ? new Date(Math.ceil(Date.now() / 86400e3) * 86400e3 + state.deps.settings.hour * 3600e3).toISOString() : null,
    last_run: last,
    runs: state.deps.runs,
    proposals: PROPOSALS,
  }
}

function rdnsView(): RdnsView {
  return {
    settings: state.rdns,
    stats: { enabled: state.rdns.enabled, cached: 18234, queued: 3, hits: 912_400, misses: 21_870, dropped: 0, found: 16_902, not_found: 4_811, errors: 157 },
  }
}

const scope: ScopeView = { restricted: false, ok: true, configured: true, known: true, mode: 'all', cis: 0, services: 0, refs: 0, addresses: 0, checked_at: now() }

function randomToken() {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  return 'flow_' + Array.from({ length: 43 }, () => a[Math.floor(Math.random() * a.length)]).join('')
}

// extensionsMock answers the paths it knows, null otherwise.
export function extensionsMock(method: string, p: string, body: unknown): Reply | null {
  const b = (body ?? {}) as Record<string, unknown>
  // ---- roles, service accounts and API tokens
  const rolesReply = rolesMock(method, p, body)
  if (rolesReply) return rolesReply
  if (p === '/api/service-accounts' && method === 'GET') return ok({ results: state.accounts.map((a) => ({ ...a, tokens: state.tokens.filter((x) => x.service_account_id === a.id && x.active).length })) })
  if (p === '/api/service-accounts' && method === 'POST') {
    const name = String(b.name ?? '').trim()
    if (!/^[^\s/]{1,64}$/.test(name)) return fail(400, 'invalid_name', 'name: 1-64 characters, no spaces or /')
    if (state.accounts.some((a) => a.name === name)) return fail(409, 'conflict', 'the name is taken')
    const role = roles.find((r) => r.id === Number(b.role_id))
    if (!role) return fail(400, 'invalid_role', 'unknown role')
    const a: ServiceAccount = { id: Math.max(0, ...state.accounts.map((x) => x.id)) + 1, name, description: String(b.description ?? ''), role_id: role.id, role: role.name, disabled: false, tokens: 0, created_by: 'admin', created_at: now(), updated_at: now() }
    state.accounts.push(a)
    return ok(a, 201)
  }
  if (p.startsWith('/api/service-accounts/') && method === 'DELETE') {
    const id = Number(p.split('/').pop())
    state.accounts = state.accounts.filter((a) => a.id !== id)
    state.tokens = state.tokens.filter((x) => x.service_account_id !== id)
    return ok({ ok: true })
  }
  if (p === '/api/tokens' && method === 'GET') return ok({ results: [...state.tokens].sort((x, y) => y.id - x.id) })
  if (p === '/api/tokens' && method === 'POST') {
    const a = state.accounts.find((x) => x.id === Number(b.service_account_id))
    if (!a) return fail(400, 'invalid_service_account', 'unknown service account')
    const exp = String(b.expires_at ?? '')
    if (exp && !(Date.parse(exp) > Date.now())) return fail(400, 'invalid_expiry', 'the expiry must be in the future')
    const token = randomToken()
    const v: IssuedToken = { id: Math.max(0, ...state.tokens.map((x) => x.id)) + 1, service_account_id: a.id, service_account: a.name, name: String(b.name ?? ''), display: token.slice(0, 9) + '…', expires_at: exp ? new Date(exp).toISOString() : null, last_used_at: null, last_used_from: '', created_by: 'admin', created_at: now(), revoked_at: null, revoked_by: '', active: true, token }
    const { token: _plain, ...stored } = v
    state.tokens.push(stored)
    return ok(v, 201)
  }
  if (p.startsWith('/api/tokens/') && method === 'DELETE') {
    const t = state.tokens.find((x) => x.id === Number(p.split('/').pop()))
    if (!t) return fail(404, 'not_found')
    Object.assign(t, { revoked_at: now(), revoked_by: 'admin', active: false })
    return ok(t)
  }
  // ---- SPA and the people it gives Flow
  if (p === '/api/settings/spa' && method === 'GET') return ok(spaView())
  if (p === '/api/settings/spa/sync' && method === 'POST') {
    state.spaSynced = now()
    return ok(spaView())
  }
  if (p === '/api/users' && method === 'GET') return ok({ results: spaUsers })
  // ---- OpenBao move
  if (p === '/api/settings/openbao/probe') {
    const addr = String(b.addr ?? '')
    if (!/^https?:\/\//.test(addr)) return ok({ ok: false, error: 'addr must start with http:// or https://', secrets: 0 })
    const same = addr.replace(/\/$/, '') === 'http://openbao:8200' && (b.mount ?? 'flow') === 'flow'
    return ok({ ok: true, secrets: addr.includes('used') ? 4 : 0, same, status: { version: '2.5.0' } })
  }
  if (p === '/api/settings/openbao/migrate') {
    const target = (b.target ?? {}) as { addr?: string; mount?: string }
    if (String(target.addr ?? '').replace(/\/$/, '') === 'http://openbao:8200' && (target.mount ?? 'flow') === 'flow') return fail(400, 'openbao_same_store', 'the target is the current OpenBao mount')
    if (String(target.addr ?? '').includes('used') && !b.overwrite) return fail(409, 'openbao_target_not_empty', 'the target mount has secrets')
    return ok({ addr: target.addr, mount: target.mount || 'flow', copied: 14, refs: 9 })
  }
  // ---- Inventory DB integration
  if (p === '/api/inventory-db/integration' && method === 'GET') return ok(state.inventoryIntegration)
  if (p === '/api/inventory-db/integration' && method === 'PUT') {
    const i = state.inventoryIntegration
    if (typeof b.hook_secret === 'string') i.hook_secret_set = b.hook_secret !== ''
    if (typeof b.write_token === 'string') i.write_token_set = b.write_token !== ''
    return ok(i)
  }
  if (p === '/api/inventory-db/unknown/create') {
    if (!state.inventoryIntegration.write_token_set) return fail(409, 'write_token_required', 'no Inventory DB editor token')
    const address = String(b.address ?? '')
    return ok({ ok: true, address, object: { id: 9000 + Math.floor(Math.random() * 999), address: `${address}/32`, display: `${address}/32`, display_url: `${state.inventoryIntegration.inventory_url}/ipam/ip-addresses` } }, 201)
  }
  // ---- Umbrella API, scope and dependencies
  if (p === '/api/settings/umbrella/api' && method === 'GET') return ok(state.umbrellaApi)
  if (p === '/api/settings/umbrella/api' && method === 'PUT') {
    if (typeof b.url === 'string') state.umbrellaApi.url = b.url.replace(/\/+$/, '').replace(/\/api$/, '')
    if (typeof b.token === 'string') state.umbrellaApi.token_set = b.token !== ''
    return ok(state.umbrellaApi)
  }
  if (p === '/api/settings/umbrella/api/test') {
    if (!state.umbrellaApi.token_set && !b.token) return ok({ ok: false, error: 'no Umbrella service-account token' })
    return ok({ ok: true, details: { restricted: false, known: true, mode: 'all', cis: 0, services: 0, refs: 0, addresses: 0 } })
  }
  if (p === '/api/umbrella/scope') return ok({ ...scope, configured: state.umbrellaApi.token_set, checked_at: now() })
  if (p === '/api/dependencies' && method === 'GET') return ok(depsView())
  if (p === '/api/dependencies/settings' && method === 'PUT') {
    state.deps.settings = { ...state.deps.settings, ...(b as object) }
    return ok(depsView())
  }
  if (p === '/api/dependencies/run') {
    const dry = b.dry_run === true
    const r = { ...run(Math.max(...state.deps.runs.map((x) => x.id)) + 1, 4000, dry, dry ? 0 : 1), trigger: 'manual' as const, actor: 'admin' }
    state.deps.runs = [r, ...state.deps.runs].slice(0, 50)
    return ok({ run: r, proposals: PROPOSALS })
  }
  // ---- threat intelligence
  if (p === '/api/settings/threat' && method === 'GET') return ok(state.threat)
  if (p === '/api/settings/threat' && method === 'PUT') {
    const s = b as unknown as ThreatView['settings']
    if (!Array.isArray(s.lists)) return fail(400, 'threat_invalid', 'lists are required')
    state.threat = { ...state.threat, settings: { ...s, refresh_requested_at: state.threat.settings.refresh_requested_at } }
    return ok(state.threat)
  }
  if (p === '/api/settings/threat/refresh') {
    const at = now()
    state.threat.settings = { ...state.threat.settings, refresh_requested_at: at }
    return ok({ requested_at: at }, 202)
  }
  // ---- reverse DNS
  if (p === '/api/settings/rdns' && method === 'GET') return ok(rdnsView())
  if (p === '/api/settings/rdns' && method === 'PUT') {
    const s = b as unknown as RdnsSettings
    if (!['all', 'private', 'public'].includes(s.scope)) return fail(400, 'rdns_invalid', 'scope is all, private or public')
    state.rdns = { ...state.rdns, ...s }
    return ok(rdnsView())
  }
  // ---- cloud flow logs
  if (p === '/api/settings/flowlogs' && method === 'GET') return ok(state.flowlogs)
  if (p === '/api/settings/flowlogs' && method === 'PUT') {
    for (const name of ['aws', 'azure', 'gcp'] as Provider[]) {
      const inp = b[name] as { enabled: boolean; token?: string } | undefined
      if (!inp) continue
      const cur = state.flowlogs[name]
      if (typeof inp.token === 'string' && inp.token !== '' && inp.token.length < 16) return fail(400, 'flowlogs_invalid', `${name}: the token must have at least 16 characters`)
      const tokenSet = typeof inp.token === 'string' ? inp.token !== '' : cur.token_set
      if (inp.enabled && !tokenSet) return fail(400, 'flowlogs_invalid', `${name}: a token is required to enable ingestion`)
      state.flowlogs = { ...state.flowlogs, [name]: { ...cur, enabled: inp.enabled, token_set: tokenSet } }
    }
    return ok(state.flowlogs)
  }
  return null
}
