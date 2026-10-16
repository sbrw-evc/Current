import type { Tone } from '../../ui/ui'

// Network devices (docs/devices.md, docs/api.md "Network devices"): the API shapes and the pure
// logic of the Devices, Device, Clients and Network map pages.

export type Transport = { name: string; port: number }
export type Platform = {
  key: string
  vendor: string
  title: string
  segment: 'home' | 'smb' | 'enterprise' | 'any'
  kind: string
  transports: Transport[]
  credentials: string[]
  hint: string
  aliases?: string[]
  capabilities: Record<string, string[]>
}
export type PlatformsView = {
  platforms: Platform[]
  actions: string[]
  action_titles: Record<string, string>
  admin_actions: string[]
  secret_fields: string[]
  roles: string[]
  flow_protocols: string[]
  snmp_auth_protocols: string[]
  snmp_priv_protocols: string[]
}

export type DeviceStatus = 'unknown' | 'up' | 'error' | 'down'
export type Facts = {
  hostname: string
  vendor: string
  model: string
  os: string
  version: string
  serial: string
  mac: string
  uptime_seconds: number | null
  cpu_percent: number | null
  memory_percent: number | null
}
export type CredentialView = {
  username: string
  snmp_version: string
  snmp_user: string
  snmp_auth_protocol: string
  snmp_priv_protocol: string
  snmp_source: 'own' | 'profile'
  set: Record<string, boolean>
}
export type Device = {
  id: number
  name: string
  platform: string
  platform_title: string
  vendor: string
  kind: string
  host: string
  port: number | null
  transport: string
  verify_tls: boolean
  controller_site: string
  inventory_id: number | null
  source_ref: string
  bound: boolean
  inventory_missing: boolean
  site: string
  role: string
  tags: string[]
  note: string
  enabled: boolean
  poll_seconds: number
  flow_exporter_ip: string
  ssh_host_key: string
  status: DeviceStatus
  failures: number
  last_poll_at: string | null
  last_ok_at: string | null
  last_error: string
  down_since: string | null
  alerted: boolean
  facts: Facts
  capabilities: string[]
  counts: { interfaces: number; interfaces_up: number; neighbors: number; children: number; endpoints: number }
  credentials: CredentialView
  exporter_ips: string[]
  created_by: string
  created_at: string
  updated_at: string
}
export type Iface = {
  name: string
  index: number | null
  description: string
  type: string
  mac: string
  admin_up: boolean | null
  oper_up: boolean | null
  speed_mbps: number | null
  mtu: number | null
  addresses: string[] | null
  rx_bytes: number | null
  tx_bytes: number | null
  vlan: number | null
  rx_bps: number | null
  tx_bps: number | null
  utilization: number | null
}
export type Neighbor = { local_interface: string; remote_name: string; remote_ip: string; remote_mac: string; remote_interface: string; remote_platform: string; protocol: string }
export type Child = { mac: string; name: string; model: string; kind: string; ip: string; online: boolean; version: string; uplink_mac: string; uplink_port: string; clients: number | null }
export type Collector = { address: string; ip: string; netflow_port: number; sflow_port: number; source: string }
export type Client = {
  mac: string
  ip: string
  hostname: string
  alias: string
  note: string
  vendor: string
  device_id: number | null
  device_name: string
  interface: string
  source: string
  attached_to: string
  port: string
  ssid: string
  signal: number | null
  vlan: number | null
  blocked: boolean
  first_seen: string
  last_seen: string
  name: string
  online: boolean
}
export type InventoryDevice = { id: number; name: string; ref: string; site: string; role: string; status: string; manufacturer: string; model: string; platform: string }
export type DeviceDetail = Device & {
  interfaces: Iface[]
  neighbors: Neighbor[]
  children: Child[]
  endpoints: Client[]
  collector: Collector
  platform_info?: Platform
  inventory?: InventoryDevice
  snmp_profile?: { id: string; name: string }
}
export type Candidate = { id: number; name: string; ref: string; site: string; role: string; status: string; manufacturer: string; model: string; platform: string; host: string; platform_guess: string }
export type Candidates = { connected: boolean; loaded: boolean; devices: Candidate[] }
export type Found = { host: string; reachable: boolean; ports: number[]; evidence: string[]; snmp: Record<string, string> | null; platforms: string[]; name: string; known: boolean; device_id?: number }
export type TestResult = { ok: boolean; facts: Facts; interfaces: number; neighbors: number; endpoints: number; children: number; host_key: string }
export type ActionResult = { ok: boolean; output: string }
export type DeviceSettings = { collector_address: string; netflow_port: number; sflow_port: number; endpoint_offline_minutes: number; endpoint_retention_days: number; concurrency: number }

export type NodeType = 'device' | 'child' | 'neighbor' | 'endpoint' | 'internet'
export type TopoNode = {
  id: string
  type: NodeType
  label: string
  role?: string
  status: string
  vendor?: string
  model?: string
  ip?: string
  mac?: string
  device_id?: number
  platform?: string
  site?: string
  x?: number | null
  y?: number | null
  clients: number
  interfaces?: number
  error?: string
  controller?: string
  platform_guess?: string
  ssid?: string
  signal?: number | null
  blocked?: boolean
  parent?: string
}
export type EdgeKind = 'link' | 'managed' | 'wired' | 'wifi' | 'wan'
export type TopoEdge = { source: string; target: string; kind: EdgeKind; source_port?: string; target_port?: string; protocol?: string; label?: string; bps?: number | null; utilization?: number | null; speed_mbps?: number | null }
export type Topology = { nodes: TopoNode[]; edges: TopoEdge[]; stats: { devices: number; children: number; neighbors: number; endpoints: number; online: number; down: number }; generated_at: string }

// ---------- status, labels ----------

export const statusTone = (s: string): Tone =>
  s === 'up' || s === 'online' ? 'ok' : s === 'error' ? 'warn' : s === 'down' ? 'error' : s === 'offline' ? 'off' : 'low'

export const SOURCE_RANK: Record<string, number> = { wifi: 5, controller: 4, bridge: 3, dhcp: 2, arp: 1 }

// deviceCounts summarises the list for the tiles.
export function deviceCounts(list: Device[]) {
  return {
    total: list.length,
    up: list.filter((d) => d.status === 'up').length,
    down: list.filter((d) => d.status === 'down').length,
    error: list.filter((d) => d.status === 'error').length,
    clients: list.reduce((a, d) => a + d.counts.endpoints, 0),
  }
}

// matchDevice: the search box of the list.
export function matchDevice(d: Device, q: string) {
  const s = q.trim().toLowerCase()
  if (!s) return true
  return [d.name, d.host, d.site, d.role, d.platform_title, d.vendor, d.facts.model, d.facts.hostname, ...d.tags].some((v) => (v ?? '').toLowerCase().includes(s))
}

export function matchClient(c: Client, q: string) {
  const s = q.trim().toLowerCase()
  if (!s) return true
  return [c.mac, c.ip, c.hostname, c.alias, c.vendor, c.device_name, c.ssid, c.note].some((v) => (v ?? '').toLowerCase().includes(s))
}

export function uptimeText(sec: number | null | undefined, locale: 'en' | 'ru') {
  if (sec == null) return '—'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const u = locale === 'ru' ? { d: 'д', h: 'ч', m: 'мин' } : { d: 'd', h: 'h', m: 'min' }
  if (d > 0) return `${d} ${u.d} ${h} ${u.h}`
  if (h > 0) return `${h} ${u.h} ${m} ${u.m}`
  return `${m} ${u.m}`
}

// ---------- the device form ----------

export type DeviceDraft = {
  inventory_id: number | null
  platform: string
  host: string
  port: string
  transport: string
  verify_tls: boolean
  controller_site: string
  name: string
  site: string
  role: string
  tags: string
  note: string
  enabled: boolean
  poll_seconds: number
  flow_exporter_ip: string
  snmp_source: 'own' | 'profile'
  plain: Record<string, string>
  secrets: Record<string, string>
  clear: string[]
}

export const PLAIN_FIELDS = ['username', 'snmp_version', 'snmp_user', 'snmp_auth_protocol', 'snmp_priv_protocol']
export const SNMP_FIELDS = ['snmp_version', 'snmp_community', 'snmp_user', 'snmp_auth_protocol', 'snmp_auth_password', 'snmp_priv_protocol', 'snmp_priv_password']

export function emptyDraft(platform = ''): DeviceDraft {
  return {
    inventory_id: null,
    platform,
    host: '',
    port: '',
    transport: '',
    verify_tls: false,
    controller_site: '',
    name: '',
    site: '',
    role: '',
    tags: '',
    note: '',
    enabled: true,
    poll_seconds: 300,
    flow_exporter_ip: '',
    snmp_source: 'own',
    plain: {},
    secrets: {},
    clear: [],
  }
}

export function draftOf(d: Device): DeviceDraft {
  const c = d.credentials
  return {
    ...emptyDraft(d.platform),
    inventory_id: d.inventory_id,
    host: d.host,
    port: d.port ? String(d.port) : '',
    transport: d.transport,
    verify_tls: d.verify_tls,
    controller_site: d.controller_site,
    name: d.name,
    site: d.site,
    role: d.role,
    tags: d.tags.join(', '),
    note: d.note,
    enabled: d.enabled,
    poll_seconds: d.poll_seconds,
    flow_exporter_ip: d.flow_exporter_ip,
    snmp_source: c.snmp_source,
    plain: { username: c.username, snmp_version: c.snmp_version, snmp_user: c.snmp_user, snmp_auth_protocol: c.snmp_auth_protocol, snmp_priv_protocol: c.snmp_priv_protocol },
  }
}

// fromCandidate fills the form from an Inventory DB device.
export function fromCandidate(c: Candidate, platforms: Platform[]): DeviceDraft {
  const p = platforms.find((x) => x.key === c.platform_guess)
  return { ...emptyDraft(p?.key ?? ''), inventory_id: c.id, host: c.host, name: c.name, site: c.site, role: c.role, transport: p?.transports[0]?.name ?? '' }
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const HOST = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/
export const isIP = (s: string) => IPV4.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.split('::').length <= 2)
export const isHost = (s: string) => isIP(s) || HOST.test(s)

// validateDraft lists the problems (string keys) that keep the form from being sent.
export function validateDraft(d: DeviceDraft, opts: { inventory: boolean; creating: boolean; platform?: Platform }): string[] {
  const out: string[] = []
  if (!d.platform) out.push('form.err.platform')
  if (!isHost(d.host.trim())) out.push('form.err.host')
  if (d.port.trim() && !(Number.isInteger(Number(d.port)) && Number(d.port) >= 1 && Number(d.port) <= 65535)) out.push('form.err.port')
  if (d.poll_seconds < 60 || d.poll_seconds > 86400) out.push('form.err.poll')
  if (d.flow_exporter_ip.trim() && !isIP(d.flow_exporter_ip.trim())) out.push('form.err.exporter')
  if (opts.inventory && opts.creating && !d.inventory_id) out.push('form.err.inventory')
  if (opts.platform && d.transport && !opts.platform.transports.some((t) => t.name === d.transport)) out.push('form.err.transport')
  return out
}

// inputOf is the API body of the form: secrets only when typed (an empty one keeps the stored
// value), name / site / role only for a standalone device.
export function inputOf(d: DeviceDraft, opts: { bound: boolean; creating: boolean }) {
  const credentials: Record<string, string> = {}
  for (const k of PLAIN_FIELDS) if (d.plain[k] !== undefined) credentials[k] = d.plain[k].trim()
  for (const [k, v] of Object.entries(d.secrets)) if (v !== '') credentials[k] = v
  const body: Record<string, unknown> = {
    platform: d.platform,
    host: d.host.trim(),
    port: d.port.trim() ? Number(d.port) : 0,
    transport: d.transport,
    verify_tls: d.verify_tls,
    controller_site: d.controller_site.trim(),
    tags: d.tags.split(',').map((x) => x.trim()).filter(Boolean),
    note: d.note,
    enabled: d.enabled,
    poll_seconds: d.poll_seconds,
    flow_exporter_ip: d.flow_exporter_ip.trim(),
    snmp_source: d.snmp_source,
    credentials,
  }
  if (d.inventory_id && opts.creating) body.inventory_id = d.inventory_id
  if (!opts.bound && !d.inventory_id) {
    body.name = d.name.trim()
    body.site = d.site.trim()
    if (d.role) body.role = d.role
  }
  if (!opts.creating && d.clear.length) body.clear_credentials = d.clear
  return body
}

// credentialFields: the fields of the form for a platform and transport (SNMP fields only for the
// snmp transport or platforms polled over SNMP, and none when a Flow SNMP profile is used).
export function credentialFields(p: Platform | undefined, transport: string, snmpSource: 'own' | 'profile') {
  if (!p) return []
  const snmp = transport === 'snmp'
  return p.credentials.filter((f) => {
    const isSnmp = SNMP_FIELDS.includes(f)
    if (isSnmp && snmpSource === 'profile') return false
    return snmp ? isSnmp : !isSnmp
  })
}

// visibleActions: the actions offered on the device page for the capabilities and permissions.
export function visibleActions(caps: string[], admin: string[], can: { operate: boolean; admin: boolean }) {
  return caps.filter((a) => (admin.includes(a) ? can.admin : can.operate || can.admin) && a !== 'endpoint_block' && a !== 'backup')
}

// ---------- the network map ----------

const ROLE_SYMBOL: Record<string, string> = { router: 'roundRect', firewall: 'diamond', gateway: 'roundRect', switch: 'rect', ap: 'triangle', controller: 'pin' }

export type GraphNode = { id: string; name: string; value: string; category: number; symbol: string; symbolSize: number; x?: number; y?: number; fixed?: boolean; itemStyle: { color: string; borderColor?: string; borderWidth?: number }; label: { show: boolean } }
export type GraphLink = { source: string; target: string; value: string; lineStyle: { width: number; type: 'solid' | 'dashed' | 'dotted'; color: string; opacity: number } }

export const NODE_COLORS = { up: '#16a34a', error: '#d97706', down: '#dc2626', unknown: '#64748b', online: '#0ea5e9', offline: '#94a3b8', internet: '#7c3aed', neighbor: '#64748b' }

export function nodeColor(n: TopoNode) {
  if (n.type === 'internet') return NODE_COLORS.internet
  if (n.type === 'neighbor') return NODE_COLORS.neighbor
  if (n.type === 'endpoint') return n.status === 'online' ? NODE_COLORS.online : NODE_COLORS.offline
  return NODE_COLORS[n.status as 'up' | 'error' | 'down'] ?? NODE_COLORS.unknown
}

// edgeWidth: links get thicker with their utilization (1–6 px).
export function edgeWidth(e: TopoEdge) {
  if (e.kind === 'wifi' || e.kind === 'wired') return 1
  if (e.kind === 'managed') return 1
  const u = e.utilization ?? 0
  return Math.round((1.5 + Math.min(100, Math.max(0, u)) / 25) * 10) / 10
}

export const edgeColor = (e: TopoEdge) => ((e.utilization ?? 0) >= 85 ? '#dc2626' : (e.utilization ?? 0) >= 60 ? '#d97706' : '#94a3b8')

export function graphOf(t: Topology, opts: { clients: boolean; labels: boolean }): { nodes: GraphNode[]; links: GraphLink[] } {
  const keep = (n: TopoNode) => opts.clients || n.type !== 'endpoint'
  const nodes = t.nodes.filter(keep).map((n): GraphNode => {
    const big = n.type === 'device' || n.type === 'internet'
    const g: GraphNode = {
      id: n.id,
      name: n.label,
      value: n.ip ?? '',
      category: ['device', 'child', 'neighbor', 'endpoint', 'internet'].indexOf(n.type),
      symbol: n.type === 'internet' ? 'circle' : n.type === 'endpoint' ? 'circle' : ROLE_SYMBOL[n.role ?? ''] ?? 'circle',
      symbolSize: big ? 34 : n.type === 'endpoint' ? 10 : 22,
      itemStyle: { color: nodeColor(n), ...(n.blocked ? { borderColor: '#dc2626', borderWidth: 2 } : {}) },
      label: { show: opts.labels && n.type !== 'endpoint' },
    }
    if (n.x != null && n.y != null) {
      g.x = n.x
      g.y = n.y
      g.fixed = true
    }
    return g
  })
  const ids = new Set(nodes.map((n) => n.id))
  const links = t.edges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e): GraphLink => ({
      source: e.source,
      target: e.target,
      value: [e.source_port, e.target_port].filter(Boolean).join(' ↔ '),
      lineStyle: { width: edgeWidth(e), type: e.kind === 'wifi' ? 'dashed' : e.kind === 'managed' || e.kind === 'wan' ? 'dotted' : 'solid', color: edgeColor(e), opacity: e.kind === 'wired' || e.kind === 'wifi' ? 0.5 : 0.9 },
    }))
  return { nodes, links }
}

// positionsOf: what PUT /api/topology/positions stores after a drag (devices only).
export function positionsOf(moved: { id: string; x: number; y: number }[]): Record<string, [number, number]> {
  const out: Record<string, [number, number]> = {}
  for (const m of moved) if (m.id.startsWith('dev:') && Number.isFinite(m.x) && Number.isFinite(m.y)) out[m.id] = [Math.round(m.x), Math.round(m.y)]
  return out
}
