import { validate } from '../filter/parse'
import { KIND_SPECS, parseDuration, type AlertState, type DetectorStatus, type Rule, type RulesView } from '../pages/detector/model'
import { columns } from './schema'

// Mock handlers of the detector API, the Beacon settings used by the status page and the
// sampling overrides (VITE_MOCK=1). Rules are checked like detector.ValidateRule.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown): Reply => ({ status: 200, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })

export const DEFAULT_RULES: Rule[] = [
  { id: 'link-utilization', name: 'Interface utilization', enabled: true, kind: 'link_utilization', thresholds: { percent: 85 }, window: '1m', for: '5m', interval: '1m', hysteresis: '5m', severity: 'warning' },
  { id: 'link-commit', name: '95th percentile above commit', enabled: true, kind: 'link_commit', thresholds: { percent: 100 }, interval: '15m', hysteresis: '1h', severity: 'warning' },
  { id: 'ddos-volumetric', name: 'Volumetric DDoS', enabled: true, kind: 'ddos_volumetric', filter: "InIfBoundary = 'external'", thresholds: { bps: 1e9, pps: 100000 }, window: '1m', for: '1m', interval: '30s', hysteresis: '5m', severity: 'critical', baseline: { window: '1h', k: 3 } },
  { id: 'ddos-syn', name: 'SYN flood', enabled: true, kind: 'ddos_syn', filter: "InIfBoundary = 'external'", thresholds: { ratio: 0.5, pps: 10000 }, window: '1m', for: '1m', interval: '30s', hysteresis: '5m', severity: 'error' },
  { id: 'traffic-anomaly', name: 'Traffic anomaly on external interfaces', enabled: true, kind: 'traffic_anomaly', filter: "InIfBoundary = 'external'", dimensions: ['ExporterName', 'InIfName'], thresholds: {}, window: '15m', for: '15m', interval: '5m', hysteresis: '15m', severity: 'warning', baseline: { weeks: 4, min_samples: 2, k: 3, ratio: 0.5, min_volume: 10e6, direction: 'up' } },
  { id: 'traffic-drop', name: 'Service traffic drop', enabled: true, kind: 'traffic_drop', filter: "DstCI != ''", dimensions: ['DstCI'], thresholds: { ratio: 0.1 }, window: '15m', for: '15m', interval: '5m', hysteresis: '15m', severity: 'error', baseline: { weeks: 4, min_samples: 2, min_volume: 1e6 } },
  { id: 'exporter-silent', name: 'Silent exporter', enabled: true, kind: 'exporter_silent', thresholds: { silence: '10m' }, interval: '1m', hysteresis: '1m', severity: 'low' },
  { id: 'threat-contact', name: 'Contact with a threat list address', enabled: true, kind: 'threat_contact', thresholds: {}, window: '5m', interval: '1m', hysteresis: '30m', severity: 'error' },
]

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T

const state = {
  rules: [
    // saved before threat-contact existed: the console offers it as a new built-in rule
    ...clone(DEFAULT_RULES.filter((r) => r.id !== 'threat-contact')),
    { id: 'dns-amplification', name: 'DNS responses from outside', enabled: false, kind: 'custom', filter: "InIfBoundary = 'external' AND SrcPort = 53 AND Proto = udp", dimensions: ['DstAddr'], thresholds: { bps: 200e6 }, window: '1m', for: '2m', interval: '30s', severity: 'error', signal: 'red.traffic.dns', metric: 'bps', operator: '>' },
  ] as Rule[],
  saved: new Date(Date.now() - 3 * 86400e3).toISOString() as string | undefined,
  isDefault: false,
  dismissed: [] as string[],
  umbrella: { enabled: true, ingest_url: 'https://umbrella.example.net/api/ingest/flow', token_set: true },
  sent: 1284,
  sampling: [
    { exporter: '10.0.0.0/8', if_index: 0, rate: 1000, comment: 'Core: 1:1000 everywhere' },
    { exporter: '10.0.0.1/32', if_index: 503, rate: 4000, comment: 'RETN transit: sampler not reported' },
  ] as { exporter: string; if_index: number; rate: number; comment: string }[],
}

const ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/
const SEVERITIES = ['critical', 'error', 'warning', 'low', 'info']

// checkRule mirrors detector.ValidateRule (enough of it for the console).
export function checkRule(r: Rule): string[] {
  const errs: string[] = []
  if (!ID_RE.test(r.id ?? '')) errs.push(`id ${JSON.stringify(r.id ?? '')}: lower-case letters, digits, '.', '_', '-' (max 64)`)
  const spec = KIND_SPECS[r.kind]
  if (!spec) return [...errs, `kind ${JSON.stringify(r.kind)} is unknown`]
  if (r.severity && !SEVERITIES.includes(r.severity)) errs.push(`severity ${JSON.stringify(r.severity)}: one of [${SEVERITIES.join(' ')}]`)
  if (r.filter) {
    const v = validate(r.filter, columns)
    if (!v.valid) errs.push(`filter: ${v.errors[0].message}`)
    else if (spec.rollupOnly) {
      for (const c of columns) if (!c.rollup && !c.metric && new RegExp(`\\b${c.name}\\b`).test(r.filter)) errs.push(`filter: column ${c.name} is not in the aggregated tables`)
    }
  }
  for (const d of r.dimensions ?? []) {
    const c = columns.find((x) => x.name === d)
    if (!c || !c.dimension) errs.push(`dimension ${JSON.stringify(d)} is unknown`)
    else if (spec.rollupOnly && !c.rollup) errs.push(`dimension ${d} is not in the aggregated tables`)
  }
  for (const k of ['window', 'for', 'interval', 'hysteresis'] as const) if (Number.isNaN(parseDuration(r[k] ?? ''))) errs.push(`${k}: bad duration`)
  if (r.interval && parseDuration(r.interval) < 10e3) errs.push('interval must be at least 10s')
  const t = r.thresholds ?? {}
  switch (r.kind) {
    case 'link_utilization':
      if (!(t.percent! > 0)) errs.push('thresholds.percent is required')
      break
    case 'ddos_volumetric':
      if (!(t.bps! > 0) && !(t.pps! > 0)) errs.push('thresholds.bps or thresholds.pps is required')
      break
    case 'ddos_syn':
      if (!(t.ratio! > 0 && t.ratio! <= 1)) errs.push('thresholds.ratio must be in (0, 1]')
      break
    case 'traffic_drop':
      if (!(t.ratio! > 0 && t.ratio! < 1)) errs.push('thresholds.ratio must be in (0, 1)')
      break
    case 'custom':
      if (!/^[a-z0-9][a-z0-9_.-]{0,127}$/.test(r.signal ?? '')) errs.push('signal is required for custom rules (lower-case, e.g. red.traffic.dns)')
      if ((r.metric === 'pps' && !(t.pps! > 0)) || (r.metric !== 'pps' && !(t.bps! > 0))) errs.push('threshold of the metric is required')
      break
  }
  return errs
}

function newDefaults(): Rule[] {
  if (state.isDefault) return []
  const have = new Set(state.rules.map((r) => r.id))
  return DEFAULT_RULES.filter((r) => !have.has(r.id) && !state.dismissed.includes(r.id))
}

function rulesView(): RulesView {
  return { rules: state.rules, default: state.isDefault, updated_at: state.isDefault ? undefined : state.saved, new_defaults: clone(newDefaults()) }
}

const ago = (ms: number) => new Date(Date.now() - ms).toISOString()
const ahead = (ms: number) => new Date(Date.now() + ms).toISOString()

function status(): DetectorStatus {
  const alerts: AlertState[] = []
  const has = (id: string) => state.rules.some((r) => r.id === id && r.enabled)
  if (has('ddos-volumetric'))
    alerts.push({
      rule_id: 'ddos-volumetric',
      key: '203.0.113.10',
      state: 'firing',
      since: ago(7 * 60e3),
      last_sent: ago(40e3),
      value: 3.42e9,
      group: '203.0.113.10',
      event: { id: 'flow-ddos-1', status: 'firing', signal: 'red.ddos.volumetric', method: 'RED', severity: 'critical', title: 'Объёмная атака на 203.0.113.10: 3.42 Gbit/s', ip: '203.0.113.10', labels: { dst_ip: '203.0.113.10', proto: 'udp', exporter: 'edge-msk-01', interface: 'Hu0/0/0/1' }, starts_at: ago(7 * 60e3) },
    })
  if (has('link-utilization'))
    alerts.push({
      rule_id: 'link-utilization',
      key: '10.0.0.1|HundredGigE0/0/0/1|out',
      state: 'pending',
      since: ago(2 * 60e3),
      value: 91.4,
      group: 'edge-msk-01 HundredGigE0/0/0/1 out',
      event: { id: 'flow-lu-2', status: 'firing', signal: 'use.link.utilization', severity: 'warning', title: 'Загрузка канала HundredGigE0/0/0/1 (out) на edge-msk-01 — 91.4 %', labels: { exporter: 'edge-msk-01', exporter_address: '10.0.0.1', interface: 'HundredGigE0/0/0/1', direction: 'out' } },
    })
  if (has('traffic-anomaly'))
    alerts.push({
      rule_id: 'traffic-anomaly',
      key: 'edge-spb-01|Te0/1/0/3',
      state: 'resolving',
      since: ago(48 * 60e3),
      clear_since: ago(4 * 60e3),
      last_sent: ago(33 * 60e3),
      value: 6.1e9,
      group: 'edge-spb-01, Te0/1/0/3',
      event: { id: 'flow-an-3', status: 'firing', signal: 'red.traffic.anomaly', severity: 'warning', title: 'Аномалия трафика edge-spb-01, Te0/1/0/3: 6.1 Gbit/s при норме 2.3 Gbit/s', labels: { ExporterName: 'edge-spb-01', InIfName: 'Te0/1/0/3' } },
    })
  const errors: Record<string, string> = { 'link-commit': 'circuit commits are unknown: Ledger has no commit_rate for 3 circuits' }
  return {
    rules: state.rules.map((r, i) => {
      const iv = parseDuration(r.interval || KIND_SPECS[r.kind].interval) || 60e3
      const mine = alerts.filter((a) => a.rule_id === r.id)
      return {
        rule: r,
        last_eval: r.enabled ? ago((i * 7919) % iv) : undefined,
        next_eval: r.enabled ? ahead(iv - ((i * 7919) % iv)) : undefined,
        duration_ms: r.enabled ? 18 + ((i * 37) % 140) : 0,
        error: r.enabled ? errors[r.id] : undefined,
        groups: r.enabled ? [42, 3, 1812, 1812, 96, 140, 17, 0][i % 8] : 0,
        pending: mine.filter((a) => a.state === 'pending').length,
        firing: mine.filter((a) => a.state !== 'pending').length,
      }
    }),
    alerts,
    queued: 0,
    sender: {
      url: state.umbrella.ingest_url,
      outbox: 1,
      sent: state.sent,
      dropped: 0,
      last_success: ago(40e3),
      last_error: '',
      configured: state.umbrella.enabled && state.umbrella.token_set,
    },
  }
}

// detectorMock answers the paths it knows, null otherwise.
export function detectorMock(method: string, p: string, body: unknown): Reply | null {
  if (p === '/api/detector/rules' && method === 'GET') return ok(rulesView())
  if (p === '/api/detector/rules/defaults') return ok({ rules: DEFAULT_RULES, default: true })
  if (p === '/api/detector/rules' && method === 'PUT') {
    const rules = ((body as { rules?: Rule[] })?.rules ?? []) as Rule[]
    const seen = new Set<string>()
    for (let i = 0; i < rules.length; i++) {
      const errs = checkRule(rules[i])
      if (errs.length) return fail(400, 'invalid_rule', `rule ${i + 1}: ${errs.join('\n')}`)
      if (seen.has(rules[i].id)) return fail(400, 'duplicate_rule', `rule id ${rules[i].id} is repeated`)
      seen.add(rules[i].id)
    }
    // a built-in rule the saved set had and this one drops was deleted on purpose
    const had = new Set(state.rules.map((r) => r.id))
    for (const d of DEFAULT_RULES) if ((had.has(d.id) || state.isDefault) && !seen.has(d.id) && !state.dismissed.includes(d.id)) state.dismissed.push(d.id)
    state.rules = clone(rules)
    state.isDefault = false
    state.saved = new Date().toISOString()
    return ok(rulesView())
  }
  if (p === '/api/detector/rules/add-defaults' && method === 'POST') {
    const b = (body ?? {}) as { ids?: string[]; dismiss?: string[] }
    const offered = newDefaults()
    const dismiss = b.dismiss ?? []
    const add = b.ids ?? (dismiss.length ? [] : offered.map((r) => r.id))
    for (const id of [...add, ...dismiss]) if (!offered.some((r) => r.id === id)) return fail(400, 'unknown_default', 'not a new built-in rule: ' + id)
    for (const id of add) if (!dismiss.includes(id)) state.rules.push(clone(offered.find((r) => r.id === id)!))
    state.dismissed.push(...dismiss)
    return ok(rulesView())
  }
  if (p === '/api/detector/status') return ok(status())
  if (p === '/api/settings/umbrella' && method === 'GET') return ok(state.umbrella)
  if (p === '/api/settings/umbrella/test') {
    const b = (body ?? {}) as { ingest_url?: string }
    if (!/^https?:\/\//.test(b.ingest_url ?? state.umbrella.ingest_url)) return ok({ ok: false, error: 'ingest URL must start with http:// or https://' })
    state.sent++
    return ok({ ok: true, details: { event: { id: 'flow-test', status: 'firing', signal: 'flow.test', labels: { umbrella_test: 'true' } } } })
  }
  if (p === '/api/sampling-overrides' && method === 'GET') return ok({ results: state.sampling })
  if (p === '/api/sampling-overrides' && method === 'PUT') {
    const list = ((body as { results?: typeof state.sampling })?.results ?? []).map((o) => ({ ...o, if_index: o.if_index ?? 0, comment: (o.comment ?? '').trim() }))
    for (const o of list) {
      const host = /^[0-9.]+$/.test(o.exporter) ? `${o.exporter}/32` : /^[0-9a-f:]+$/i.test(o.exporter) ? `${o.exporter}/128` : o.exporter
      if (!/^[0-9a-f:.]+\/\d{1,3}$/i.test(host)) return fail(400, 'invalid_exporter', 'not an address or CIDR: ' + o.exporter)
      if (!(o.rate > 0) || o.rate > 2 ** 31) return fail(400, 'invalid_rate', 'the sampling rate must be positive')
      o.exporter = host
    }
    state.sampling = list
    return ok({ results: state.sampling })
  }
  return null
}
