// Detector rules (internal/detector.Rule) and the editing model of the rule form: which fields a
// kind uses, the draft the form edits (numbers as text), client-side checks mirroring
// detector.ValidateRule, and the mapping of server errors (400 invalid_rule) to fields.

export type Kind =
  | 'link_utilization'
  | 'link_commit'
  | 'ddos_volumetric'
  | 'ddos_syn'
  | 'traffic_anomaly'
  | 'traffic_drop'
  | 'exporter_silent'
  | 'custom'
  | 'threat_contact'

export const KINDS: Kind[] = ['link_utilization', 'link_commit', 'ddos_volumetric', 'ddos_syn', 'traffic_anomaly', 'traffic_drop', 'exporter_silent', 'custom', 'threat_contact']
export const SEVERITIES = ['critical', 'error', 'warning', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]

export type Thresholds = { bps?: number; pps?: number; percent?: number; ratio?: number; silence?: string }
export type Baseline = { weeks?: number; min_samples?: number; window?: string; k?: number; ratio?: number; min_volume?: number; direction?: string }

export type Rule = {
  id: string
  name: string
  enabled: boolean
  kind: Kind
  filter?: string
  dimensions?: string[]
  thresholds: Thresholds
  window?: string
  for?: string
  interval?: string
  hysteresis?: string
  severity: string
  baseline?: Baseline
  signal?: string
  method?: string
  metric?: string
  operator?: string
  title?: string
}

export type RulesView = { rules: Rule[]; default: boolean; updated_at?: string }

export type DetectorEvent = {
  id: string
  status: string
  signal: string
  method?: string
  severity: string
  title: string
  ci?: string
  source_ref?: string
  ip?: string
  value?: number
  labels?: Record<string, string>
  links?: { flow?: string }
  starts_at?: string
  ends_at?: string
}

export type AlertState = {
  rule_id: string
  key: string
  state: 'pending' | 'firing' | 'resolving'
  since: string
  clear_since?: string
  last_sent?: string
  value: number
  event?: DetectorEvent
  group?: string
  last_evaluated?: string
}

export type RuleStatus = { rule: Rule; last_eval?: string; next_eval?: string; duration_ms: number; error?: string; groups: number; pending: number; firing: number }
export type SenderStatus = { url: string; outbox: number; sent: number; dropped: number; last_success?: string; last_error?: string; configured: boolean }
export type DetectorStatus = { rules: RuleStatus[]; alerts: AlertState[]; queued: number; sender?: SenderStatus; remote?: boolean }

// Fields of the form. Threshold and baseline fields are prefixed.
export type FieldName =
  | 'id'
  | 'name'
  | 'kind'
  | 'severity'
  | 'filter'
  | 'dimensions'
  | 'window'
  | 'for'
  | 'interval'
  | 'hysteresis'
  | 't.bps'
  | 't.pps'
  | 't.percent'
  | 't.ratio'
  | 't.silence'
  | 'b.weeks'
  | 'b.min_samples'
  | 'b.window'
  | 'b.k'
  | 'b.ratio'
  | 'b.min_volume'
  | 'b.direction'
  | 'signal'
  | 'method'
  | 'metric'
  | 'operator'
  | 'title'

export type KindSpec = {
  thresholds: ('bps' | 'pps' | 'percent' | 'ratio' | 'silence')[]
  baseline: ('weeks' | 'min_samples' | 'window' | 'k' | 'ratio' | 'min_volume' | 'direction')[]
  dimensions: boolean
  rollupOnly: boolean // filter and dimensions limited to the aggregated tables' columns
  filter: boolean
  window: string // kind default ("" = not used)
  interval: string
  signal: string // derived event signal ("" = custom)
}

export const KIND_SPECS: Record<Kind, KindSpec> = {
  link_utilization: { thresholds: ['percent'], baseline: [], dimensions: false, rollupOnly: false, filter: true, window: '1m', interval: '1m', signal: 'use.link.utilization' },
  link_commit: { thresholds: ['percent'], baseline: [], dimensions: false, rollupOnly: true, filter: true, window: '', interval: '15m', signal: 'use.link.commit' },
  ddos_volumetric: { thresholds: ['bps', 'pps'], baseline: ['window', 'k'], dimensions: false, rollupOnly: false, filter: true, window: '1m', interval: '30s', signal: 'red.ddos.volumetric' },
  ddos_syn: { thresholds: ['pps', 'ratio'], baseline: [], dimensions: false, rollupOnly: false, filter: true, window: '1m', interval: '30s', signal: 'red.ddos.syn' },
  traffic_anomaly: { thresholds: [], baseline: ['weeks', 'min_samples', 'k', 'ratio', 'min_volume', 'direction'], dimensions: true, rollupOnly: true, filter: true, window: '15m', interval: '5m', signal: 'red.traffic.anomaly' },
  traffic_drop: { thresholds: ['ratio'], baseline: ['weeks', 'min_samples', 'min_volume'], dimensions: true, rollupOnly: true, filter: true, window: '15m', interval: '5m', signal: 'red.traffic.drop' },
  exporter_silent: { thresholds: ['silence'], baseline: [], dimensions: false, rollupOnly: false, filter: false, window: '', interval: '1m', signal: 'use.exporter.silent' },
  custom: { thresholds: ['bps', 'pps'], baseline: [], dimensions: true, rollupOnly: false, filter: true, window: '5m', interval: '1m', signal: '' },
  threat_contact: { thresholds: ['bps'], baseline: [], dimensions: false, rollupOnly: false, filter: true, window: '5m', interval: '1m', signal: 'sec.threat.contact' },
}

// ---- numbers and durations

const SI: Record<string, number> = { '': 1, k: 1e3, K: 1e3, m: 1e6, M: 1e6, g: 1e9, G: 1e9, t: 1e12, T: 1e12 }

// parseRate reads "1.5G", "100M", "250k", "1e9" or a plain number; NaN when invalid.
export function parseRate(s: string): number {
  const v = s.trim().replace(/\s+/g, '').replace(/(bps|pps|b\/s|p\/s)$/i, '')
  if (v === '') return NaN
  const m = /^([0-9]*\.?[0-9]+(?:e[+-]?\d+)?)([kKmMgGtT]?)$/.exec(v)
  if (!m) return NaN
  return Number(m[1]) * SI[m[2]]
}

// formatRate writes a rate compactly for the form: 1000000000 → "1G".
export function formatRate(n: number | undefined): string {
  if (n === undefined || n === null || !Number.isFinite(n) || n === 0) return ''
  for (const [suffix, f] of [['T', 1e12], ['G', 1e9], ['M', 1e6], ['k', 1e3]] as const) {
    if (n < f) continue
    const x = Math.round((n / f) * 100) / 100
    // only when exact (at most two decimals): the form must not change the stored value
    if (Math.abs(x * f - n) <= 1e-9 * n) return `${x}${suffix}`
  }
  return String(n)
}

const UNIT_MS: Record<string, number> = { ms: 1, s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 }

// parseDuration reads Go durations plus days and weeks ("90s", "1h30m", "7d", "2w"); milliseconds,
// NaN when invalid, 0 for "".
export function parseDuration(s: string): number {
  const v = s.trim()
  if (v === '') return 0
  if (v === '0') return 0
  const re = /([0-9]*\.?[0-9]+)(ms|s|m|h|d|w)/gy
  let total = 0
  let pos = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(v))) {
    total += Number(m[1]) * UNIT_MS[m[2]]
    pos = re.lastIndex
  }
  if (pos !== v.length || pos === 0) return NaN
  return total
}

// ---- the draft

export type Draft = {
  id: string
  name: string
  enabled: boolean
  kind: Kind
  severity: string
  filter: string
  dimensions: string[]
  window: string
  for: string
  interval: string
  hysteresis: string
  t: { bps: string; pps: string; percent: string; ratio: string; silence: string }
  b: { weeks: string; min_samples: string; window: string; k: string; ratio: string; min_volume: string; direction: string }
  signal: string
  method: string
  metric: string
  operator: string
  title: string
}

const str = (n: number | undefined) => (n === undefined || n === null || n === 0 ? '' : String(n))

export function toDraft(r: Rule): Draft {
  const t = r.thresholds ?? {}
  const b = r.baseline ?? {}
  return {
    id: r.id ?? '',
    name: r.name ?? '',
    enabled: r.enabled ?? true,
    kind: r.kind,
    severity: r.severity || 'warning',
    filter: r.filter ?? '',
    dimensions: [...(r.dimensions ?? [])],
    window: r.window && r.window !== '0s' ? r.window : '',
    for: r.for && r.for !== '0s' ? r.for : '',
    interval: r.interval && r.interval !== '0s' ? r.interval : '',
    hysteresis: r.hysteresis && r.hysteresis !== '0s' ? r.hysteresis : '',
    t: { bps: formatRate(t.bps), pps: formatRate(t.pps), percent: str(t.percent), ratio: str(t.ratio), silence: t.silence && t.silence !== '0s' ? t.silence : '' },
    b: {
      weeks: str(b.weeks),
      min_samples: str(b.min_samples),
      window: b.window && b.window !== '0s' ? b.window : '',
      k: str(b.k),
      ratio: str(b.ratio),
      min_volume: formatRate(b.min_volume),
      direction: b.direction ?? '',
    },
    signal: r.signal ?? '',
    method: r.method ?? '',
    metric: r.metric ?? '',
    operator: r.operator ?? '',
    title: r.title ?? '',
  }
}

export function newDraft(kind: Kind = 'custom'): Draft {
  const d = toDraft({ id: '', name: '', enabled: true, kind, severity: 'warning', thresholds: {} })
  if (kind === 'custom') {
    d.metric = 'bps'
    d.operator = '>'
  }
  return d
}

// slug proposes a rule id from its name.
export function slug(name: string): string {
  const tr: Record<string, string> = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' }
  return name
    .toLowerCase()
    .split('')
    .map((c) => tr[c] ?? c)
    .join('')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}

const num = (s: string) => (s.trim() === '' ? undefined : Number(s.trim().replace(',', '.')))

// fromDraft builds the rule sent to the server: fields the kind does not use are left out.
export function fromDraft(d: Draft): Rule {
  const spec = KIND_SPECS[d.kind]
  const r: Rule = { id: d.id.trim(), name: d.name.trim(), enabled: d.enabled, kind: d.kind, severity: d.severity, thresholds: {} }
  if (spec.filter && d.filter.trim()) r.filter = d.filter.trim()
  if (spec.dimensions && d.dimensions.length) r.dimensions = [...d.dimensions]
  for (const k of ['window', 'for', 'interval', 'hysteresis'] as const) if (d[k].trim()) r[k] = d[k].trim()
  for (const k of spec.thresholds) {
    const v = d.t[k].trim()
    if (!v) continue
    if (d.kind === 'custom' && k !== (d.metric === 'pps' ? 'pps' : 'bps')) continue
    if (k === 'silence') r.thresholds.silence = v
    else if (k === 'bps' || k === 'pps') r.thresholds[k] = parseRate(v)
    else r.thresholds[k] = num(v)
  }
  if (spec.baseline.length) {
    const b: Baseline = {}
    for (const k of spec.baseline) {
      const v = d.b[k].trim()
      if (!v) continue
      if (k === 'window' || k === 'direction') b[k] = v
      else if (k === 'min_volume') b.min_volume = parseRate(v)
      else b[k] = num(v)
    }
    if (Object.keys(b).length) r.baseline = b
  }
  if (d.kind === 'custom') {
    r.signal = d.signal.trim()
    if (d.method) r.method = d.method
    r.metric = d.metric || 'bps'
    r.operator = d.operator || '>'
  }
  if (d.title.trim()) r.title = d.title.trim()
  return r
}

// ---- checks (mirroring detector.ValidateRule; the server has the last word)

export type Problems = Partial<Record<FieldName, string>>

const ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/
const SIGNAL_RE = /^[a-z0-9][a-z0-9_.-]{0,127}$/

// validateDraft returns problems as message keys (strings of the page dictionary).
export function validateDraft(d: Draft, takenIds: string[] = []): Problems {
  const p: Problems = {}
  const spec = KIND_SPECS[d.kind]
  if (!d.name.trim()) p.name = 'v.required'
  if (!ID_RE.test(d.id.trim())) p.id = 'v.id'
  else if (takenIds.includes(d.id.trim())) p.id = 'v.id.taken'
  for (const k of ['window', 'for', 'interval', 'hysteresis'] as const) {
    if (Number.isNaN(parseDuration(d[k]))) p[k] = 'v.duration'
  }
  if (!p.interval && d.interval.trim() && parseDuration(d.interval) < 10e3) p.interval = 'v.interval'
  if (spec.dimensions && d.dimensions.length > 8) p.dimensions = 'v.dims'
  const t = d.t
  const has = (k: 'bps' | 'pps') => t[k].trim() !== ''
  for (const k of ['bps', 'pps'] as const) {
    if (spec.thresholds.includes(k) && has(k) && !(parseRate(t[k]) >= 0)) p[`t.${k}`] = 'v.rate'
  }
  for (const k of ['percent', 'ratio'] as const) {
    const v = t[k].trim()
    if (spec.thresholds.includes(k) && v && !(Number(v.replace(',', '.')) >= 0)) p[`t.${k}`] = 'v.number'
  }
  if (spec.thresholds.includes('silence') && Number.isNaN(parseDuration(t.silence))) p['t.silence'] = 'v.duration'
  const pct = Number(t.percent.replace(',', '.'))
  const ratio = Number(t.ratio.replace(',', '.'))
  switch (d.kind) {
    case 'link_utilization':
      if (!p['t.percent'] && !(pct > 0)) p['t.percent'] = 'v.required'
      break
    case 'ddos_volumetric':
      if (!p['t.bps'] && !p['t.pps'] && !(parseRate(t.bps) > 0) && !(parseRate(t.pps) > 0)) p['t.bps'] = 'v.bps_or_pps'
      break
    case 'ddos_syn':
      if (!p['t.ratio'] && !(ratio > 0 && ratio <= 1)) p['t.ratio'] = 'v.ratio01'
      break
    case 'traffic_drop':
      if (!p['t.ratio'] && !(ratio > 0 && ratio < 1)) p['t.ratio'] = 'v.ratio01open'
      break
    case 'custom': {
      if (!SIGNAL_RE.test(d.signal.trim())) p.signal = 'v.signal'
      const metric = d.metric || 'bps'
      const k = metric === 'pps' ? 'pps' : 'bps'
      if (!p[`t.${k}`] && !(parseRate(t[k]) > 0)) p[`t.${k}`] = 'v.metric'
      break
    }
  }
  const b = d.b
  for (const k of spec.baseline) {
    const v = b[k].trim()
    if (!v || k === 'direction') continue
    if (k === 'window') {
      if (Number.isNaN(parseDuration(v))) p['b.window'] = 'v.duration'
    } else if (k === 'min_volume') {
      if (!(parseRate(v) >= 0)) p['b.min_volume'] = 'v.rate'
    } else if (!(Number(v.replace(',', '.')) >= 0)) p[`b.${k}`] = 'v.number'
  }
  if (spec.baseline.includes('weeks') && b.weeks.trim()) {
    const w = Number(b.weeks)
    if (!Number.isInteger(w) || w > 52) p['b.weeks'] = 'v.weeks'
    else if (b.min_samples.trim() && Number(b.min_samples) > w) p['b.min_samples'] = 'v.min_samples'
  }
  return p
}

// fieldOfServerError maps one line of a detector.ValidateRule error to a form field.
export function fieldOfServerError(line: string, metric = 'bps'): FieldName | null {
  const s = line.trim().replace(/^rule \d+:\s*/, '')
  const rules: [RegExp, FieldName][] = [
    [/^id\b/, 'id'],
    [/^kind\b/, 'kind'],
    [/^severity\b/, 'severity'],
    [/^filter\b/, 'filter'],
    [/^(dimension|at most \d+ dimensions)/, 'dimensions'],
    [/^window\b/, 'window'],
    [/^for\b/, 'for'],
    [/^interval\b/, 'interval'],
    [/^hysteresis\b/, 'hysteresis'],
    [/^thresholds\.percent/, 't.percent'],
    [/^thresholds\.bps or thresholds\.pps/, 't.bps'],
    [/^thresholds\.ratio/, 't.ratio'],
    [/^baseline: min_samples/, 'b.min_samples'],
    [/^baseline: direction/, 'b.direction'],
    [/^baseline\b/, 'b.weeks'],
    [/^signal\b/, 'signal'],
    [/^method\b/, 'method'],
    [/^metric\b/, 'metric'],
    [/^operator\b/, 'operator'],
  ]
  for (const [re, f] of rules) if (re.test(s)) return f
  if (/^threshold of the metric/.test(s)) return metric === 'pps' ? 't.pps' : 't.bps'
  return null
}

// serverProblems splits the message of a 400 invalid_rule answer into per-field problems; lines
// that name no field are returned in `other`.
export function serverProblems(message: string, metric = 'bps'): { fields: Problems; other: string[] } {
  const fields: Problems = {}
  const other: string[] = []
  const lines = message.split('\n').map((l) => l.trim()).filter(Boolean)
  lines.forEach((l, i) => {
    const text = i === 0 ? l.replace(/^rule \d+:\s*/, '') : l
    const f = fieldOfServerError(text, metric)
    if (f && !fields[f]) fields[f] = text
    else other.push(text)
  })
  return { fields, other }
}

// ---- display helpers

export function thresholdSummary(r: Rule, fmt: { bps: (n: number) => string; pps: (n: number) => string; pct: (n: number) => string }): string {
  const t = r.thresholds ?? {}
  const parts: string[] = []
  switch (r.kind) {
    case 'link_utilization':
    case 'link_commit':
      parts.push(`≥ ${fmt.pct(t.percent ?? (r.kind === 'link_commit' ? 100 : 0))}`)
      break
    case 'ddos_volumetric':
      if (t.bps) parts.push(`≥ ${fmt.bps(t.bps)}`)
      if (t.pps) parts.push(`≥ ${fmt.pps(t.pps)}`)
      if (r.baseline?.k) parts.push(`× ${r.baseline.k}`)
      break
    case 'ddos_syn':
      if (t.pps) parts.push(`≥ ${fmt.pps(t.pps)}`)
      if (t.ratio) parts.push(`SYN ≥ ${fmt.pct(t.ratio * 100)}`)
      break
    case 'traffic_anomaly':
      parts.push(`k ${r.baseline?.k ?? 3}`)
      if (r.baseline?.ratio) parts.push(`± ${fmt.pct(r.baseline.ratio * 100)}`)
      break
    case 'traffic_drop':
      if (t.ratio) parts.push(`< ${fmt.pct(t.ratio * 100)}`)
      break
    case 'exporter_silent':
      parts.push(`≥ ${t.silence ?? '10m'}`)
      break
    case 'threat_contact':
      parts.push(t.bps ? `≥ ${fmt.bps(t.bps)}` : 'sec.threat.contact')
      break
    case 'custom': {
      const m = r.metric || 'bps'
      const v = m === 'pps' ? t.pps : t.bps
      parts.push(`${r.operator || '>'} ${v ? (m === 'pps' ? fmt.pps(v) : fmt.bps(v)) : '?'}`)
      break
    }
  }
  return parts.join(' · ')
}

// replaceRule puts r in place of the rule with id `old` (or appends it).
export function replaceRule(rules: Rule[], old: string | null, r: Rule): Rule[] {
  const i = old === null ? -1 : rules.findIndex((x) => x.id === old)
  if (i < 0) return [...rules, r]
  const out = [...rules]
  out[i] = r
  return out
}
