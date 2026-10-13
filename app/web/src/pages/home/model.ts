import type { Exporter } from '../../api/types'
import type { UmbrellaAPI, UmbrellaIngest } from '../../api/umbrella'
import type { AlertState, RulesView } from '../detector/model'
import type { BmpView } from '../settings/BmpModel'
import type { InventoryIntegration } from '../settings/InventoryDbModel'

// The Overview's «needs attention» list and «first steps» checklist (Umbrella's onboarding
// checklist), computed from what the other pages already read.

export const SILENT_MS = 5 * 60e3

export type Tone = 'error' | 'warn' | 'info'
export type Attention = { id: 'alerts' | 'silent' | 'noinventory'; tone: Tone; count: number; path: string }

// attention lists what an engineer should look at now, the most urgent first; only non-zero items.
export function attention(alerts: AlertState[] | undefined, exporters: Exporter[] | undefined, now = Date.now()): Attention[] {
  const out: Attention[] = []
  const firing = alerts?.filter((a) => a.state === 'firing').length ?? 0
  if (firing) out.push({ id: 'alerts', tone: 'error', count: firing, path: '/detector/status' })
  const silent = exporters?.filter((e) => now - Date.parse(e.last_seen) > SILENT_MS).length ?? 0
  if (silent) out.push({ id: 'silent', tone: 'warn', count: silent, path: '/exporters' })
  const unknown = exporters?.filter((e) => !e.ref).length ?? 0
  if (unknown) out.push({ id: 'noinventory', tone: 'info', count: unknown, path: '/exporters' })
  return out
}

export type StepId = 'exporters' | 'detector' | 'inventory' | 'umbrella' | 'bmp'
export type Step = { id: StepId; path: string; done: boolean; optional?: boolean }

// The facts a step is decided by; undefined = not read (no permission or still loading).
export type StepFacts = {
  exporters?: Exporter[]
  rules?: RulesView
  inventory?: InventoryIntegration
  umbrella?: { ingest?: UmbrellaIngest; api?: UmbrellaAPI }
  bmp?: BmpView
}

// steps is the path from installation to useful data: flows arrive, the detector watches them, and
// Inventory DB and Umbrella Monitoring add names and incidents. A step whose facts are unknown is
// left out, so a role sees only what it can check.
export function steps(f: StepFacts): Step[] {
  const out: Step[] = []
  if (f.exporters) out.push({ id: 'exporters', path: '/exporters', done: f.exporters.length > 0 })
  if (f.rules) out.push({ id: 'detector', path: '/detector/rules', done: f.rules.rules.some((r) => r.enabled) })
  if (f.inventory) out.push({ id: 'inventory', path: '/settings/inventory-db', done: f.inventory.hook_secret_set || f.inventory.write_token_set })
  if (f.umbrella?.ingest && f.umbrella.api) out.push({ id: 'umbrella', path: '/settings/umbrella', done: f.umbrella.ingest.enabled || f.umbrella.api.url.trim() !== '' })
  if (f.bmp) out.push({ id: 'bmp', path: '/settings/bmp', done: f.bmp.enabled, optional: true })
  return out
}

// stepsDone: every required step is done, so the checklist is no longer shown.
export const stepsDone = (s: Step[]) => s.filter((x) => !x.optional).every((x) => x.done)
