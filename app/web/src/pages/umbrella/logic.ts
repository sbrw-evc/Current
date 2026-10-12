import type { DependencyRun, Proposal } from '../../api/umbrella'

// Pure helpers of the Umbrella pages (tested in logic.test.ts).

// endLabel: the name of a proposal end, else its address, else the Inventory DB ref.
export function endLabel(e: { source_ref: string; name?: string; ip?: string }) {
  return e.name || e.ip || e.source_ref
}

// service: "tcp/5432 · postgres".
export function serviceLabel(p: Proposal) {
  const s = `${p.evidence.protocol}/${p.evidence.port}`
  return p.evidence.app ? `${s} · ${p.evidence.app}` : s
}

// filterProposals: case-insensitive match on names, addresses, refs, port and application.
export function filterProposals(list: Proposal[], q: string) {
  const s = q.trim().toLowerCase()
  if (!s) return list
  return list.filter((p) =>
    [p.from.name, p.from.ip, p.from.source_ref, p.to.name, p.to.ip, p.to.source_ref, p.evidence.app, serviceLabel(p)]
      .filter(Boolean)
      .some((v) => String(v).toLowerCase().includes(s)),
  )
}

export type SortKey = 'bytes' | 'flows' | 'days' | 'from' | 'to'

export function sortProposals(list: Proposal[], key: SortKey) {
  const out = [...list]
  const by: Record<SortKey, (a: Proposal, b: Proposal) => number> = {
    bytes: (a, b) => b.evidence.bytes_7d - a.evidence.bytes_7d,
    flows: (a, b) => b.evidence.flows_7d - a.evidence.flows_7d,
    days: (a, b) => b.evidence.days_seen - a.evidence.days_seen || b.evidence.bytes_7d - a.evidence.bytes_7d,
    from: (a, b) => endLabel(a.from).localeCompare(endLabel(b.from)),
    to: (a, b) => endLabel(a.to).localeCompare(endLabel(b.to)),
  }
  return out.sort(by[key])
}

export type RunState = 'running' | 'ok' | 'failed' | 'preview'

// runState: what a run's chip shows.
export function runState(r: DependencyRun): RunState {
  if (r.finished_at === null && r.ok === null) return 'running'
  if (r.ok === false) return 'failed'
  return r.dry_run ? 'preview' : 'ok'
}

// isUrl accepts http(s) addresses with a host.
export function isUrl(s: string) {
  return /^https?:\/\/[^/\s]+/i.test(s.trim())
}
