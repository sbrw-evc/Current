// Types of the Beacon API endpoints (docs/api.md, "Beacon: visibility scope, dependencies").

export type UmbrellaIngest = { enabled: boolean; ingest_url: string; token_set: boolean }
export type UmbrellaIngestUpdate = { enabled: boolean; ingest_url: string; token?: string }

export type UmbrellaAPI = { url: string; token_set: boolean }
export type UmbrellaAPIUpdate = { url: string; token?: string }

export type ScopeView = {
  restricted: boolean
  ok: boolean
  error?: string
  configured: boolean
  known: boolean
  mode?: 'all' | 'teams' | 'selected'
  cis: number
  services: number
  refs: number
  addresses: number
  checked_at?: string
}

export type CheckResult<D = unknown> = { ok: boolean; error?: string; details?: D }

export type DependencySettings = { enabled: boolean; hour: number; min_flows: number; min_days: number; max_proposals: number }

export type DependencyRun = {
  id: number
  trigger: 'schedule' | 'manual'
  actor: string
  dry_run: boolean
  started_at: string
  finished_at: string | null
  ok: boolean | null
  error: string
  pairs: number
  sent: number
  accepted: number
  updated: number
  ignored: number
  params: { days?: number; min_flows?: number; min_days?: number; limit?: number }
}

export type ProposalEnd = { source_ref: string; name?: string; ip?: string }

export type Proposal = {
  key: string
  from: ProposalEnd
  to: ProposalEnd
  type: 'depends_on'
  evidence: {
    protocol: string
    port: number
    app?: string
    bytes_7d: number
    flows_7d: number
    days_seen: number
    first_seen: string
    last_seen: string
    flow_url?: string
  }
}

export type Dependencies = {
  settings: DependencySettings
  configured: boolean
  available: boolean
  running: boolean
  next_run: string | null
  last_run: DependencyRun | null
  runs: DependencyRun[]
  proposals: Proposal[]
}

export type DependencyRunReply = { run: DependencyRun; proposals: Proposal[] }
