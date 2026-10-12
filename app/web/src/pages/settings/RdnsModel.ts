// Reverse DNS settings (docs/api.md, "Reverse DNS"): asynchronous PTR lookups in the enricher for
// addresses without an Inventory DB host name; results go to SrcHostPTR / DstHostPTR.

export type RdnsScope = 'all' | 'private' | 'public'

export type RdnsSettings = {
  enabled: boolean
  servers: string[]
  scope: RdnsScope
  workers: number
  rate_limit: number
  positive_ttl: number
  negative_ttl: number
  timeout_ms: number
  cache_size: number
  queue_size: number
}

export type RdnsStats = {
  enabled: boolean
  cached: number
  queued: number
  hits: number
  misses: number
  dropped: number
  found: number
  not_found: number
  errors: number
}

export type RdnsView = { settings: RdnsSettings; stats?: RdnsStats }

// parseServers splits the server text (one per line, commas or spaces) into entries.
export function parseServers(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

// validServer accepts "address", "[v6]:port", "host" or "host:port" (the server checks it exactly).
export function validServer(s: string): boolean {
  const v6 = /^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/.exec(s)
  if (v6) return v6[2] === undefined || Number(v6[2]) <= 65535
  if (/^[0-9a-fA-F:]+$/.test(s) && s.split(':').length > 2) return true // bare IPv6
  const m = /^([a-zA-Z0-9.-]+)(?::(\d{1,5}))?$/.exec(s)
  if (!m) return false
  if (m[1].startsWith('.') || m[1].endsWith('-') || m[1].includes('..')) return false
  return m[2] === undefined || (Number(m[2]) >= 1 && Number(m[2]) <= 65535)
}

// hitRatio is the share of lookups answered from the cache (null before any lookup).
export function hitRatio(s: RdnsStats | undefined): number | null {
  if (!s) return null
  const total = s.hits + s.misses
  return total > 0 ? s.hits / total : null
}
