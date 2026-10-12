// Threat intelligence settings (docs/api.md, "Threat intelligence"): public IP blocklists downloaded
// by the enricher at run time; SrcThreat / DstThreat name the list an address belongs to.

export type ThreatList = { name: string; url: string; enabled: boolean; terms?: string }

export type ThreatSettings = {
  enabled: boolean
  lists: ThreatList[]
  refresh_minutes: number
  exclude: string[]
  refresh_requested_at?: string
}

export type ThreatListStatus = {
  name: string
  url: string
  enabled: boolean
  prefixes: number
  skipped: number
  updated_at?: string
  checked_at?: string
  error?: string
}

export type ThreatStatus = { updated_at?: string; prefixes: number; lists: ThreatListStatus[] }

export type ThreatView = { settings: ThreatSettings; status: ThreatStatus; default_lists: ThreatList[] }

export type ListState = 'ok' | 'error' | 'pending' | 'disabled'

// listState: how a list is doing, from the status written by the downloading process.
export function listState(l: ThreatList, s: ThreatListStatus | undefined, enabled: boolean): ListState {
  if (!enabled || !l.enabled) return 'disabled'
  if (!s || (s.url !== l.url && s.url !== '')) return 'pending'
  if (s.error) return 'error'
  return s.updated_at ? 'ok' : 'pending'
}

const nameRe = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/

// validateLists returns the message keys of the problems (empty when the lists can be saved).
export function validateLists(lists: ThreatList[]): string[] {
  const out = new Set<string>()
  const seen = new Set<string>()
  for (const l of lists) {
    if (!nameRe.test(l.name)) out.add('thr.err.name')
    if (seen.has(l.name)) out.add('thr.err.dup')
    seen.add(l.name)
    if (!/^https?:\/\/[^\s/]+/.test(l.url)) out.add('thr.err.url')
  }
  return [...out]
}

// parseExclude splits the exclusion text (one prefix per line, commas or spaces) into entries.
export function parseExclude(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

// validPrefix accepts an IPv4 / IPv6 address or prefix (the server checks it exactly).
export function validPrefix(s: string): boolean {
  const [addr, bits, extra] = s.split('/')
  if (extra !== undefined) return false
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr)
  if (v4) {
    if (v4.slice(1).some((o) => Number(o) > 255)) return false
    return bits === undefined || (/^\d{1,2}$/.test(bits) && Number(bits) <= 32)
  }
  if (!/^[0-9a-fA-F:.]+$/.test(addr) || !addr.includes(':')) return false
  return bits === undefined || (/^\d{1,3}$/.test(bits) && Number(bits) <= 128)
}

// statusFor finds the status of a list by name.
export function statusFor(status: ThreatStatus | undefined, name: string): ThreatListStatus | undefined {
  return status?.lists.find((s) => s.name === name)
}
