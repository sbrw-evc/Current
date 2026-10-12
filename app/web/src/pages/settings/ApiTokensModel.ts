// Types and helpers of Settings → API tokens (docs/api.md, "API tokens").

export type ServiceAccount = {
  id: number
  name: string
  description: string
  role_id: number
  role: string
  disabled: boolean
  tokens: number
  created_by: string
  created_at: string
  updated_at: string
}

export type ApiToken = {
  id: number
  service_account_id: number
  service_account: string
  name: string
  display: string
  expires_at: string | null
  last_used_at: string | null
  last_used_from: string
  created_by: string
  created_at: string
  revoked_at: string | null
  revoked_by: string
  active: boolean
}

// The answer of POST /api/tokens: the token itself is in it only this once.
export type IssuedToken = ApiToken & { token: string }

export type Role = { id: number; name: string; builtin: boolean }

export type TokenState = 'active' | 'expired' | 'revoked'

export function tokenState(t: Pick<ApiToken, 'revoked_at' | 'expires_at'>, now = Date.now()): TokenState {
  if (t.revoked_at) return 'revoked'
  if (t.expires_at && new Date(t.expires_at).getTime() <= now) return 'expired'
  return 'active'
}

// Expiry presets of the issue dialog, in days (0 = never).
export const EXPIRY_PRESETS = [30, 90, 365, 0] as const

// expiryDate turns a preset into the expires_at the API takes (a date, end of that day UTC).
export function expiryDate(days: number, now = new Date()): string {
  if (days <= 0) return ''
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + days))
  return d.toISOString().slice(0, 10)
}

// A service account name: 1-64 characters without spaces or slashes (the server checks the same).
export function validAccountName(s: string): boolean {
  const v = s.trim()
  return v.length > 0 && [...v].length <= 64 && !/[\s/]/.test(v)
}
