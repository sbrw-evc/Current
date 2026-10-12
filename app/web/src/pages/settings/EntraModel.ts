// Types and helpers of Settings → Entra ID (docs/api.md, "Microsoft Entra ID").

export const ENTRA_CALLBACK = '/api/auth/entra/callback'

export type EntraGroupRole = { group_id: string; role_id: number; role?: string }

export type EntraView = {
  enabled: boolean
  cloud: string
  tenant_id: string
  client_id: string
  redirect_url: string
  client_secret_set: boolean
  default_role_id: number
  group_roles: EntraGroupRole[]
  users: number
}

export type EntraInput = Omit<EntraView, 'client_secret_set' | 'users'> & { client_secret?: string }

export type EntraTest = { ok: boolean; probe: { issuer?: string; tenant_id?: string; credentials: boolean }; error?: string }

export const CLOUDS = ['global', 'usgov', 'china'] as const

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export const isGuid = (s: string) => GUID.test(s.trim())

// A tenant is a GUID or a domain; the multi-tenant endpoints are refused (as on the server).
export function validTenant(s: string): boolean {
  const v = s.trim().toLowerCase()
  if (!v || ['common', 'organizations', 'consumers'].includes(v)) return false
  return /^[a-z0-9][a-z0-9.-]{0,252}$/.test(v)
}

// The redirect URI to register in Entra ID for this Flow address.
export function defaultRedirect(origin: string): string {
  return origin.replace(/\/+$/, '') + ENTRA_CALLBACK
}

// Sign-in error codes the callback puts into /login?signin_error=…
export const SIGNIN_ERRORS = ['entra_off', 'entra_unavailable', 'entra_denied', 'entra_state', 'entra_account', 'entra_no_role', 'entra_conflict', 'user_disabled', 'too_many_attempts'] as const
