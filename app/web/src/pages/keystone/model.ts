// Keystone, sign-in and access for the Umbrella family (docs/identity-federation.md): people sign in there, Current
// reads them and their roles every five minutes and publishes its roles as Keystone's catalogue.

export const SPA_REPO = 'https://github.com/sbrw-evc/keystone'
export const SPA_PROTOCOL = SPA_REPO + '/blob/main/docs/protocol.md'

// GET /api/auth/spa: what the sign-in page needs (no session).
export type SpaInfo = { connected: boolean; issuer?: string; application?: string; error?: string; mock?: boolean }

export type SpaRole = { id: string; name: string; description?: string }

// GET /api/settings/spa.
export type SpaView = {
  connected: boolean
  key_source?: 'env' | 'file' | 'openbao' | ''
  key_error?: string
  redirect_uri: string
  post_logout_redirect_uri: string
  issuer: string
  client_id: string
  application: { id: string; name: string; type: string }
  account_url: string
  sign_out_url: string
  methods: { id: string; title: string }[]
  last_sync?: string
  ok: boolean
  error?: string
  users: number
  created: number
  updated: number
  bound: number
  disabled: number
  conflicts: string[]
  no_role: string[]
  catalogue: { at?: string; roles: number; error?: string }
  counts: { enabled: number; disabled: number; legacy: number }
  roles: SpaRole[]
  interval: string
}

// The sign-out leaves this mark so that the sign-in page does not go straight back to Keystone.
export const SIGNED_OUT_KEY = 'flow.signedOut'

export function markSignedOut() {
  try {
    sessionStorage.setItem(SIGNED_OUT_KEY, '1')
  } catch {
    // Without storage the sign-in page goes to Keystone again, which shows its own sign-in.
  }
}

// takeSignedOut reads and clears the mark.
export function takeSignedOut(): boolean {
  try {
    const v = sessionStorage.getItem(SIGNED_OUT_KEY) === '1'
    sessionStorage.removeItem(SIGNED_OUT_KEY)
    return v
  } catch {
    return false
  }
}

// safeNext keeps the page to return to inside Current.
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\') || next.startsWith('/api/') || next.startsWith('/login')) return '/'
  return next
}

// startURL is where the "Sign in with Keystone" button goes.
export function startURL(next: string | null | undefined, opts: { prompt?: 'login'; loginHint?: string } = {}): string {
  const q = new URLSearchParams({ return: safeNext(next) })
  if (opts.prompt) q.set('prompt', opts.prompt)
  if (opts.loginHint) q.set('login_hint', opts.loginHint)
  return `/api/auth/spa/start?${q.toString()}`
}

// autoRedirect: the sign-in page goes to Keystone by itself when Current is connected, nothing went wrong
// and the person was not just signed out.
export function autoRedirect(info: SpaInfo | undefined, ssoError: string | null, signedOut: boolean): boolean {
  return !!info?.connected && !info.mock && !ssoError && !signedOut
}

// Known sso_error codes have their own text; others fall back to a generic one.
export const SSO_ERRORS = ['access_denied', 'no_role', 'state', 'invalid_token', 'spa_unavailable', 'not_connected', 'account_conflict', 'login_required', 'user_disabled'] as const

export function ssoErrorKey(code: string): string {
  return (SSO_ERRORS as readonly string[]).includes(code) ? `sso.${code}` : 'sso.other'
}
