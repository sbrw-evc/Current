// Passkey ceremonies in the browser: Windows Hello (face, fingerprint, iris, PIN), Touch ID /
// Face ID, Android biometrics and security keys. The server sends WebAuthn options with binary
// fields in base64url; the answer goes back the same way.

type Json = Record<string, unknown>

const b64 = (buf: ArrayBuffer) => {
  let s = ''
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const buf = (s: string) => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer
}

export function passkeysSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials
}

// platformAuthenticator: Windows Hello, Touch ID or Android biometrics on this device.
export async function platformAuthenticator() {
  try {
    return passkeysSupported() && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
  } catch {
    return false
  }
}

export class PasskeyError extends Error {
  code: 'passkey_cancelled' | 'passkey_unsupported'
  constructor(code: 'passkey_cancelled' | 'passkey_unsupported', message?: string) {
    super(message ?? code)
    this.code = code
  }
}

function unwrap(options: Json): Json {
  return ((options.publicKey as Json) ?? options) as Json
}

function credentialJSON(c: PublicKeyCredential): Json {
  const r = c.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse
  const response: Json = { clientDataJSON: b64(r.clientDataJSON) }
  if ('attestationObject' in r && r.attestationObject) {
    response.attestationObject = b64(r.attestationObject)
    response.transports = typeof r.getTransports === 'function' ? r.getTransports() : []
  }
  if ('authenticatorData' in r && r.authenticatorData) {
    response.authenticatorData = b64(r.authenticatorData)
    response.signature = b64(r.signature)
    if (r.userHandle) response.userHandle = b64(r.userHandle)
  }
  return {
    id: c.id,
    rawId: b64(c.rawId),
    type: c.type,
    response,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults: c.getClientExtensionResults?.() ?? {},
  }
}

function fail(e: unknown): never {
  if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')) throw new PasskeyError('passkey_cancelled', e.message)
  if (e instanceof DOMException && e.name === 'NotSupportedError') throw new PasskeyError('passkey_unsupported', e.message)
  throw e
}

// createPasskey runs navigator.credentials.create with the server's registration options.
export async function createPasskey(options: Json): Promise<Json> {
  if (!passkeysSupported()) throw new PasskeyError('passkey_unsupported')
  const o = unwrap(options)
  const user = o.user as Json
  const publicKey = {
    ...o,
    challenge: buf(o.challenge as string),
    user: { ...user, id: buf(user.id as string) },
    excludeCredentials: ((o.excludeCredentials as Json[]) ?? []).map((c) => ({ ...c, id: buf(c.id as string) })),
  } as unknown as PublicKeyCredentialCreationOptions
  try {
    const c = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
    if (!c) throw new PasskeyError('passkey_cancelled')
    return credentialJSON(c)
  } catch (e) {
    fail(e)
  }
}

// getPasskey runs navigator.credentials.get with the server's sign-in options.
export async function getPasskey(options: Json, signal?: AbortSignal): Promise<Json> {
  if (!passkeysSupported()) throw new PasskeyError('passkey_unsupported')
  const o = unwrap(options)
  const publicKey = {
    ...o,
    challenge: buf(o.challenge as string),
    allowCredentials: ((o.allowCredentials as Json[]) ?? []).map((c) => ({ ...c, id: buf(c.id as string) })),
  } as unknown as PublicKeyCredentialRequestOptions
  try {
    const c = (await navigator.credentials.get({ publicKey, signal })) as PublicKeyCredential | null
    if (!c) throw new PasskeyError('passkey_cancelled')
    return credentialJSON(c)
  } catch (e) {
    fail(e)
  }
}
