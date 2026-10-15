// The API client: JSON in and out, the CSRF header on changing requests (as in Umbrella), and a
// 401 hook so the app returns to the sign-in page when the session ends.

export class ApiError extends Error {
  status: number
  code: string
  detail?: string

  constructor(status: number, code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code)
    this.status = status
    this.code = code
    this.detail = detail
  }
}

let csrf = ''
let onUnauthorized: (() => void) | null = null

export function setCsrf(v: string) {
  csrf = v
}

export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn
}

// Requests whose 401 is an answer, not an expired session.
const QUIET_401 = ['/api/auth/me', '/api/setup/check-code']

export async function api<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method,
      credentials: 'same-origin',
      signal,
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(csrf && method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError(0, 'network', e instanceof Error ? e.message : String(e))
  }
  if (res.status === 401 && !QUIET_401.includes(path)) onUnauthorized?.()
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown = undefined
  try {
    data = text ? JSON.parse(text) : undefined
  } catch {
    data = undefined
  }
  if (!res.ok) {
    const d = (data ?? {}) as { error?: string; message?: string }
    throw new ApiError(res.status, d.error ?? `http_${res.status}`, d.message)
  }
  return data as T
}

export const get = <T>(path: string, signal?: AbortSignal) => api<T>('GET', path, undefined, signal)
export const post = <T>(path: string, body?: unknown, signal?: AbortSignal) => api<T>('POST', path, body ?? {}, signal)
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body)
export const del = <T>(path: string) => api<T>('DELETE', path)
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, body)
