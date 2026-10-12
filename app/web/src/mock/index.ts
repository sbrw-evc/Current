import { handle } from './server'

// installMock routes fetch('/api/…') to the in-browser mock server.
export function installMock() {
  const real = window.fetch.bind(window)
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const path = url.startsWith(window.location.origin) ? url.slice(window.location.origin.length) : url
    if (!path.startsWith('/api/')) return real(input, init)
    const method = (init?.method ?? 'GET').toUpperCase()
    let body: unknown = undefined
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body)
      } catch {
        body = undefined
      }
    }
    const r = await handle(method, path, body)
    if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } })
  }
  console.info('[flow] mock API is on (VITE_MOCK=1)')
}
