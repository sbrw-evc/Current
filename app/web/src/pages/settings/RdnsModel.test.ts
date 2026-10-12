import { describe, expect, it } from 'vitest'
import { hitRatio, parseServers, validServer } from './RdnsModel'

describe('reverse DNS settings', () => {
  it('parses servers', () => {
    expect(parseServers(' 192.0.2.53\n dns.example:5353, [2001:db8::53]:53 ')).toEqual(['192.0.2.53', 'dns.example:5353', '[2001:db8::53]:53'])
    expect(parseServers('')).toEqual([])
  })
  it('validates servers', () => {
    for (const s of ['192.0.2.53', '192.0.2.53:53', 'dns.example', 'dns.example:5353', '[2001:db8::53]:53', '2001:db8::53']) expect(validServer(s), s).toBe(true)
    for (const s of ['dns.example:99999', 'a b', 'https://dns.example', '..', '[x]:53']) expect(validServer(s), s).toBe(false)
  })
  it('computes the cache hit ratio', () => {
    expect(hitRatio(undefined)).toBeNull()
    const s = { enabled: true, cached: 1, queued: 0, hits: 3, misses: 1, dropped: 0, found: 1, not_found: 0, errors: 0 }
    expect(hitRatio(s)).toBe(0.75)
    expect(hitRatio({ ...s, hits: 0, misses: 0 })).toBeNull()
  })
})
