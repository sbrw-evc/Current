import { describe, expect, it } from 'vitest'
import { publicURLOk, spaKeyOk } from './url'

describe('public URL', () => {
  it('accepts http(s) without a query', () => {
    expect(publicURLOk('https://flow.example.com')).toBe(true)
    expect(publicURLOk('')).toBe(true)
    expect(publicURLOk('ftp://x')).toBe(false)
    expect(publicURLOk('https://x/?a=1')).toBe(false)
  })
})

describe('Keystone connection key', () => {
  it('takes only spa1. keys', () => {
    expect(spaKeyOk('spa1.eyJpc3N1ZXIiOiJodHRwczovL3NwYS5leGFtcGxlLmNvbSJ9')).toBe(true)
    expect(spaKeyOk('umbid1.eyJpc3N1ZXIiOiJodHRwczovL3NwYS5leGFtcGxlLmNvbSJ9')).toBe(false)
    expect(spaKeyOk('spa1.short')).toBe(false)
  })
})
