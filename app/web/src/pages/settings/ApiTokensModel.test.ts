import { describe, expect, it } from 'vitest'
import { expiryDate, tokenState, validAccountName } from './ApiTokensModel'

describe('API tokens', () => {
  const now = Date.parse('2026-10-12T10:00:00Z')
  it('derives the token state', () => {
    expect(tokenState({ revoked_at: null, expires_at: null }, now)).toBe('active')
    expect(tokenState({ revoked_at: null, expires_at: '2026-10-13T00:00:00Z' }, now)).toBe('active')
    expect(tokenState({ revoked_at: null, expires_at: '2026-10-11T00:00:00Z' }, now)).toBe('expired')
    expect(tokenState({ revoked_at: '2026-10-01T00:00:00Z', expires_at: '2026-10-11T00:00:00Z' }, now)).toBe('revoked')
  })
  it('computes expiry dates', () => {
    expect(expiryDate(30, new Date(now))).toBe('2026-11-11')
    expect(expiryDate(0, new Date(now))).toBe('')
  })
  it('checks account names', () => {
    expect(validAccountName('inventory-db')).toBe(true)
    expect(validAccountName(' ')).toBe(false)
    expect(validAccountName('a b')).toBe(false)
    expect(validAccountName('a/b')).toBe(false)
    expect(validAccountName('x'.repeat(65))).toBe(false)
  })
})
