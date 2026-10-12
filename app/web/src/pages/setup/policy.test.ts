import { describe, expect, it } from 'vitest'
import { DEFAULT_POLICY, failed, publicURLOk } from './policy'

describe('password policy', () => {
  it('needs 12+ letters and digits by default', () => {
    expect(failed('short1', 'admin', DEFAULT_POLICY)).toEqual(['length'])
    expect(failed('onlylettersherehere', 'admin', DEFAULT_POLICY)).toEqual(['digits'])
    expect(failed('Пароль-надёжный-2026', 'admin', DEFAULT_POLICY)).toEqual([])
    expect(failed('admin-password-1', 'admin', DEFAULT_POLICY)).toEqual(['username'])
  })
  it('checks special characters when asked', () => {
    expect(failed('abcdefghijk12', 'x', { ...DEFAULT_POLICY, symbols: true })).toEqual(['symbols'])
  })
})

describe('public URL', () => {
  it('accepts http(s) without a query', () => {
    expect(publicURLOk('https://flow.example.com')).toBe(true)
    expect(publicURLOk('')).toBe(true)
    expect(publicURLOk('ftp://x')).toBe(false)
    expect(publicURLOk('https://x/?a=1')).toBe(false)
  })
})
