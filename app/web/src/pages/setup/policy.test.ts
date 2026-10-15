import { describe, expect, it } from 'vitest'
import { DEFAULT_POLICY, failed, publicURLOk } from './policy'

describe('password policy', () => {
  it('follows the corporate default of the family', () => {
    expect(failed('Short-1', 'admin', DEFAULT_POLICY)).toEqual(['length'])
    expect(failed('onlylettershere', 'admin', DEFAULT_POLICY)).toEqual(['digits', 'special', 'mixed_case'])
    expect(failed('Correct-Horse-9', 'admin', DEFAULT_POLICY)).toEqual([])
    expect(failed('Пароль-Надёжный-2026', 'admin', DEFAULT_POLICY)).toEqual(['letters'])
    expect(failed('Admin2026!', 'admin', { ...DEFAULT_POLICY, min_length: 8 })).toContain('common')
  })
  it('allows any alphabet when asked', () => {
    expect(failed('Пароль-Надёжный-2026', 'admin', { ...DEFAULT_POLICY, letters: 'any' })).toEqual([])
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
