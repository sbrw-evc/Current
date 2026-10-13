import { describe, expect, it } from 'vitest'
import { mobileReady, pageOf } from './pages'

describe('pageOf', () => {
  it('finds the page that owns the path, the longest path first', () => {
    expect(pageOf('/')?.id).toBe('home')
    expect(pageOf('/detector/rules/ddos')?.id).toBe('detector-rules')
    expect(pageOf('/settings/bmp')?.id).toBe('bmp')
    expect(pageOf('/go/incident')).toBeUndefined()
  })
  it('keeps settings and editors for a computer', () => {
    expect(mobileReady(pageOf('/exporters')!)).toBe(true)
    expect(mobileReady(pageOf('/settings/bmp')!)).toBe(false)
    expect(mobileReady(pageOf('/flows')!)).toBe(false)
  })
})
