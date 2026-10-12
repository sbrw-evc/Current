import { describe, expect, it } from 'vitest'
import { formatBps, formatPercent, formatPps, formatUnits } from './format'

describe('format', () => {
  it('scales bits per second with SI prefixes', () => {
    expect(formatBps(0, 'en')).toBe('0 bps')
    expect(formatBps(950, 'en')).toBe('950 bps')
    expect(formatBps(1234, 'en')).toBe('1.23 kbps')
    expect(formatBps(12.5e6, 'en')).toBe('12.5 Mbps')
    expect(formatBps(182e9, 'en')).toBe('182 Gbps')
    expect(formatBps(1.5e12, 'en')).toBe('1.5 Tbps')
  })
  it('uses Russian units and decimal comma', () => {
    expect(formatBps(1.25e9, 'ru')).toBe('1,25 Гбит/с')
    expect(formatPps(21.5e6, 'ru')).toBe('21,5 Мпак/с')
  })
  it('keeps the sign of reverse values', () => {
    expect(formatBps(-2e9, 'en')).toBe('−2 Gbps')
  })
  it('formats by units', () => {
    expect(formatUnits(3e6, 'pps', 'en')).toBe('3 Mpps')
    expect(formatUnits(45.678, 'inl2%', 'en')).toBe('45.7 %')
    expect(formatPercent(1.234, 'en')).toBe('1.23 %')
    expect(formatUnits(Number.NaN, 'l3bps', 'en')).toBe('—')
  })
})
