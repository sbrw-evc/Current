import { describe, expect, it } from 'vitest'
import { incidentState } from './deeplink'

const now = Date.parse('2026-10-12T12:00:00Z')

describe('incident deep link', () => {
  it('filters by IP over the incident time', () => {
    const s = incidentState(new URLSearchParams('ip=10.20.14.77&from=2026-10-12T10:00:00Z&to=2026-10-12T10:30:00Z'), now)
    expect(s.filter).toBe('SrcAddr = 10.20.14.77 OR DstAddr = 10.20.14.77 OR ExporterAddress = 10.20.14.77')
    expect(s.range).toEqual({ start: '2026-10-12T09:45:00Z', end: '2026-10-12T10:45:00Z' })
  })
  it('uses the CI when there is no IP and quotes it', () => {
    const s = incidentState(new URLSearchParams("ci=web-front'end"), now)
    expect(s.filter).toBe("SrcCI = 'web-front\\'end' OR DstCI = 'web-front\\'end' OR ExporterName = 'web-front\\'end'")
    expect(s.range).toEqual({ preset: '1h' })
  })
  it('takes a prefix with <<', () => {
    expect(incidentState(new URLSearchParams('ip=10.20.0.0/16'), now).filter).toBe('SrcAddr << 10.20.0.0/16 OR DstAddr << 10.20.0.0/16 OR ExporterAddress << 10.20.0.0/16')
  })
  it('ignores an invalid IP', () => {
    expect(incidentState(new URLSearchParams('ip=1;DROP'), now).filter).toBe('')
  })
  it('filters by the Inventory DB ref when there is no address', () => {
    const s = incidentState(new URLSearchParams('ci=edge-01&ref=inventory-db:dcim.device:100&from=2026-10-12T09:30:00Z&to=2026-10-12T10:30:00Z'), now)
    expect(s.filter).toBe("SrcCI = 'inventory-db:dcim.device:100' OR DstCI = 'inventory-db:dcim.device:100' OR ExporterRef = 'inventory-db:dcim.device:100'")
    expect(s.range).toEqual({ start: '2026-10-12T09:15:00Z', end: '2026-10-12T10:45:00Z' })
  })
  it('matches an exporter CI by its address and its ref (link incidents)', () => {
    const s = incidentState(new URLSearchParams('ci=edge-01&ip=127.0.0.11&ref=inventory-db:dcim.device:2'), now)
    expect(s.filter).toBe(
      "SrcAddr = 127.0.0.11 OR DstAddr = 127.0.0.11 OR ExporterAddress = 127.0.0.11 OR SrcCI = 'inventory-db:dcim.device:2' OR DstCI = 'inventory-db:dcim.device:2' OR ExporterRef = 'inventory-db:dcim.device:2'",
    )
    expect(s.dimensions).toEqual(['SrcAddr', 'DstAddr', 'Proto'])
  })
})
