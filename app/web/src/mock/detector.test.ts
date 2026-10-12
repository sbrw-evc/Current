import { describe, expect, it } from 'vitest'
import type { RulesView } from '../pages/detector/model'
import { detectorMock } from './detector'

describe('detector mock: new built-in rules', () => {
  it('offers, adds and dismisses built-in rules missing from the saved set', () => {
    const v = detectorMock('GET', '/api/detector/rules', null)!.body as RulesView
    expect(v.new_defaults?.map((r) => r.id)).toEqual(['threat-contact'])
    expect(detectorMock('POST', '/api/detector/rules/add-defaults', { ids: ['nope'] })!.status).toBe(400)
    const added = detectorMock('POST', '/api/detector/rules/add-defaults', {})!.body as RulesView
    expect(added.rules.some((r) => r.id === 'threat-contact')).toBe(true)
    expect(added.new_defaults).toEqual([])
    // deleting a built-in rule dismisses it
    const put = detectorMock('PUT', '/api/detector/rules', { rules: added.rules.filter((r) => r.id !== 'threat-contact') })!
    expect(put.status).toBe(200)
    expect((put.body as RulesView).new_defaults).toEqual([])
  })
})
