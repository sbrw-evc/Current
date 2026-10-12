import { describe, expect, it } from 'vitest'
import { defaultRedirect, isGuid, validTenant } from './EntraModel'

describe('Entra ID settings', () => {
  it('checks tenants and GUIDs', () => {
    expect(validTenant('11111111-2222-3333-4444-555555555555')).toBe(true)
    expect(validTenant('contoso.onmicrosoft.com')).toBe(true)
    expect(validTenant('common')).toBe(false)
    expect(validTenant('')).toBe(false)
    expect(isGuid('AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee')).toBe(true)
    expect(isGuid('app')).toBe(false)
  })
  it('builds the redirect URI', () => {
    expect(defaultRedirect('https://flow.example/')).toBe('https://flow.example/api/auth/entra/callback')
  })
})
