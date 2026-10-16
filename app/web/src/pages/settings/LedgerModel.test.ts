import { describe, expect, it } from 'vitest'
import { canCreateAddresses, deviceCreateUrl } from './LedgerModel'

describe('deviceCreateUrl', () => {
  it('links to the device creation form', () => {
    expect(deviceCreateUrl('https://inventory.example')).toBe('https://inventory.example/dcim/devices?_sel=new')
    expect(deviceCreateUrl('https://inventory.example/')).toBe('https://inventory.example/dcim/devices?_sel=new')
    expect(deviceCreateUrl('https://inventory.example/api/v1/')).toBe('https://inventory.example/dcim/devices?_sel=new')
  })
  it('needs an address', () => {
    expect(deviceCreateUrl('')).toBeNull()
    expect(deviceCreateUrl('inventory')).toBeNull()
  })
})

describe('canCreateAddresses', () => {
  const v = { hook_secret_set: false, write_token_set: true, hook_url: '', inventory_url: 'https://inv' }
  it('is hidden without the editor token or the permission', () => {
    expect(canCreateAddresses(v, true)).toBe(true)
    expect(canCreateAddresses({ ...v, write_token_set: false }, true)).toBe(false)
    expect(canCreateAddresses(v, false)).toBe(false)
    expect(canCreateAddresses(undefined, true)).toBe(false)
  })
})
