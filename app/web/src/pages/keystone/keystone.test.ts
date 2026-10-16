import { describe, expect, it } from 'vitest'
import { navStrings } from '../../shell/strings'
import { setupStrings } from '../setup/strings'
import { autoRedirect, safeNext, ssoErrorKey, SSO_ERRORS, startURL } from './model'
import { spaStrings } from './strings'
import { rolesStrings } from '../settings/rolesStrings'
import { devicesStrings } from '../devices/strings'

describe('sign-in through Keystone', () => {
  it('keeps the return page inside Current', () => {
    expect(safeNext('/visualize?f=1')).toBe('/visualize?f=1')
    expect(safeNext('//evil.example')).toBe('/')
    expect(safeNext('https://evil.example')).toBe('/')
    expect(safeNext('/login?next=/x')).toBe('/')
    expect(safeNext(null)).toBe('/')
  })
  it('starts at /api/auth/spa/start', () => {
    expect(startURL('/flows')).toBe('/api/auth/spa/start?return=%2Fflows')
    expect(startURL(null, { prompt: 'login' })).toBe('/api/auth/spa/start?return=%2F&prompt=login')
  })
  it('goes to Keystone by itself only when nothing stops it', () => {
    const on = { connected: true }
    expect(autoRedirect(on, null, false)).toBe(true)
    expect(autoRedirect(on, 'access_denied', false)).toBe(false)
    expect(autoRedirect(on, null, true)).toBe(false)
    expect(autoRedirect({ connected: false }, null, false)).toBe(false)
    expect(autoRedirect({ connected: true, mock: true }, null, false)).toBe(false)
    expect(autoRedirect(undefined, null, false)).toBe(false)
  })
  it('has a text for every error Keystone or Current sends back', () => {
    for (const code of SSO_ERRORS) expect(spaStrings.en[ssoErrorKey(code)], code).toBeTruthy()
    expect(ssoErrorKey('server_error')).toBe('sso.other')
  })
})

describe('translations', () => {
  it('have the same keys in English and Russian', () => {
    for (const [name, dict] of Object.entries({ spaStrings, navStrings, setupStrings, rolesStrings, devicesStrings })) {
      const en = Object.keys(dict.en).sort()
      const ru = Object.keys(dict.ru).sort()
      expect(ru, name).toEqual(en)
      for (const k of en) expect(dict.ru[k], `${name}: ${k}`).not.toBe('')
    }
  })
})
