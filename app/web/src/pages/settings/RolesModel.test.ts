import { describe, expect, it } from 'vitest'
import { handle } from '../../mock/server'
import { catalog } from '../../mock/roles'
import { allPermissions, draftOf, grouped, lockedView, normalize, sameDraft, toggle, validRoleName, type RoleRecord } from './RolesModel'

describe('roles', () => {
  it('checks role names', () => {
    expect(validRoleName('NOC')).toBe(true)
    expect(validRoleName('  ')).toBe(false)
    expect(validRoleName('x'.repeat(64))).toBe(true)
    expect(validRoleName('x'.repeat(65))).toBe(false)
  })
  it('gives the view of a page with any of its functions, as the server does', () => {
    expect(normalize(catalog, ['settings.inventory:sync', 'flows:view', 'nope:x'])).toEqual(['flows:view', 'settings.inventory:view', 'settings.inventory:sync'])
    // A page without a view function stays as it is.
    expect(normalize(catalog, ['scope:umbrella'])).toEqual(['scope:umbrella'])
  })
  it('toggles permissions with their view', () => {
    let p = toggle(catalog, [], 'exporters:edit', true)
    expect(p).toEqual(['exporters:view', 'exporters:edit'])
    expect(lockedView(p, 'exporters:view')).toBe(true)
    expect(lockedView(p, 'exporters:edit')).toBe(false)
    p = toggle(catalog, p, 'exporters:edit', false)
    expect(p).toEqual(['exporters:view'])
    expect(lockedView(p, 'exporters:view')).toBe(false)
    expect(toggle(catalog, ['detector:view', 'detector:edit', 'flows:view'], 'detector:view', false)).toEqual(['flows:view'])
  })
  it('groups the catalogue pages and compares drafts', () => {
    const g = grouped(catalog)
    expect(g.map((x) => x.group.id)).toEqual(['traffic', 'network', 'org', 'settings'])
    expect(g.flatMap((x) => x.pages).length).toBe(catalog.pages.length)
    const r: RoleRecord = { id: 5, ident: 'noc', name: 'NOC', description: 'x', builtin: false, permissions: ['flows:view', 'visualize:view'], users: 0 }
    expect(sameDraft(draftOf(r), { name: ' NOC ', description: 'x', permissions: ['visualize:view', 'flows:view'] })).toBe(true)
    expect(sameDraft(draftOf(r), { ...draftOf(r), permissions: [] })).toBe(false)
    expect(draftOf(null)).toEqual({ name: '', description: '', permissions: [] })
  })
  it('lists the catalogue in the mock with every permission once', () => {
    const all = allPermissions(catalog)
    expect(new Set(all).size).toBe(all.length)
    expect(all).toContain('roles:edit')
  })
})

describe('roles in the mock server', () => {
  it('creates, changes and deletes custom roles and keeps built-in ones', async () => {
    expect((await handle('GET', '/api/access/catalog', undefined)).status).toBe(200)
    const created = await handle('POST', '/api/roles', { name: 'Shift lead', description: 'd', permissions: ['detector:edit'] })
    expect(created.status).toBe(201)
    const r = created.body as RoleRecord
    expect(r.ident).toBe('shift-lead')
    expect(r.permissions).toEqual(['detector:view', 'detector:edit'])
    expect((await handle('POST', '/api/roles', { name: 'Shift lead' })).status).toBe(409)
    expect((await handle('POST', '/api/roles', { name: 'x', permissions: ['nope:x'] })).status).toBe(400)
    const changed = await handle('PUT', `/api/roles/${r.id}`, { name: 'Shift leads', permissions: ['flows:view'] })
    expect(changed.status).toBe(200)
    expect((changed.body as RoleRecord).ident).toBe('shift-lead')
    expect((await handle('PUT', '/api/roles/1', { name: 'x' })).status).toBe(409)
    expect((await handle('DELETE', '/api/roles/2', undefined)).status).toBe(409)
    expect((await handle('DELETE', '/api/roles/4', undefined)).status).toBe(409)
    expect((await handle('DELETE', `/api/roles/${r.id}`, undefined)).status).toBe(200)
    expect(((await handle('GET', '/api/roles', undefined)).body as { results: RoleRecord[] }).results.some((x) => x.id === r.id)).toBe(false)
  })
})
