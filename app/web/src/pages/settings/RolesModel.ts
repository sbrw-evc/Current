import type { Locale } from '../../api/types'

// Settings → Roles: the role records of GET /api/roles and the permission catalogue of
// GET /api/access/catalog (docs/api.md "Users and roles"). Permissions are "<page>:<function>";
// any function of a page gives its "view" too, as the server's access.Normalize does.

export type Text = Record<Locale, string>
export type CatalogFeature = { id: string; title: Text }
export type CatalogPage = { id: string; group: string; title: Text; features: CatalogFeature[] }
export type CatalogGroup = { id: string; title: Text }
export type Catalog = { groups: CatalogGroup[]; pages: CatalogPage[] }

export type RoleRecord = {
  id: number
  ident: string
  name: string
  description: string
  builtin: boolean
  permissions: string[]
  users: number
  created_at?: string
  updated_at?: string
}

export type RoleDraft = { name: string; description: string; permissions: string[] }

export const VIEW = 'view'
export const NAME_MAX = 64

export const perm = (page: string, feature: string) => `${page}:${feature}`

export function validRoleName(name: string) {
  const n = name.trim()
  return n.length > 0 && n.length <= NAME_MAX
}

// allPermissions lists every permission of the catalogue in its order.
export function allPermissions(c: Catalog): string[] {
  return c.pages.flatMap((p) => p.features.map((f) => perm(p.id, f.id)))
}

function hasView(c: Catalog, page: string) {
  return c.pages.some((p) => p.id === page && p.features.some((f) => f.id === VIEW))
}

// normalize keeps the known permissions, adds the "view" of every page with another function and
// sorts them in catalogue order (what the server stores).
export function normalize(c: Catalog, perms: string[]): string[] {
  const all = allPermissions(c)
  const set = new Set<string>()
  for (const p of perms) {
    if (!all.includes(p)) continue
    set.add(p)
    const page = p.slice(0, p.indexOf(':'))
    if (hasView(c, page)) set.add(perm(page, VIEW))
  }
  return all.filter((p) => set.has(p))
}

// toggle turns one permission on or off. Turning a function on gives the page's view; turning the
// view off takes the other functions of the page away.
export function toggle(c: Catalog, perms: string[], p: string, on: boolean): string[] {
  if (on) return normalize(c, [...perms, p])
  const [page, feature] = [p.slice(0, p.indexOf(':')), p.slice(p.indexOf(':') + 1)]
  const left = feature === VIEW ? perms.filter((x) => !x.startsWith(page + ':')) : perms.filter((x) => x !== p)
  return normalize(c, left)
}

// required: a function that cannot be turned off alone (the page's view while another of its
// functions is on) is shown checked and locked.
export function lockedView(perms: string[], p: string): boolean {
  const i = p.indexOf(':')
  const page = p.slice(0, i)
  return p.slice(i + 1) === VIEW && perms.some((x) => x.startsWith(page + ':') && x !== p)
}

// grouped returns the catalogue pages by group, in the group order, without empty groups.
export function grouped(c: Catalog): { group: CatalogGroup; pages: CatalogPage[] }[] {
  return c.groups.map((g) => ({ group: g, pages: c.pages.filter((p) => p.group === g.id) })).filter((x) => x.pages.length > 0)
}

export function draftOf(r?: RoleRecord | null): RoleDraft {
  return r ? { name: r.name, description: r.description, permissions: [...r.permissions] } : { name: '', description: '', permissions: [] }
}

export function sameDraft(a: RoleDraft, b: RoleDraft) {
  return a.name.trim() === b.name.trim() && a.description.trim() === b.description.trim() && [...a.permissions].sort().join(',') === [...b.permissions].sort().join(',')
}

// ERROR_KEYS are the server's error codes of /api/roles with their own text on the page.
export const ERROR_KEYS = ['invalid_name', 'invalid_permission', 'builtin_role', 'role_in_use', 'last_admin', 'conflict'] as const
