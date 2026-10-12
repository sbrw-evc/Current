import { Activity, BarChart3, Cpu, Database, Home, LineChart, ListTree, LockKeyhole, Router, Settings, Tags, type LucideIcon } from 'lucide-react'

// The menu: groups of pages in Umbrella's sidebar style. A page the role can't see is hidden
// (the API enforces the permissions anyway).
export type PageDef = { id: string; path: string; icon: LucideIcon; perm?: string; subtitle?: string }
export type NavGroup = { id: string; icon: LucideIcon; pages: PageDef[] }

export const NAV: NavGroup[] = [
  {
    id: 'analysis',
    icon: Activity,
    pages: [
      { id: 'home', path: '/', icon: Home },
      { id: 'visualize', path: '/visualize', icon: LineChart, perm: 'visualize:view' },
      { id: 'flows', path: '/flows', icon: ListTree, perm: 'flows:view' },
    ],
  },
  {
    id: 'sources',
    icon: Cpu,
    pages: [{ id: 'exporters', path: '/exporters', icon: Router, perm: 'exporters:view' }],
  },
  {
    id: 'settings',
    icon: Settings,
    pages: [
      { id: 'inventory', path: '/settings/inventory-db', icon: Database, perm: 'settings.inventory:view' },
      { id: 'classifiers', path: '/settings/classifiers', icon: Tags, perm: 'settings.classifiers:view' },
      { id: 'openbao', path: '/settings/openbao', icon: LockKeyhole, perm: 'settings.openbao:view' },
    ],
  },
]

export const ALL_PAGES = NAV.flatMap((g) => g.pages)
export const HomeIcon = BarChart3

export function owns(page: PageDef, path: string) {
  return page.path === '/' ? path === '/' : path === page.path || path.startsWith(page.path + '/')
}

export function visibleNav(can: (p: string) => boolean): NavGroup[] {
  return NAV.map((g) => ({ ...g, pages: g.pages.filter((p) => !p.perm || can(p.perm)) })).filter((g) => g.pages.length > 0)
}
