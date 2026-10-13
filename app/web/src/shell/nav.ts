import { AtSign, CloudUpload, Cable, Waypoints, Route, Activity, Network, Umbrella, BarChart3, Building2, KeyRound, BellRing, Cpu, Database, Home, LineChart, ListChecks, ListTree, LockKeyhole, Radar, Router, Settings, ShieldAlert, Tags, type LucideIcon } from 'lucide-react'

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
      { id: 'dependencies', path: '/dependencies', icon: Network, perm: 'dependencies:view' },
    ],
  },
  {
    id: 'sources',
    icon: Cpu,
    pages: [{ id: 'exporters', path: '/exporters', icon: Router, perm: 'exporters:view' }],
  },
  {
    id: 'detector',
    icon: Radar,
    pages: [
      { id: 'detector-rules', path: '/detector/rules', icon: ListChecks, perm: 'detector:view' },
      { id: 'detector-status', path: '/detector/status', icon: BellRing, perm: 'detector:view' },
    ],
  },
  {
    id: 'settings',
    icon: Settings,
    pages: [
      { id: 'inventory', path: '/settings/inventory-db', icon: Database, perm: 'settings.inventory:view' },
      { id: 'classifiers', path: '/settings/classifiers', icon: Tags, perm: 'settings.classifiers:view' },
      { id: 'umbrella', path: '/settings/umbrella', icon: Umbrella, perm: 'settings.umbrella:view' },
      { id: 'openbao', path: '/settings/openbao', icon: LockKeyhole, perm: 'settings.openbao:view' },
      { id: 'tokens', path: '/settings/api-tokens', icon: KeyRound, perm: 'tokens:view' },
      { id: 'entra', path: '/settings/entra', icon: Building2, perm: 'users:view' },
      { id: 'threat', path: '/settings/threat', icon: ShieldAlert, perm: 'settings.threat:view' },
      { id: 'rdns', path: '/settings/rdns', icon: AtSign, perm: 'settings.rdns:view' },
      { id: 'flowlogs', path: '/settings/flowlogs', icon: CloudUpload, perm: 'settings.flowlogs:view' },
      { id: 'gnmi', path: '/settings/gnmi', icon: Waypoints, perm: 'settings.gnmi:view' },
      { id: 'snmp', path: '/settings/snmp', icon: Cable, perm: 'settings.snmp:view' },
      { id: 'bmp', path: '/settings/bmp', icon: Route, perm: 'settings.bmp:view' },
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
