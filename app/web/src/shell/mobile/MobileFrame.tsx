import { useEffect, useState, type ReactNode } from 'react'
import { ChevronRight, Menu, Monitor, type LucideIcon } from 'lucide-react'
import { motion } from 'motion/react'
import { Link, useLocation } from 'react-router-dom'
import { useT } from '../../i18n'
import { spring } from '../../ui/ui'
import { useDetectorStatus } from '../../pages/detector/api'
import { owns, visibleNav, type PageDef } from '../nav'
import { useSession } from '../session'
import { navStrings } from '../strings'
import { UserMenu } from '../UserMenu'
import { mobileReady, pageOf, TAB_SLOTS } from './pages'
import { Sheet } from './Sheet'
import { mobileStrings } from './strings'
import './mobile.css'

// MobileFrame is the shell of the phone layout, as Beacon's (app/web/src/app/mobile/MobileFrame.tsx):
// the title of the page with the user menu on top, the page in between and the tab bar at the
// bottom: the overview, the alerts, the exporters, the charts and "More".
export function MobileFrame({ children }: { children: ReactNode }) {
  const t = useT(mobileStrings)
  const { pathname } = useLocation()
  const { can } = useSession()
  const [more, setMore] = useState(false)
  const pages = visibleNav(can).flatMap((g) => g.pages)
  const home = pages.find((p) => p.id === 'home')
  const tabs = TAB_SLOTS.flatMap((slot) => pages.find((p) => slot.includes(p.id)) ?? [])
  const inTabs = pathname === '/' || tabs.some((p) => owns(p, pathname))

  useEffect(() => setMore(false), [pathname])

  return (
    <div className="m-shell">
      <TopBar />
      <div id="app-main" className="m-main">
        {children}
      </div>
      <nav className="m-tabs" aria-label={t('m.tabs')}>
        {home && <Tab to="/" icon={home.icon} label="m.tab.home" active={pathname === '/' && !more} />}
        {tabs.map((p) => (
          <Tab key={p.id} to={p.path} icon={p.icon} label={`m.tab.${p.id}`} active={owns(p, pathname) && !more} badge={p.id === 'detector-status'} />
        ))}
        <TabButton icon={Menu} label="m.tab.more" active={more || !inTabs} onClick={() => setMore(true)} />
      </nav>
      <MoreSheet open={more} onClose={() => setMore(false)} pages={pages} tabs={home ? [home, ...tabs] : tabs} />
    </div>
  )
}

function TopBar() {
  const t = useT(navStrings)
  const { pathname } = useLocation()
  const page = pageOf(pathname)
  return (
    <header className="m-top">
      <Link to="/" className="m-top-brand" aria-label="Current">
        <img src="/logo.svg" alt="" width={28} height={28} />
      </Link>
      <h1 className="m-top-title">{page ? t(`page.${page.id}`) : 'Current'}</h1>
      <div className="m-top-end">
        {import.meta.env.VITE_MOCK === '1' && <span className="pill pill-warn mock-badge">{t('mock.badge')}</span>}
        <UserMenu />
      </div>
    </header>
  )
}

// Badge: the number of firing alerts on the Alerts tab.
function Badge() {
  const t = useT(mobileStrings)
  const { can } = useSession()
  const q = useDetectorStatus(30e3, can('detector:view'))
  const n = q.data?.alerts.filter((a) => a.state === 'firing').length ?? 0
  if (!n) return null
  return (
    <span className="m-tab-badge tone-error" aria-label={t('m.badge', { n })}>
      {n > 99 ? '99+' : n}
    </span>
  )
}

function TabInner({ icon: Icon, label, active, badge }: { icon: LucideIcon; label: string; active: boolean; badge?: boolean }) {
  const t = useT(mobileStrings)
  return (
    <>
      {active && <motion.span layoutId="m-tab-pill" className="m-tab-pill" transition={spring} />}
      <span className="m-tab-icon">
        <Icon size={21} aria-hidden />
        {badge && <Badge />}
      </span>
      <span className="m-tab-label">{t(label)}</span>
    </>
  )
}

function Tab({ to, active, ...rest }: { to: string; icon: LucideIcon; label: string; active: boolean; badge?: boolean }) {
  return (
    <Link to={to} className={`m-tab${active ? ' active' : ''}`} aria-current={active ? 'page' : undefined}>
      <TabInner active={active} {...rest} />
    </Link>
  )
}

function TabButton({ onClick, active, ...rest }: { icon: LucideIcon; label: string; active: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`m-tab${active ? ' active' : ''}`} onClick={onClick} aria-haspopup="dialog">
      <TabInner active={active} {...rest} />
    </button>
  )
}

// MoreSheet lists the sections that are not in the tab bar: first those made for the phone, then
// those better opened on a computer (they still open here, after a note), grouped as in the menu.
function MoreSheet({ open, onClose, pages, tabs }: { open: boolean; onClose: () => void; pages: PageDef[]; tabs: PageDef[] }) {
  const t = useT(mobileStrings)
  const tn = useT(navStrings)
  const { pathname } = useLocation()
  const { can } = useSession()
  const rest = pages.filter((p) => !tabs.includes(p))
  const phone = rest.filter(mobileReady)
  const desk = visibleNav(can)
    .map((g) => ({ ...g, pages: g.pages.filter((p) => !tabs.includes(p) && !mobileReady(p)) }))
    .filter((g) => g.pages.length > 0)
  return (
    <Sheet open={open} title={t('m.more.title')} onClose={onClose}>
      {phone.length > 0 && (
        <div className="m-more-grid">
          {phone.map((p) => (
            <Link key={p.id} to={p.path} className={`m-more-tile${owns(p, pathname) ? ' active' : ''}`}>
              <span className="m-more-icon">
                <p.icon size={20} aria-hidden />
              </span>
              <span>{tn(`page.${p.id}`)}</span>
            </Link>
          ))}
        </div>
      )}
      {desk.length > 0 && (
        <section className="m-more-desk">
          <h3>
            <Monitor size={15} aria-hidden />
            {t('m.more.desktop')}
          </h3>
          <p className="muted">{t('m.more.desktop.hint')}</p>
          {desk.map((g) => (
            <div key={g.id} className="m-more-list">
              <h4 className="m-more-group">{tn(`group.${g.id}`)}</h4>
              {g.pages.map((p) => (
                <Link key={p.id} to={p.path} className={`m-more-row${owns(p, pathname) ? ' active' : ''}`}>
                  <p.icon size={17} aria-hidden />
                  <span>{tn(`page.${p.id}`)}</span>
                  <ChevronRight size={16} aria-hidden className="m-more-chev" />
                </Link>
              ))}
            </div>
          ))}
        </section>
      )}
    </Sheet>
  )
}
