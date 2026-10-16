import { Fragment, useCallback, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { ChevronDown } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { Link, useLocation } from 'react-router-dom'
import { useT } from '../i18n'
import { spring } from '../ui/ui'
import { owns, visibleNav, type NavGroup, type PageDef } from './nav'
import { useSession } from './session'
import { navStrings } from './strings'

// The sidebar of Beacon (app/web/src/app/Sidebar.tsx): accordion groups, a sliding pill on the
// current page, a resizable width and an icon rail when collapsed.

const COMPACT = '(max-width: 860px)'
const openKey = (g: string) => `flow.sidebar.${g}`
const COLLAPSED = 'flow.sidebar.collapsed'
const WIDTH = 'flow.sidebar.width'
export const SIDEBAR_WIDTH = { min: 220, max: 400, initial: 260 }

function useCompact() {
  return useSyncExternalStore(
    (notify) => {
      const mq = window.matchMedia(COMPACT)
      mq.addEventListener('change', notify)
      return () => mq.removeEventListener('change', notify)
    },
    () => window.matchMedia(COMPACT).matches,
  )
}

function read(key: string) {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, v: string) {
  try {
    localStorage.setItem(key, v)
  } catch {
    // Kept until reload.
  }
}

export function useCollapsed() {
  const [collapsed, set] = useState(() => read(COLLAPSED) === '1')
  const toggle = useCallback(
    () =>
      set((v) => {
        write(COLLAPSED, v ? '0' : '1')
        return !v
      }),
    [],
  )
  return [collapsed, toggle] as const
}

const clamp = (w: number) => Math.round(Math.min(SIDEBAR_WIDTH.max, Math.max(SIDEBAR_WIDTH.min, w)))

export function useSidebarWidth() {
  const [width, set] = useState(() => {
    const v = Number(read(WIDTH))
    return v > 0 ? clamp(v) : SIDEBAR_WIDTH.initial
  })
  const change = useCallback((w: number) => {
    const next = clamp(w)
    set(next)
    write(WIDTH, String(next))
  }, [])
  return [width, change] as const
}

export function SidebarResizer({ width, onChange }: { width: number; onChange: (w: number) => void }) {
  const [dragging, setDragging] = useState(false)
  const start = useRef<{ x: number; width: number } | null>(null)
  useEffect(() => {
    if (!dragging) return
    document.body.classList.add('side-resizing')
    return () => document.body.classList.remove('side-resizing')
  }, [dragging])
  const stop = () => {
    start.current = null
    setDragging(false)
  }
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-valuemin={SIDEBAR_WIDTH.min}
      aria-valuemax={SIDEBAR_WIDTH.max}
      aria-valuenow={width}
      tabIndex={0}
      className={`side-resizer ${dragging ? 'dragging' : ''}`}
      onPointerDown={(e) => {
        if (e.button !== 0) return
        e.preventDefault()
        e.currentTarget.setPointerCapture(e.pointerId)
        start.current = { x: e.clientX, width }
        setDragging(true)
      }}
      onPointerMove={(e) => start.current && onChange(start.current.width + e.clientX - start.current.x)}
      onPointerUp={stop}
      onPointerCancel={stop}
      onDoubleClick={() => onChange(SIDEBAR_WIDTH.initial)}
      onKeyDown={(e) => {
        if (e.key === 'ArrowLeft') onChange(width - 16)
        else if (e.key === 'ArrowRight') onChange(width + 16)
      }}
    />
  )
}

function Tip({ anchor, children }: { anchor: HTMLElement | null; children: ReactNode }) {
  if (!anchor) return null
  const r = anchor.getBoundingClientRect()
  return createPortal(
    <motion.div role="tooltip" className="side-tip" style={{ top: r.top + r.height / 2, left: r.right + 10, y: '-50%' }} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.12 }}>
      {children}
    </motion.div>,
    document.body,
  )
}

function SideLink({ page, active, rail }: { page: PageDef; active: boolean; rail?: boolean }) {
  const t = useT(navStrings)
  const compact = useCompact()
  const [tip, setTip] = useState<HTMLElement | null>(null)
  const label = t(`page.${page.id}`)
  const show = (e: { currentTarget: HTMLElement }) => rail && !compact && setTip(e.currentTarget)
  const hide = () => setTip(null)
  return (
    <Link
      to={page.path}
      className={`side-link ${active ? 'active' : ''}`}
      aria-current={active ? 'page' : undefined}
      aria-label={rail ? label : undefined}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      onClick={hide}
    >
      {active && <motion.span layoutId="side-pill" className="side-pill" transition={spring} />}
      <page.icon size={17} aria-hidden />
      <span className="side-label">{label}</span>
      {rail && <Tip anchor={tip}>{label}</Tip>}
    </Link>
  )
}

// readOpen (as Beacon's): a group the user has not opened or closed yet is open when it is the
// first one, so a short menu greets a new user instead of every page at once.
function readOpen(group: string, first: boolean) {
  const v = read(openKey(group))
  return v === null ? first : v === '1'
}

function GroupAccordion({ group, first, path }: { group: NavGroup; first: boolean; path: string }) {
  const t = useT(navStrings)
  const compact = useCompact()
  const hasActive = group.pages.some((p) => owns(p, path))
  const [open, setOpen] = useState(() => hasActive || readOpen(group.id, first))
  useEffect(() => {
    if (hasActive) setOpen(true)
  }, [hasActive])
  const toggle = () =>
    setOpen((v) => {
      write(openKey(group.id), v ? '0' : '1')
      return !v
    })
  const shown = open || compact
  return (
    <div className="side-group">
      <button type="button" className={`side-accordion ${hasActive ? 'has-active' : ''}`} aria-expanded={shown} onClick={toggle}>
        <group.icon size={17} aria-hidden />
        <span>{t(`group.${group.id}`)}</span>
        <motion.span className="side-chevron" animate={{ rotate: shown ? 180 : 0 }} transition={spring}>
          <ChevronDown size={16} />
        </motion.span>
      </button>
      <AnimatePresence initial={false}>
        {shown && (
          <motion.div
            className="side-children"
            initial={compact ? false : { height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="side-children-inner">
              {group.pages.map((p) => (
                <SideLink key={p.id} page={p} active={owns(p, path)} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function Sidebar({ collapsed }: { collapsed: boolean }) {
  const t = useT(navStrings)
  const { pathname } = useLocation()
  const { can } = useSession()
  const groups = visibleNav(can)
  const nav = useRef<HTMLElement>(null)
  useEffect(() => {
    // On a phone the menu is a scrolling row: keep the current page in view.
    const el = nav.current
    const active = el?.querySelector<HTMLElement>('.side-link.active')
    if (!el || !active || el.scrollWidth <= el.clientWidth) return
    const box = el.getBoundingClientRect()
    const item = active.getBoundingClientRect()
    el.scrollBy({ left: item.left - box.left - box.width / 2 + item.width / 2 })
  }, [pathname])
  return (
    <nav ref={nav} id="app-sidebar" className={`sidebar ${collapsed ? 'collapsed' : ''}`} aria-label={t('nav.label')}>
      {collapsed
        ? groups.map((g, i) => (
            <Fragment key={g.id}>
              {i > 0 && <span className="side-sep" aria-hidden />}
              <div className="side-group" role="group" aria-label={t(`group.${g.id}`)}>
                {g.pages.map((p) => (
                  <SideLink key={p.id} page={p} active={owns(p, pathname)} rail />
                ))}
              </div>
            </Fragment>
          ))
        : groups.map((g, i) => <GroupAccordion key={g.id} group={g} first={i === 0} path={pathname} />)}
    </nav>
  )
}
