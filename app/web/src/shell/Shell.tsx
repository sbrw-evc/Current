import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { ApiError, post, setCsrf, setUnauthorizedHandler } from '../api/client'
import { useMe } from '../api/queries'
import { useT } from '../i18n'
import { Banner, Button } from '../ui/ui'
import { Sidebar, SidebarResizer, useCollapsed, useSidebarWidth } from './Sidebar'
import { SessionProvider, type Session } from './session'
import { TopBar } from './TopBar'
import { ScopeBanner } from './ScopeBanner'
import { DesktopOnly, forcedPages } from './mobile/DesktopOnly'
import { MobileFrame } from './mobile/MobileFrame'
import { mobileReady, pageOf } from './mobile/pages'
import { useMobile } from './mobile/useMobile'

// Shell: checks the setup state and the session, then draws Umbrella's frame (top bar, sidebar,
// rounded page block) around the current page.
export function Shell() {
  const t = useT()
  const loc = useLocation()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const me = useMe()
  const [collapsed, toggle] = useCollapsed()
  const [width, setWidth] = useSidebarWidth()
  const mobile = useMobile()

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrf('')
      qc.setQueryData(['me'], undefined)
      void qc.invalidateQueries({ queryKey: ['me'] })
    })
    return () => setUnauthorizedHandler(null)
  }, [qc])

  useEffect(() => {
    if (me.data) setCsrf(me.data.csrf)
  }, [me.data])

  const signOut = useCallback(async () => {
    try {
      await post('/api/auth/logout')
    } catch {
      // Signed out locally anyway.
    }
    setCsrf('')
    qc.clear()
    navigate('/login', { replace: true })
  }, [qc, navigate])

  const perms = useMemo(() => new Set(me.data?.user.permissions ?? []), [me.data])
  const session = useMemo<Session | null>(() => (me.data ? { user: me.data.user, can: (p) => perms.has(p), signOut } : null), [me.data, perms, signOut])

  if (me.isPending) return <div className="center-page boot">{t('loading')}</div>
  if (me.error) {
    if (me.error instanceof ApiError && (me.error.status === 401 || me.error.status === 403)) {
      const next = loc.pathname + loc.search
      return <Navigate to={`/login${next !== '/' ? `?next=${encodeURIComponent(next)}` : ''}`} replace />
    }
    return (
      <div className="center-page">
        <Banner kind="error" title={t('err.network')} />
        <Button onClick={() => void me.refetch()}>{t('retry')}</Button>
      </div>
    )
  }
  if (!session) return null
  // An expired password leaves only the profile, where a new one is set.
  if (session.user.password_expired && loc.pathname !== '/profile') return <Navigate to="/profile" replace />

  if (mobile)
    return (
      <SessionProvider value={session}>
        <MobileFrame>
          <ScopeBanner />
          <PhonePage />
        </MobileFrame>
      </SessionProvider>
    )

  return (
    <SessionProvider value={session}>
      <div className="app-shell">
        <TopBar collapsed={collapsed} toggle={toggle} />
        <div className={`app-body ${collapsed ? 'side-collapsed' : ''}`} style={{ '--side-width': `${width}px` } as CSSProperties}>
          <Sidebar collapsed={collapsed} />
          {!collapsed && <SidebarResizer width={width} onChange={setWidth} />}
          <div id="app-main" className="app-main">
            <ScopeBanner />
            <Outlet />
          </div>
        </div>
      </div>
    </SessionProvider>
  )
}

// PhonePage keeps the pages made for a computer behind a note on the phone (Umbrella's Pages).
function PhonePage() {
  const { pathname } = useLocation()
  const [forced, setForced] = useState(forcedPages)
  const page = pageOf(pathname)
  if (page && !mobileReady(page) && !forced.has(page.id)) return <DesktopOnly page={page} onOpen={() => setForced(forcedPages())} />
  return <Outlet />
}
