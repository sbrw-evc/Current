import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useT } from '../i18n'
import { Brand } from '../ui/ui'
import { navStrings } from './strings'
import { UserMenu } from './UserMenu'

export function TopBar({ collapsed, toggle }: { collapsed: boolean; toggle: () => void }) {
  const t = useT(navStrings)
  const label = t(collapsed ? 'nav.expand' : 'nav.collapse')
  return (
    <header className="topbar">
      <div className="topbar-start">
        <button type="button" className="icon-btn side-toggle" aria-label={label} title={label} aria-expanded={!collapsed} aria-controls="app-sidebar" onClick={toggle}>
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
        <Link to="/" className="brand-link">
          <Brand />
        </Link>
      </div>
      <div className="topbar-end">
        {import.meta.env.VITE_MOCK === '1' && <span className="pill pill-warn mock-badge">{t('mock.badge')}</span>}
        <UserMenu />
      </div>
    </header>
  )
}
