import { Monitor } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useT } from '../../i18n'
import { Button } from '../../ui/ui'
import type { PageDef } from '../nav'
import { navStrings } from '../strings'
import { mobileStrings } from './strings'

// Umbrella's DesktopOnly (app/web/src/app/mobile/DesktopOnly.tsx).

const KEY = 'flow.mobile.forced'

// The pages the user chose to open on the phone anyway, for this tab of the browser.
export function forcedPages(): Set<string> {
  try {
    return new Set(JSON.parse(window.sessionStorage.getItem(KEY) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function force(id: string) {
  const s = forcedPages()
  s.add(id)
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify([...s]))
  } catch {
    // The choice then lasts until the page is rendered again.
  }
}

// DesktopOnly stands in for a page made for a computer when it is opened on a phone.
export function DesktopOnly({ page, onOpen }: { page: PageDef; onOpen: () => void }) {
  const t = useT(mobileStrings)
  const tn = useT(navStrings)
  return (
    <main className="page">
      <div className="card m-desk">
        <span className="m-desk-icon">
          <page.icon size={26} aria-hidden />
          <Monitor size={16} aria-hidden className="m-desk-badge" />
        </span>
        <h2>{t('m.desktop.title', { page: tn(`page.${page.id}`) })}</h2>
        <p className="muted">{t('m.desktop.text')}</p>
        <div className="m-desk-actions">
          <Link to="/" className="btn btn-primary">
            {t('m.desktop.home')}
          </Link>
          <Button
            variant="ghost"
            onClick={() => {
              force(page.id)
              onOpen()
            }}
          >
            {t('m.desktop.open')}
          </Button>
        </div>
      </div>
    </main>
  )
}
