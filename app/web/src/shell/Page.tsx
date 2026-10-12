import type { ReactNode } from 'react'
import { motion } from 'motion/react'
import { ShieldOff } from 'lucide-react'
import { useT } from '../i18n'
import { navStrings } from './strings'
import { useSession } from './session'

// Page: Umbrella's page column with a PageHead (22px title, muted subtitle, actions on the right).
export function Page({ id, title, subtitle, actions, wide, children }: { id: string; title?: string; subtitle?: ReactNode; actions?: ReactNode; wide?: boolean; children: ReactNode }) {
  const t = useT(navStrings)
  return (
    <motion.main className={`page ${wide ? 'page-wide' : ''}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}>
      <div className="page-head">
        <div>
          <h1>{title ?? t(`page.${id}`)}</h1>
          {subtitle && <p className="muted">{subtitle}</p>}
        </div>
        {actions && <div className="row page-actions">{actions}</div>}
      </div>
      {children}
    </motion.main>
  )
}

// Guard shows the page only to a role with the permission.
export function Guard({ perm, children }: { perm: string; children: ReactNode }) {
  const { can } = useSession()
  const t = useT()
  if (can(perm)) return <>{children}</>
  return (
    <main className="page">
      <div className="card empty-state">
        <ShieldOff size={28} />
        <h2>{t('noaccess.title')}</h2>
        <p className="muted">{t('noaccess.text')}</p>
      </div>
    </main>
  )
}
