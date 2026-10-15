import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { Check, ChevronDown, ChevronRight, Fingerprint, Languages, LogOut, Moon, Sun } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useLocation, useNavigate } from 'react-router-dom'
import type { Locale, Theme } from '../api/types'
import { useLocale, useT } from '../i18n'
import { useTheme } from '../theme'
import { spring } from '../ui/ui'
import { Avatar } from './Avatar'
import { useSession } from './session'
import { navStrings } from './strings'

// The user menu of Umbrella: who is signed in, language and theme accordions, sign out.
export function UserMenu() {
  const t = useT(navStrings)
  const { user, signOut } = useSession()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { theme, setTheme } = useTheme()
  const { locale, setLocale } = useLocale()
  const [open, setOpen] = useState(false)
  const [section, setSection] = useState<'language' | 'theme' | null>(null)
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const id = useId()

  useEffect(() => setOpen(false), [pathname])
  useEffect(() => {
    if (!open) setSection(null)
  }, [open])
  useEffect(() => {
    if (!open) return
    const onDown = (e: PointerEvent) => !root.current?.contains(e.target as Node) && setOpen(false)
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('pointerdown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('pointerdown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const origin = () => {
    const r = trigger.current?.getBoundingClientRect()
    return r ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : undefined
  }
  const role = t(`role.${user.role}`)

  return (
    <div className="user-menu" ref={root}>
      <button ref={trigger} type="button" className="user-btn" aria-haspopup="menu" aria-expanded={open} aria-controls={id} aria-label={t('menu.open')} onClick={() => setOpen((v) => !v)}>
        <span className="who">
          <strong>{user.name}</strong>
          <small>{role.startsWith('role.') ? user.role : role}</small>
        </span>
        <Avatar name={user.name} username={user.username} size={32} />
        <motion.span className="pop-icon chevron" animate={{ rotate: open ? 180 : 0 }} transition={spring}>
          <ChevronDown size={16} />
        </motion.span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            id={id}
            role="menu"
            className="card user-dropdown"
            initial={{ opacity: 0, y: -8, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
            style={{ transformOrigin: 'top right' }}
          >
            <div className="menu-head">
              <Avatar name={user.name} username={user.username} size={44} />
              <div>
                <strong>{user.name}</strong>
                <small>
                  {user.username} · {role.startsWith('role.') ? user.role : role}
                </small>
              </div>
            </div>
            <Accordion
              icon={<Languages size={18} />}
              label={t('menu.language')}
              value={t(`lang.${locale}`)}
              open={section === 'language'}
              onToggle={() => setSection(section === 'language' ? null : 'language')}
              options={(['ru', 'en'] as Locale[]).map((l) => ({ key: l, label: t(`lang.${l}`), selected: l === locale, select: () => setLocale(l) }))}
            />
            <Accordion
              icon={theme === 'dark' ? <Moon size={18} /> : <Sun size={18} />}
              label={t('menu.theme')}
              value={t(`theme.${theme}`)}
              open={section === 'theme'}
              onToggle={() => setSection(section === 'theme' ? null : 'theme')}
              options={(['light', 'dark'] as Theme[]).map((v) => ({
                key: v,
                label: t(`theme.${v}`),
                icon: v === 'dark' ? <Moon size={16} /> : <Sun size={16} />,
                selected: v === theme,
                select: () => setTheme(v, origin()),
              }))}
            />
            <div className="menu-sep" />
            <button type="button" role="menuitem" className="menu-item" onClick={() => navigate('/profile')}>
              <Fingerprint size={18} />
              {t('menu.profile')}
            </button>
            <button type="button" role="menuitem" className="menu-item danger" onClick={signOut}>
              <LogOut size={18} />
              {t('menu.signout')}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

type Option = { key: string; label: string; icon?: ReactNode; selected: boolean; select: () => void }

function Accordion({ icon, label, value, open, onToggle, options }: { icon: ReactNode; label: string; value: string; open: boolean; onToggle: () => void; options: Option[] }) {
  const panel = useId()
  return (
    <div className={`menu-accordion ${open ? 'open' : ''}`}>
      <button type="button" className="menu-item" aria-expanded={open} aria-controls={panel} onClick={onToggle}>
        {icon}
        <span className="menu-label">{label}</span>
        <span className="menu-value">{value}</span>
        <motion.span className="pop-icon menu-chevron" animate={{ rotate: open ? 90 : 0 }} transition={spring}>
          <ChevronRight size={16} />
        </motion.span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div id={panel} role="group" aria-label={label} className="menu-options" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}>
            {options.map((o) => (
              <button key={o.key} type="button" role="menuitemradio" aria-checked={o.selected} className={`menu-option ${o.selected ? 'selected' : ''}`} onClick={o.select}>
                {o.icon}
                <span className="menu-label">{o.label}</span>
                {o.selected && <Check size={16} />}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
