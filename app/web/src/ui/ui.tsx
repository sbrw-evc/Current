// Controls in Beacon's look (adapted from Beacon app/web/src/ui.tsx).
import { useEffect, useId, useRef, useState, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes } from 'react'
import { AlertTriangle, CheckCircle2, Eye, EyeOff, Info, Loader2, Minus, Moon, Plus, Sun, X, XCircle } from 'lucide-react'
import { AnimatePresence, motion, type HTMLMotionProps, type Transition } from 'motion/react'
import { useLocale, useT } from '../i18n'
import { useTheme } from '../theme'
import { Link } from 'react-router-dom'
import { originOf } from '../lib/fx'
import { Select } from './select'

export const spring: Transition = { type: 'spring', stiffness: 420, damping: 30 }

type ButtonProps = Omit<HTMLMotionProps<'button'>, 'children'> & {
  children?: ReactNode
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-soft'
  size?: 'sm'
  busy?: boolean
}

export function Button({ variant = 'secondary', size, busy, disabled, children, className, type = 'button', ...rest }: ButtonProps) {
  return (
    <motion.button
      {...rest}
      type={type}
      className={`btn btn-${variant} ${size ? `btn-${size}` : ''} ${className ?? ''}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      whileTap={disabled || busy ? undefined : { scale: 0.97 }}
      transition={spring}
    >
      {busy && <Loader2 className="spin" size={16} aria-hidden />}
      {children}
    </motion.button>
  )
}

export function Field({ label, hint, children, optional }: { label: string; hint?: ReactNode; children: (id: string) => ReactNode; optional?: string }) {
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {optional && <span className="optional"> ({optional})</span>}
      </label>
      {children(id)}
      {hint && <div className="hint">{hint}</div>}
    </div>
  )
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className ?? ''}`} />
}

export function Password(props: InputHTMLAttributes<HTMLInputElement>) {
  const [shown, setShown] = useState(false)
  const t = useT()
  return (
    <div className="password">
      <input {...props} type={shown ? 'text' : 'password'} className="input" />
      <button type="button" className="icon-btn" onClick={() => setShown(!shown)} aria-label={shown ? t('ui.hide') : t('ui.show')}>
        {shown ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  )
}

export { Select }

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={`input textarea ${props.className ?? ''}`} />
}

export function Switch({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; disabled?: boolean }) {
  const id = useId()
  return (
    <div className="switch-row">
      <button id={id} type="button" role="switch" aria-checked={checked} disabled={disabled} className={`switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}>
        <span />
      </button>
      <label htmlFor={id}>
        <span>{label}</span>
        {hint && <span className="hint">{hint}</span>}
      </label>
    </div>
  )
}

export function Stepper({ value, onChange, min, max, label, id, suffix }: { value: number; onChange: (v: number) => void; min: number; max: number; label?: string; id?: string; suffix?: string }) {
  const [draft, setDraft] = useState(String(value))
  useEffect(() => setDraft(String(value)), [value])
  const clamp = (v: number) => Math.min(max, Math.max(min, Math.trunc(v)))
  const commit = (text: string) => {
    const n = Number(text)
    const next = text.trim() === '' || Number.isNaN(n) ? value : clamp(n)
    setDraft(String(next))
    if (next !== value) onChange(next)
  }
  const step = (d: number) => onChange(clamp(value + d))
  return (
    <div className="stepper" role="group" aria-label={label}>
      <button type="button" className="stepper-btn" onClick={() => step(-1)} disabled={value <= min} aria-label="-" tabIndex={-1}>
        <Minus size={14} />
      </button>
      <input
        id={id}
        className="stepper-input"
        inputMode="numeric"
        aria-label={label}
        value={draft}
        size={Math.max(String(max).length, 2)}
        onChange={(e) => {
          const text = e.target.value.replace(/[^0-9]/g, '')
          setDraft(text)
          const n = Number(text)
          if (text !== '' && n >= min && n <= max) onChange(n)
        }}
        onBlur={(e) => commit(e.target.value)}
      />
      {suffix && <span className="stepper-suffix">{suffix}</span>}
      <button type="button" className="stepper-btn" onClick={() => step(1)} disabled={value >= max} aria-label="+" tabIndex={-1}>
        <Plus size={14} />
      </button>
    </div>
  )
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: ReactNode; title?: string }[]; onChange: (v: T) => void; label: string }) {
  const group = useId()
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" title={o.title} aria-checked={value === o.value} className={value === o.value ? 'active' : ''} onClick={() => onChange(o.value)}>
          {value === o.value && <motion.span layoutId={`seg-${group}`} className="seg-pill" transition={spring} />}
          <span className="seg-label">{o.label}</span>
        </button>
      ))}
    </div>
  )
}

const icons = { ok: CheckCircle2, error: XCircle, warn: AlertTriangle, info: Info }

export function Banner({ kind, title, children }: { kind: keyof typeof icons; title: ReactNode; children?: ReactNode }) {
  const Icon = icons[kind]
  return (
    <motion.div
      className={`banner banner-${kind}`}
      role={kind === 'error' ? 'alert' : 'status'}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
    >
      <Icon size={18} aria-hidden />
      <div>
        <div className="banner-title">{title}</div>
        {children && <div className="banner-body">{children}</div>}
      </div>
    </motion.div>
  )
}

export function Rows({ rows, align = 'start' }: { rows: [ReactNode, ReactNode][]; align?: 'start' | 'end' }) {
  return (
    <dl className={`rows ${align === 'end' ? 'rows-end' : ''}`}>
      {rows.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v === '' || v === undefined || v === null ? '—' : v}</dd>
        </div>
      ))}
    </dl>
  )
}

// Chip: a soft pill with a coloured dot (state, boundary, provider).
export type Tone = 'ok' | 'warn' | 'error' | 'info' | 'low' | 'off' | 'orange' | 'purple'
export function Chip({ tone, children, dot = true, title }: { tone: Tone; children: ReactNode; dot?: boolean; title?: string }) {
  return (
    <span className={`pill chip-soft tone-${tone}`} title={title}>
      {dot && <span className="chip-dot" aria-hidden />}
      {children}
    </span>
  )
}

export function Brand({ compact }: { compact?: boolean }) {
  const t = useT()
  return (
    <div className="brand">
      <img src="/logo.svg" alt="" width={32} height={32} />
      {!compact && (
        <div>
          <div className="brand-name">{t('app.name')}</div>
        </div>
      )}
    </div>
  )
}

export function Preferences() {
  const { theme, setTheme } = useTheme()
  const { locale, setLocale } = useLocale()
  const t = useT()
  return (
    <div className="prefs">
      <Segmented
        label={t('lang.toggle')}
        value={locale}
        onChange={(l) => setLocale(l)}
        options={[
          { value: 'ru', label: 'RU' },
          { value: 'en', label: 'EN' },
        ]}
      />
      <button type="button" className="icon-btn" aria-label={t('theme.toggle')} title={t('theme.toggle')} onClick={(e) => setTheme(theme === 'dark' ? 'light' : 'dark', originOf(e))}>
        {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
      </button>
    </div>
  )
}

export function Modal({ open, title, onClose, children, footer }: { open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  const t = useT()
  const box = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close.current()
    window.addEventListener('keydown', onKey)
    requestAnimationFrame(() => box.current?.querySelector<HTMLElement>('input, select, textarea')?.focus())
    return () => window.removeEventListener('keydown', onKey)
  }, [open])
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="modal-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
          <motion.div
            ref={box}
            className="card modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.98 }}
            transition={spring}
          >
            <header className="modal-head">
              <h2 id={titleId}>{title}</h2>
              <button type="button" className="icon-btn" onClick={onClose} aria-label={t('close')}>
                <X size={18} />
              </button>
            </header>
            <div className="stack">{children}</div>
            {footer && <div className="modal-foot">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export function Card({ title, actions, children, className, pad = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`card ${pad ? 'status-card' : 'flush-card'} ${className ?? ''}`}>
      {(title || actions) && (
        <header className={pad ? undefined : 'flush-head'}>
          {title && <h2 className="card-title">{title}</h2>}
          {actions && <div className="row card-head-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  )
}

// Tile is a counter card; with `to` the whole card opens the page with the details.
export function Tile({ label, value, sub, icon, tone, to }: { label: string; value: ReactNode; sub?: ReactNode; icon?: ReactNode; tone?: Tone; to?: string }) {
  const body = (
    <>
      <div className="tile-head">
        <span className="tile-label">{label}</span>
        {icon && <span className="tile-icon">{icon}</span>}
      </div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub muted">{sub}</div>}
    </>
  )
  const cls = `card tile ${tone ? `tile-${tone}` : ''}`
  return to ? (
    <Link to={to} className={`${cls} tile-link`}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  )
}

export function Loading() {
  const t = useT()
  return (
    <div className="loading-line muted">
      <Loader2 className="spin" size={16} aria-hidden /> {t('loading')}
    </div>
  )
}

export function formatDate(v: string | undefined | null, locale: string) {
  if (!v) return ''
  const d = new Date(v)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 2000) return ''
  return d.toLocaleString(locale === 'ru' ? 'ru-RU' : 'en-GB')
}
