import { useEffect, useId, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { AnimatePresence, motion, useDragControls, type PanInfo } from 'motion/react'
import { useT } from '../../i18n'
import { mobileStrings } from './strings'

// Copied from Umbrella Monitoring (app/web/src/app/mobile/Sheet.tsx).
// Sheet is the bottom sheet of the phone layout: it slides up over the page, closes on the
// backdrop, Escape, the close button or a swipe down by the handle.
export function Sheet({ open, title, onClose, children, footer, full = false }: { open: boolean; title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; full?: boolean }) {
  const t = useT(mobileStrings)
  const titleId = useId()
  const box = useRef<HTMLDivElement>(null)
  const drag = useDragControls()
  const close = useRef(onClose)
  close.current = onClose

  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close.current()
    window.addEventListener('keydown', onKey)
    requestAnimationFrame(() => box.current?.focus())
    return () => {
      window.removeEventListener('keydown', onKey)
      prev?.focus()
    }
  }, [open])

  const end = (_: unknown, info: PanInfo) => {
    if (info.offset.y > 90 || info.velocity.y > 500) close.current()
  }

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div className="m-sheet-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={(e) => e.target === e.currentTarget && onClose()}>
          <motion.div
            ref={box}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            className={`m-sheet${full ? ' m-sheet-full' : ''}`}
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            transition={{ type: 'spring', stiffness: 380, damping: 36 }}
            drag="y"
            dragListener={false}
            dragControls={drag}
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.6 }}
            onDragEnd={end}
          >
            <div className="m-sheet-grip" onPointerDown={(e) => drag.start(e)} aria-hidden>
              <span />
            </div>
            <header className="m-sheet-head" onPointerDown={(e) => drag.start(e)}>
              <h2 id={titleId}>{title}</h2>
              <button type="button" className="icon-btn" onClick={onClose} aria-label={t('m.close')}>
                <X size={18} />
              </button>
            </header>
            <div className="m-sheet-body">{children}</div>
            {footer && <div className="m-sheet-foot">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  )
}
