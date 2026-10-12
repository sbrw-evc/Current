import { useSyncExternalStore } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'

// Toasts in the bottom right corner, in Umbrella's look.
export type NoteKind = 'ok' | 'error' | 'warn' | 'info'
type Note = { id: number; kind: NoteKind; title: string; body?: string }

let notes: Note[] = []
let seq = 0
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

export function notify(kind: NoteKind, title: string, body?: string) {
  const id = ++seq
  notes = [...notes, { id, kind, title, body }].slice(-4)
  emit()
  setTimeout(() => dismiss(id), kind === 'error' ? 9000 : 4500)
}

function dismiss(id: number) {
  notes = notes.filter((n) => n.id !== id)
  emit()
}

const icons = { ok: CheckCircle2, error: XCircle, warn: AlertTriangle, info: Info }

export function Toaster() {
  const list = useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => notes,
  )
  return (
    <div className="toaster" aria-live="polite">
      <AnimatePresence initial={false}>
        {list.map((n) => {
          const Icon = icons[n.kind]
          return (
            <motion.div key={n.id} layout className={`toast toast-${n.kind}`} initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 24 }}>
              <Icon className="toast-icon" size={18} />
              <div className="toast-text">
                <div className="toast-title">{n.title}</div>
                {n.body && <div className="toast-body">{n.body}</div>}
              </div>
              <button type="button" className="icon-btn toast-close" onClick={() => dismiss(n.id)} aria-label="×">
                <X size={16} />
              </button>
            </motion.div>
          )
        })}
      </AnimatePresence>
    </div>
  )
}
