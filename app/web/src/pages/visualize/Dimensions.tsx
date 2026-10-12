import { useMemo, useRef, useState } from 'react'
import { GripVertical, Plus, X } from 'lucide-react'
import type { Column } from '../../api/types'
import { useT } from '../../i18n'
import { visStrings } from './strings'

// The ordered list of dimensions: drag to reorder, × to remove, a searchable list to add.
export function Dimensions({ value, onChange, columns, max = 10 }: { value: string[]; onChange: (v: string[]) => void; columns: Column[]; max?: number }) {
  const t = useT(visStrings)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [drag, setDrag] = useState<number | null>(null)
  const [over, setOver] = useState<number | null>(null)
  const input = useRef<HTMLInputElement>(null)

  const choices = useMemo(() => {
    const q = query.trim().toLowerCase()
    return columns.filter((c) => c.dimension && !value.includes(c.name) && (!q || c.name.toLowerCase().includes(q)))
  }, [columns, value, query])

  const add = (name: string) => {
    if (value.length >= max) return
    onChange([...value, name])
    setQuery('')
    setActive(0)
    input.current?.focus()
  }

  const move = (from: number, to: number) => {
    if (from === to) return
    const next = [...value]
    const [x] = next.splice(from, 1)
    next.splice(to, 0, x)
    onChange(next)
  }

  const byName = new Map(columns.map((c) => [c.name, c]))

  return (
    <div className="dims">
      {value.length === 0 ? (
        <p className="hint">{t('opt.dims.none')}</p>
      ) : (
        <ol className="dims-list">
            {value.map((d, i) => (
              <li
                key={d}
                className={`dim-chip ${drag === i ? 'dragging' : ''} ${over === i && drag !== null && drag !== i ? 'over' : ''}`}
                draggable
                onDragStart={(e) => {
                  setDrag(i)
                  e.dataTransfer.effectAllowed = 'move'
                  e.dataTransfer.setData('text/plain', d)
                }}
                onDragOver={(e) => {
                  e.preventDefault()
                  setOver(i)
                }}
                onDragLeave={() => setOver((o) => (o === i ? null : o))}
                onDrop={(e) => {
                  e.preventDefault()
                  if (drag !== null) move(drag, i)
                  setDrag(null)
                  setOver(null)
                }}
                onDragEnd={() => {
                  setDrag(null)
                  setOver(null)
                }}
                title={t('opt.dims.drag')}
              >
                <GripVertical size={14} className="dim-grip" aria-hidden />
                <span className="dim-index">{i + 1}</span>
                <span className="dim-name">{d}</span>
                {byName.get(d) && !byName.get(d)!.rollup && <span className="dim-raw">raw</span>}
                <button type="button" className="dim-x" aria-label={t('opt.dims.remove', { name: d })} onClick={() => onChange(value.filter((x) => x !== d))}>
                  <X size={13} />
                </button>
              </li>
            ))}
        </ol>
      )}
      {value.length < max && (
        <div className="dim-add">
          <Plus size={15} className="dim-add-icon" aria-hidden />
          <input
            ref={input}
            className="input"
            value={query}
            placeholder={t('opt.dims.add')}
            role="combobox"
            aria-expanded={open}
            aria-autocomplete="list"
            onChange={(e) => {
              setQuery(e.target.value)
              setActive(0)
              setOpen(true)
            }}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 120)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setOpen(true)
                setActive((a) => Math.min(choices.length - 1, a + 1))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setActive((a) => Math.max(0, a - 1))
              } else if (e.key === 'Enter' && open && choices[active]) {
                e.preventDefault()
                add(choices[active].name)
              } else if (e.key === 'Escape') setOpen(false)
              else if (e.key === 'Backspace' && query === '' && value.length > 0) onChange(value.slice(0, -1))
            }}
          />
          {open && (
            <ul className="dim-menu" role="listbox">
              {choices.length === 0 ? (
                <li className="dim-menu-empty muted">{t('opt.dims.nomatch')}</li>
              ) : (
                choices.map((c, i) => (
                  <li
                    key={c.name}
                    role="option"
                    aria-selected={i === active}
                    className={`dim-option ${i === active ? 'active' : ''}`}
                    onMouseEnter={() => setActive(i)}
                    onMouseDown={(e) => {
                      e.preventDefault()
                      add(c.name)
                    }}
                    ref={i === active ? (el) => el?.scrollIntoView({ block: 'nearest' }) : undefined}
                  >
                    <span>{c.name}</span>
                    <span className="dim-kind">{c.rollup ? c.kind : `${c.kind} · raw`}</span>
                  </li>
                ))
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
