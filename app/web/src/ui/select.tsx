import { Children, Fragment, isValidElement, type ReactElement, type ReactNode } from 'react'
import { Listbox, ListboxButton, ListboxOption, ListboxOptions } from '@headlessui/react'
import { Check, ChevronDown } from 'lucide-react'

// Drop-down built on Headless UI's Listbox, so the open list is ours to style
// (theme colours, OverlayScrollbars) instead of the browser's native popup.
// It keeps the <select> API the pages already use: <option> children and an
// onChange that reads e.target.value.

type Opt = { value: string; label: ReactNode; disabled: boolean; title?: string }

type OptionProps = { value?: string | number; disabled?: boolean; title?: string; children?: ReactNode }

function collect(children: ReactNode, out: Opt[] = []) {
  Children.forEach(children, (c) => {
    if (!isValidElement(c)) return
    if (c.type === Fragment) collect((c as ReactElement<{ children?: ReactNode }>).props.children, out)
    else if (c.type === 'option') {
      const p = (c as ReactElement<OptionProps>).props
      out.push({ value: String(p.value ?? ''), label: p.children, disabled: !!p.disabled, title: p.title })
    }
  })
  return out
}

export type SelectProps = {
  id?: string
  value?: string | number
  disabled?: boolean
  onChange?: (e: { target: { value: string } }) => void
  children?: ReactNode
  className?: string
  'aria-label'?: string
}

export function Select({ id, value, disabled, onChange, children, className, 'aria-label': ariaLabel }: SelectProps) {
  const options = collect(children)
  const current = String(value ?? '')
  // Like a native select, an unknown value shows the first option.
  const shown = options.find((o) => o.value === current) ?? options[0]
  return (
    <Listbox value={current} disabled={disabled} onChange={(v: string) => onChange?.({ target: { value: v } })}>
      <ListboxButton id={id} aria-label={ariaLabel} className={`input select ${className ?? ''}`} title={shown?.title}>
        <span className="select-value">{shown?.label}</span>
        <ChevronDown className="select-chevron" size={16} aria-hidden />
      </ListboxButton>
      <ListboxOptions anchor={{ to: 'bottom start', gap: 4, padding: 8 }} modal={false} transition className="select-menu">
        {options.map((o) => (
          <ListboxOption key={o.value} value={o.value} disabled={o.disabled} title={o.title} className="select-option">
            <span className="select-value">{o.label}</span>
            <Check className="select-check" size={15} aria-hidden />
          </ListboxOption>
        ))}
      </ListboxOptions>
    </Listbox>
  )
}
