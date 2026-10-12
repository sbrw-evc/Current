import type { ComponentProps, ReactNode } from 'react'
import { motion } from 'motion/react'
import { spring } from './ui'

export function Pop({ children }: { children: ReactNode }) {
  return (
    <motion.span
      className="pop-icon"
      initial={{ scale: 0.3, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 520, damping: 18 }}
    >
      {children}
    </motion.span>
  )
}

export function Choice(props: ComponentProps<typeof motion.button>) {
  return <motion.button type="button" role="radio" className="choice" whileHover={{ y: -2 }} whileTap={{ scale: 0.97 }} transition={spring} {...props} />
}

export function ChoiceMark({ checked }: { checked: boolean }) {
  return <span className={`radio-mark${checked ? ' on' : ''}`} aria-hidden />
}

export function Choices<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T
  options: { value: T; title: ReactNode; hint?: ReactNode }[]
  onChange: (v: T) => void
  label: string
}) {
  return (
    <div className="choices" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <Choice key={o.value} aria-checked={value === o.value} onClick={() => onChange(o.value)}>
          <ChoiceMark checked={value === o.value} />
          {o.hint === undefined ? (
            <span className="choice-title">{o.title}</span>
          ) : (
            <span>
              <span className="choice-title">{o.title}</span>
              <br />
              <span className="hint">{o.hint}</span>
            </span>
          )}
        </Choice>
      ))}
    </div>
  )
}
