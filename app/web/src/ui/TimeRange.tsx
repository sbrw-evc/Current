import { CalendarClock } from 'lucide-react'
import { useT, type Dict } from '../i18n'
import { fromLocalInput, PRESETS, resolve, toLocalInput, type Range } from '../lib/time'

const strings: Dict = {
  en: { 'tr.custom': 'Custom', 'tr.start': 'Start', 'tr.end': 'End', 'p.15m': '15m', 'p.1h': '1h', 'p.6h': '6h', 'p.24h': '24h', 'p.7d': '7d', 'p.30d': '30d' },
  ru: { 'tr.custom': 'Свой', 'tr.start': 'Начало', 'tr.end': 'Конец', 'p.15m': '15 мин', 'p.1h': '1 ч', 'p.6h': '6 ч', 'p.24h': '24 ч', 'p.7d': '7 дн', 'p.30d': '30 дн' },
}

// TimeRange: preset chips (15m … 30d) and a custom start / end.
export function TimeRange({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  const t = useT(strings)
  const custom = !('preset' in value)
  const fixed = resolve(value)
  return (
    <div className="time-range">
      <div className="chip-row">
        {PRESETS.map((p) => (
          <button key={p} type="button" className={`chip ${'preset' in value && value.preset === p ? 'on' : ''}`} onClick={() => onChange({ preset: p })}>
            {t(`p.${p}`)}
          </button>
        ))}
        <button type="button" className={`chip ${custom ? 'on' : ''}`} onClick={() => !custom && onChange(fixed)}>
          <CalendarClock size={14} />
          {t('tr.custom')}
        </button>
      </div>
      {custom && (
        <div className="range-inputs">
          <label>
            <span>{t('tr.start')}</span>
            <input className="input" type="datetime-local" value={toLocalInput(fixed.start)} onChange={(e) => fromLocalInput(e.target.value) && onChange({ start: fromLocalInput(e.target.value), end: fixed.end })} />
          </label>
          <label>
            <span>{t('tr.end')}</span>
            <input className="input" type="datetime-local" value={toLocalInput(fixed.end)} onChange={(e) => fromLocalInput(e.target.value) && onChange({ start: fixed.start, end: fromLocalInput(e.target.value) })} />
          </label>
        </div>
      )}
    </div>
  )
}
