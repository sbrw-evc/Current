import { useId, useState } from 'react'
import { KeyRound, LockKeyhole } from 'lucide-react'
import { useT, type Dict } from '../i18n'
import { Chip, Password } from './ui'

const strings: Dict = {
  en: {
    'secret.set': 'set · kept in OpenBao',
    'secret.replace': 'Replace',
    'secret.keep': 'Keep the saved one',
    'secret.hint': 'The secret is saved to OpenBao and never shown again.',
  },
  ru: {
    'secret.set': 'задан · хранится в OpenBao',
    'secret.replace': 'Заменить',
    'secret.keep': 'Оставить сохранённый',
    'secret.hint': 'Секрет сохраняется в OpenBao и больше не показывается.',
  },
}

// SecretField: a write-only secret. A saved secret is never shown or prefilled: the field shows a
// "set" chip and a Replace button that opens an empty input; an empty value keeps the saved one.
export function SecretField({ label, value, onChange, isSet, hint, optional }: { label: string; value: string; onChange: (v: string) => void; isSet: boolean; hint?: string; optional?: string }) {
  const t = useT(strings)
  const id = useId()
  const [replacing, setReplacing] = useState(false)
  const editing = !isSet || replacing || value !== ''
  return (
    <div className="field secret-field">
      <label htmlFor={id}>
        {label}
        {optional && <span className="optional"> ({optional})</span>}
      </label>
      {editing ? (
        <div className="secret-edit">
          <Password id={id} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" autoFocus={replacing} />
          {isSet && (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                onChange('')
                setReplacing(false)
              }}
            >
              {t('secret.keep')}
            </button>
          )}
        </div>
      ) : (
        <div className="secret-set">
          <Chip tone="ok">
            <LockKeyhole size={12} /> {t('secret.set')}
          </Chip>
          <button id={id} type="button" className="btn btn-secondary btn-sm" onClick={() => setReplacing(true)}>
            <KeyRound size={14} /> {t('secret.replace')}
          </button>
        </div>
      )}
      <div className="hint">
        {hint ? `${hint} ` : ''}
        {t('secret.hint')}
      </div>
    </div>
  )
}
