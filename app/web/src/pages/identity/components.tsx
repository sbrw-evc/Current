import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Circle, Fingerprint, KeyRound, Pencil, Plus, Smartphone, Trash2 } from 'lucide-react'
import { ApiError, del, get, patch, post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { checkPassword, policyError, ruleText, rules, type Letters, type PasswordPolicy } from '../../lib/policy'
import { createPasskey, getPasskey, PasskeyError, passkeysSupported, platformAuthenticator } from '../../lib/webauthn'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Field, formatDate, Input, Select, Stepper, Switch } from '../../ui/ui'
import { strings } from './strings'

// PolicyChecklist: the rules of the policy, ticked off as the password meets them.
export function PolicyChecklist({ policy, password, username, confirm }: { policy: PasswordPolicy; password: string; username: string; confirm?: string }) {
  const t = useT(strings)
  const failed = new Set(checkPassword(password, username, policy))
  const items = rules(policy).map((r) => ({ key: r, text: ruleText(t, r, policy), ok: password !== '' && !failed.has(r) }))
  if (policy.history_count > 0) items.push({ key: 'history', text: ruleText(t, 'history', policy), ok: password !== '' })
  if (confirm !== undefined) items.push({ key: 'username', text: t('pp.match'), ok: password !== '' && password === confirm })
  return (
    <ul className="checklist">
      {items.map((i, n) => (
        <li key={`${i.key}-${n}`} className={i.ok ? 'ok' : ''}>
          {i.ok ? <CheckCircle2 size={16} /> : <Circle size={16} />}
          {i.text}
        </li>
      ))}
    </ul>
  )
}

// PolicyEditor: the policy of the family, as in Umbrella Monitoring.
export function PolicyEditor({ value: p, onChange, disabled }: { value: PasswordPolicy; onChange: (p: PasswordPolicy) => void; disabled?: boolean }) {
  const t = useT(strings)
  const set = (patch: Partial<PasswordPolicy>) => onChange({ ...p, ...patch })
  const problem = policyError(p)
  return (
    <fieldset className="plain-fieldset stack" disabled={disabled}>
      <Field label={t('pol.length')}>{(id) => <Stepper id={id} min={8} max={128} value={p.min_length} onChange={(v) => set({ min_length: v })} />}</Field>
      <div className="row wrap">
        <Switch checked={p.require_digits} onChange={(v) => set({ require_digits: v, min_digits: v ? Math.max(1, p.min_digits) : 0 })} label={t('pol.digits')} disabled={disabled} />
        {p.require_digits && <Stepper label={t('pol.count')} min={1} max={16} value={p.min_digits} onChange={(v) => set({ min_digits: v })} />}
      </div>
      <div className="row wrap">
        <Switch checked={p.require_special} onChange={(v) => set({ require_special: v, min_special: v ? Math.max(1, p.min_special) : 0 })} label={t('pol.special')} disabled={disabled} />
        {p.require_special && <Stepper label={t('pol.count')} min={1} max={16} value={p.min_special} onChange={(v) => set({ min_special: v })} />}
      </div>
      <Switch checked={p.require_mixed_case} onChange={(v) => set({ require_mixed_case: v })} label={t('pol.case')} disabled={disabled} />
      <Field label={t('pol.letters')}>
        {(id) => (
          <Select id={id} value={p.letters} onChange={(e) => set({ letters: e.target.value as Letters })}>
            {(['latin', 'cyrillic', 'latin_cyrillic', 'any'] as Letters[]).map((l) => (
              <option key={l} value={l}>
                {t(`pol.letters.${l}`)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Switch checked={p.block_common} onChange={(v) => set({ block_common: v })} label={t('pol.common')} hint={t('pol.common.hint')} disabled={disabled} />
      <div className="row wrap">
        <Switch checked={p.history_count > 0} onChange={(v) => set({ history_count: v ? 5 : 0 })} label={t('pol.history')} disabled={disabled} />
        {p.history_count > 0 && <Stepper label={t('pol.history.n')} min={1} max={24} value={p.history_count} onChange={(v) => set({ history_count: v })} />}
      </div>
      <Switch checked={p.max_age_days > 0} onChange={(v) => set(v ? { max_age_days: 90, warn_days: 14 } : { max_age_days: 0, warn_days: 0 })} label={t('pol.expire')} disabled={disabled} />
      {p.max_age_days > 0 && (
        <div className="row wrap">
          <Field label={t('pol.maxAge')}>{(id) => <Stepper id={id} min={1} max={3650} value={p.max_age_days} onChange={(v) => set({ max_age_days: v })} />}</Field>
          <Field label={t('pol.warn')}>{(id) => <Stepper id={id} min={0} max={90} value={p.warn_days} onChange={(v) => set({ warn_days: v })} />}</Field>
        </div>
      )}
      <Switch
        checked={p.lockout_attempts > 0}
        onChange={(v) => set(v ? { lockout_attempts: 10, lockout_minutes: 15 } : { lockout_attempts: 0, lockout_minutes: 0 })}
        label={t('pol.lockout')}
        disabled={disabled}
      />
      {p.lockout_attempts > 0 && (
        <div className="row wrap">
          <Field label={t('pol.lockout.attempts')}>{(id) => <Stepper id={id} min={3} max={100} value={p.lockout_attempts} onChange={(v) => set({ lockout_attempts: v })} />}</Field>
          <Field label={t('pol.lockout.minutes')}>{(id) => <Stepper id={id} min={1} max={1440} value={p.lockout_minutes} onChange={(v) => set({ lockout_minutes: v })} />}</Field>
        </div>
      )}
      {problem && <Banner kind="error" title={t(`pol.err.${problem}`)} />}
    </fieldset>
  )
}

export function passkeyError(t: (k: string) => string, e: unknown) {
  return errorText(t, e instanceof PasskeyError ? new ApiError(400, e.code) : e)
}

// passkeySignIn runs the passkey sign-in and returns the session.
export async function passkeySignIn<T>(): Promise<T> {
  const started = await post<{ ceremony: string; options: Record<string, unknown> }>('/api/auth/passkey/begin')
  const credential = await getPasskey(started.options)
  return post<T>('/api/auth/passkey/finish', { ceremony: started.ceremony, credential })
}

type Passkey = { id: number; name: string; transports: string[]; backup_eligible: boolean; hub_id?: string; created_at: string; last_used_at?: string }

const iconOf = (k: Passkey) => (k.transports.some((x) => ['usb', 'nfc', 'ble'].includes(x)) ? KeyRound : k.transports.includes('hybrid') ? Smartphone : Fingerprint)

// PasskeysCard: the passkeys of the signed-in person.
export function PasskeysCard({ fromHub }: { fromHub: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const keys = useQuery({ queryKey: ['me', 'passkeys'], queryFn: ({ signal }) => get<Passkey[]>('/api/auth/me/passkeys', signal) })
  const platform = useQuery({ queryKey: ['platform-authenticator'], queryFn: platformAuthenticator, staleTime: Infinity })
  const [renaming, setRenaming] = useState<{ id: number; name: string } | null>(null)
  const done = () => qc.invalidateQueries({ queryKey: ['me', 'passkeys'] })
  const fail = (e: unknown) => {
    const x = passkeyError(t, e)
    notify('error', x.message, x.detail)
  }
  const add = useMutation({
    mutationFn: async () => {
      const started = await post<{ ceremony: string; options: Record<string, unknown> }>('/api/auth/me/passkeys/begin')
      const credential = await createPasskey(started.options)
      return post('/api/auth/me/passkeys/finish', { ceremony: started.ceremony, credential, name: '' })
    },
    onSuccess: () => {
      void done()
      notify('ok', t('pk.added'))
    },
    onError: fail,
  })
  const rename = useMutation({
    mutationFn: (r: { id: number; name: string }) => patch(`/api/auth/me/passkeys/${r.id}`, { name: r.name }),
    onSuccess: () => {
      setRenaming(null)
      void done()
    },
    onError: fail,
  })
  const remove = useMutation({ mutationFn: (id: number) => del(`/api/auth/me/passkeys/${id}`), onSuccess: done, onError: fail })
  return (
    <Card
      title={t('pk.title')}
      actions={
        !fromHub && (
          <Button size="sm" variant="primary" busy={add.isPending} disabled={!passkeysSupported()} onClick={() => add.mutate()}>
            <Plus size={14} /> {platform.data ? t('pk.add.platform') : t('pk.add')}
          </Button>
        )
      }
    >
      <p className="muted">{fromHub ? t('pk.hub') : t('pk.text')}</p>
      {keys.data && keys.data.length === 0 && <p className="hint">{t('pk.empty')}</p>}
      <ul className="pk-list">
        {keys.data?.map((k) => {
          const Icon = iconOf(k)
          return (
            <li key={k.id}>
              <Icon size={18} aria-hidden />
              {renaming?.id === k.id ? (
                <Input
                  autoFocus
                  aria-label={t('pk.rename')}
                  value={renaming.name}
                  onChange={(e) => setRenaming({ ...renaming, name: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') rename.mutate(renaming)
                    if (e.key === 'Escape') setRenaming(null)
                  }}
                  onBlur={() => rename.mutate(renaming)}
                />
              ) : (
                <div className="pk-name">
                  <strong>{k.name}</strong>
                  <span className="hint">
                    {t('pk.created', { at: formatDate(k.created_at, locale) })} · {k.last_used_at ? t('pk.used', { at: formatDate(k.last_used_at, locale) }) : t('pk.unused')}
                    {k.hub_id && ` · ${t('pk.fromhub')}`}
                  </span>
                </div>
              )}
              {!k.hub_id && (
                <>
                  <button type="button" className="icon-btn" aria-label={t('pk.rename')} onClick={() => setRenaming({ id: k.id, name: k.name })}>
                    <Pencil size={15} />
                  </button>
                  <button
                    type="button"
                    className="icon-btn danger-icon"
                    aria-label={t('pk.remove')}
                    onClick={() => window.confirm(t('pk.remove.ask', { name: k.name })) && remove.mutate(k.id)}
                  >
                    <Trash2 size={15} />
                  </button>
                </>
              )}
            </li>
          )
        })}
      </ul>
    </Card>
  )
}

// ProviderMark: the logo of a sign-in method.
export function ProviderMark({ id }: { id: string }) {
  switch (id) {
    case 'entra':
    case 'microsoft':
      return (
        <svg width="16" height="16" viewBox="0 0 21 21" aria-hidden>
          <rect x="1" y="1" width="9" height="9" fill="#f25022" />
          <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
          <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
          <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
        </svg>
      )
    case 'google':
      return (
        <svg width="16" height="16" viewBox="0 0 48 48" aria-hidden>
          <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
          <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
          <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
          <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
        </svg>
      )
    case 'apple':
      return (
        <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden fill="currentColor">
          <path d="M16.37 12.62c-.02-2.3 1.88-3.4 1.96-3.46-1.07-1.56-2.73-1.78-3.32-1.8-1.41-.14-2.76.83-3.48.83-.72 0-1.82-.81-3-.79-1.54.02-2.96.9-3.76 2.28-1.6 2.78-.41 6.9 1.15 9.16.76 1.1 1.67 2.34 2.86 2.3 1.15-.05 1.58-.74 2.97-.74 1.38 0 1.77.74 2.98.72 1.23-.02 2.01-1.12 2.76-2.23.87-1.28 1.23-2.52 1.25-2.58-.03-.01-2.4-.92-2.42-3.66zM14.1 5.86c.63-.77 1.06-1.83.94-2.89-.91.04-2.01.61-2.66 1.37-.58.67-1.1 1.76-.96 2.79 1.01.08 2.05-.51 2.68-1.27z" />
        </svg>
      )
    case 'passkey':
      return <Fingerprint size={16} aria-hidden />
    case 'ldap':
      return <KeyRound size={16} aria-hidden />
  }
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3a9 9 0 0 1 9 9H3a9 9 0 0 1 9-9z" />
      <path d="M12 12v7a2 2 0 0 0 4 0" />
    </svg>
  )
}
