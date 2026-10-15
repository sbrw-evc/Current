import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, get, post } from '../../api/client'
import type { Me } from '../../api/types'
import { errorText, useLocale, useT } from '../../i18n'
import { checkPassword, defaultPolicy, type PasswordPolicy } from '../../lib/policy'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Field, formatDate, Password, Rows } from '../../ui/ui'
import { PasskeysCard, PolicyChecklist } from './components'
import { strings } from './strings'

export type PolicyView = { policy: PasswordPolicy; managed_by_hub: boolean }

export function usePolicy() {
  return useQuery({ queryKey: ['password-policy'], queryFn: ({ signal }) => get<PolicyView>('/api/settings/password-policy', signal) })
}

// ProfilePage: the account of the signed-in person, the password (local accounts) and passkeys.
export default function ProfilePage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { user } = useSession()
  const me = useQuery({ queryKey: ['me'], queryFn: ({ signal }) => get<Me>('/api/auth/me', signal) })
  const u = me.data?.user ?? user
  const source = u.source ?? 'local'
  const hubPasskeys = source === 'umbrella'
  return (
    <Page id="profile" title={t('pr.title')} subtitle={t('pr.sub')}>
      {u.password_expired && <Banner kind="error" title={t('pr.expired')}>{t('pr.expired.text')}</Banner>}
      {!u.password_expired && u.password_expiry_warning && u.password_expires_at && (
        <Banner kind="warn" title={t('pr.expiring', { date: formatDate(u.password_expires_at, locale) })} />
      )}
      <div className="cards">
        <Card title={t('pr.account')}>
          <Rows
            rows={[
              [t('pr.username'), u.username],
              [t('pr.source'), t(`pr.source.${source}`)],
              [t('pr.role'), u.role],
            ]}
          />
        </Card>
        {source === 'local' ? <PasswordCard username={u.username} /> : (
          <Card title={t('pr.password')}>
            <p className="muted">{t('pr.password.external', { source: t(`pr.source.${source}`) })}</p>
          </Card>
        )}
        {u.passkeys_enabled && <PasskeysCard fromHub={hubPasskeys} />}
      </div>
    </Page>
  )
}

function PasswordCard({ username }: { username: string }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const pol = usePolicy()
  const policy = pol.data?.policy ?? defaultPolicy
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const [violations, setViolations] = useState<string[]>([])
  const save = useMutation({
    mutationFn: () => post('/api/auth/password', { current, new: next }),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setRepeat('')
      setViolations([])
      void qc.invalidateQueries({ queryKey: ['me'] })
      notify('ok', t('pr.password.saved'))
    },
    onError: (e) => {
      if (e instanceof ApiError && e.violations) setViolations(e.violations)
      const x = errorText(t, e)
      notify('error', x.message, e instanceof ApiError && e.violations ? e.violations.map((v) => t(`pp.${v}`, { n: policy.history_count })).join('; ') : x.detail)
    },
  })
  const ok = current !== '' && next === repeat && checkPassword(next, username, policy).length === 0
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate()
  }
  return (
    <form className="card status-card" onSubmit={submit} noValidate>
      <header>
        <h2 className="card-title">{t('pr.password')}</h2>
      </header>
      <div className="stack">
        <Field label={t('pr.password.current')}>{(id) => <Password id={id} value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />}</Field>
        <Field label={t('pr.password.new')}>{(id) => <Password id={id} value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />}</Field>
        <Field label={t('pr.password.repeat')}>{(id) => <Password id={id} value={repeat} onChange={(e) => setRepeat(e.target.value)} autoComplete="new-password" />}</Field>
        <PolicyChecklist policy={policy} password={next} username={username} confirm={repeat} />
        {violations.includes('history') && <Banner kind="error" title={t('pp.history', { n: policy.history_count })} />}
      </div>
      <div className="card-actions row">
        <Button type="submit" variant="primary" busy={save.isPending} disabled={!ok}>
          {t('pr.password.save')}
        </Button>
      </div>
    </form>
  )
}
