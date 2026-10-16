import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Bot, Copy, KeyRound, Plus, Trash2 } from 'lucide-react'
import { del, get, post } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Modal, Select } from '../../ui/ui'
import { EXPIRY_PRESETS, expiryDate, tokenState, validAccountName, type ApiToken, type IssuedToken, type Role, type ServiceAccount } from './ApiTokensModel'

// Settings → API tokens (docs/integrations.md §1, docs/api.md "API tokens"): service accounts with a
// role, and "flow_…" bearer tokens that carry it. The token is shown once, when it is issued.

const strings: Dict = {
  en: {
    'tok.sub': 'Machine access to the Current API: Ledger, Beacon, scripts. A token acts with the role of its service account.',
    'tok.accounts': 'Service accounts',
    'tok.accounts.text': 'An account has a role; every token of the account gets exactly its permissions.',
    'tok.account.new': 'New service account',
    'tok.account.name': 'Name',
    'tok.account.name.hint': 'Without spaces, for example inventory-db',
    'tok.account.description': 'Description',
    'tok.account.role': 'Role',
    'tok.account.role.hint': 'Only a role whose permissions you have yourself.',
    'tok.account.created': 'Service account {name} created',
    'tok.account.delete': 'Delete the service account',
    'tok.account.delete.text': 'The account {name} and all its tokens are deleted; integrations using them stop working at once.',
    'tok.account.deleted': 'Service account deleted',
    'tok.account.none': 'No service accounts yet',
    'tok.tokens': 'Tokens',
    'tok.tokens.none': 'No tokens issued',
    'tok.issue': 'Issue token',
    'tok.issue.title': 'Issue an API token',
    'tok.name': 'Token name',
    'tok.name.hint': 'Where it is used, for example prod Ledger',
    'tok.expiry': 'Expires',
    'tok.expiry.30': 'in 30 days',
    'tok.expiry.90': 'in 90 days',
    'tok.expiry.365': 'in a year',
    'tok.expiry.0': 'never',
    'tok.issued': 'Token issued',
    'tok.once': 'Copy the token now: Current keeps only its hash and will not show it again.',
    'tok.copy': 'Copy',
    'tok.copied': 'Copied',
    'tok.done': 'Done',
    'tok.revoke': 'Revoke',
    'tok.revoke.title': 'Revoke the token',
    'tok.revoke.text': 'The token {name} stops working at once. This cannot be undone.',
    'tok.revoked': 'Token revoked',
    'tok.col.name': 'Name',
    'tok.col.account': 'Service account',
    'tok.col.token': 'Token',
    'tok.col.state': 'State',
    'tok.col.expires': 'Expires',
    'tok.col.used': 'Last used',
    'tok.col.created': 'Issued',
    'tok.col.role': 'Role',
    'tok.col.tokens': 'Active tokens',
    'tok.state.active': 'Active',
    'tok.state.expired': 'Expired',
    'tok.state.revoked': 'Revoked',
    'tok.never': 'never',
    'tok.unused': 'not used yet',
    'tok.by': 'by {user}',
    'tok.how': 'How to use',
    'tok.how.text': 'Send the token in the Authorization header. No CSRF header is needed.',
    'tok.roles.error': 'The list of roles is not available: you need the permission to view roles or users.',
    'tok.optional': 'optional',
  },
  ru: {
    'tok.sub': 'Машинный доступ к API Current: Ledger, Beacon, скрипты. Токен действует с ролью своей сервисной учётной записи.',
    'tok.accounts': 'Сервисные учётные записи',
    'tok.accounts.text': 'У записи есть роль; каждый её токен получает ровно эти права.',
    'tok.account.new': 'Новая сервисная запись',
    'tok.account.name': 'Имя',
    'tok.account.name.hint': 'Без пробелов, например inventory-db',
    'tok.account.description': 'Описание',
    'tok.account.role': 'Роль',
    'tok.account.role.hint': 'Только роль, все права которой есть у вас.',
    'tok.account.created': 'Сервисная запись {name} создана',
    'tok.account.delete': 'Удалить сервисную запись',
    'tok.account.delete.text': 'Запись {name} и все её токены будут удалены; интеграции с ними сразу перестанут работать.',
    'tok.account.deleted': 'Сервисная запись удалена',
    'tok.account.none': 'Сервисных записей пока нет',
    'tok.tokens': 'Токены',
    'tok.tokens.none': 'Токены не выпускались',
    'tok.issue': 'Выпустить токен',
    'tok.issue.title': 'Выпуск API-токена',
    'tok.name': 'Название токена',
    'tok.name.hint': 'Где используется, например prod Ledger',
    'tok.expiry': 'Срок действия',
    'tok.expiry.30': '30 дней',
    'tok.expiry.90': '90 дней',
    'tok.expiry.365': 'год',
    'tok.expiry.0': 'бессрочно',
    'tok.issued': 'Токен выпущен',
    'tok.once': 'Скопируйте токен сейчас: Current хранит только его хеш и больше его не покажет.',
    'tok.copy': 'Копировать',
    'tok.copied': 'Скопировано',
    'tok.done': 'Готово',
    'tok.revoke': 'Отозвать',
    'tok.revoke.title': 'Отзыв токена',
    'tok.revoke.text': 'Токен {name} сразу перестанет работать. Отменить это нельзя.',
    'tok.revoked': 'Токен отозван',
    'tok.col.name': 'Название',
    'tok.col.account': 'Сервисная запись',
    'tok.col.token': 'Токен',
    'tok.col.state': 'Состояние',
    'tok.col.expires': 'Действует до',
    'tok.col.used': 'Последнее использование',
    'tok.col.created': 'Выпущен',
    'tok.col.role': 'Роль',
    'tok.col.tokens': 'Активных токенов',
    'tok.state.active': 'Действует',
    'tok.state.expired': 'Истёк',
    'tok.state.revoked': 'Отозван',
    'tok.never': 'бессрочно',
    'tok.unused': 'ещё не использовался',
    'tok.by': '{user}',
    'tok.how': 'Как использовать',
    'tok.how.text': 'Передавайте токен в заголовке Authorization. Заголовок CSRF не нужен.',
    'tok.roles.error': 'Список ролей недоступен: нужно право просмотра ролей или пользователей.',
    'tok.optional': 'необязательно',
  },
}

const STATE_TONE = { active: 'ok', expired: 'warn', revoked: 'off' } as const

export default function ApiTokensPage() {
  const t = useT(strings)
  const { can } = useSession()
  const edit = can('tokens:edit')
  const accounts = useQuery({ queryKey: ['service-accounts'], queryFn: ({ signal }) => get<{ results: ServiceAccount[] }>('/api/service-accounts', signal) })
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: ({ signal }) => get<{ results: ApiToken[] }>('/api/tokens', signal) })
  const [newAccount, setNewAccount] = useState(false)
  const [issueFor, setIssueFor] = useState<number | null>(null)
  const error = accounts.error ?? tokens.error
  return (
    <Page
      id="tokens"
      subtitle={t('tok.sub')}
      actions={
        edit && (
          <Button variant="primary" onClick={() => setNewAccount(true)}>
            <Plus size={15} /> {t('tok.account.new')}
          </Button>
        )
      }
    >
      {error && <Banner kind="error" title={errorText(t, error).message} />}
      {accounts.isPending || tokens.isPending ? (
        <Loading />
      ) : (
        <div className="stack">
          <AccountsCard accounts={accounts.data?.results ?? []} edit={edit} onIssue={setIssueFor} />
          <TokensCard tokens={tokens.data?.results ?? []} edit={edit} />
          <Card title={t('tok.how')}>
            <p className="muted">{t('tok.how.text')}</p>
            <pre className="code-block">{`curl -H "Authorization: Bearer flow_…" ${window.location.origin}/api/exporters`}</pre>
          </Card>
        </div>
      )}
      {edit && <NewAccountDialog open={newAccount} onClose={() => setNewAccount(false)} />}
      {edit && <IssueDialog accountId={issueFor} accounts={accounts.data?.results ?? []} onClose={() => setIssueFor(null)} />}
    </Page>
  )
}

function AccountsCard({ accounts, edit, onIssue }: { accounts: ServiceAccount[]; edit: boolean; onIssue: (id: number) => void }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const [deleting, setDeleting] = useState<ServiceAccount | null>(null)
  const remove = useMutation({
    mutationFn: (id: number) => del(`/api/service-accounts/${id}`),
    onSuccess: () => {
      setDeleting(null)
      void qc.invalidateQueries({ queryKey: ['service-accounts'] })
      void qc.invalidateQueries({ queryKey: ['tokens'] })
      notify('ok', t('tok.account.deleted'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  return (
    <Card title={t('tok.accounts')} actions={<Chip tone="info">{accounts.length}</Chip>} pad={false}>
      <p className="muted card-pad">{t('tok.accounts.text')}</p>
      {accounts.length === 0 ? (
        <p className="card-pad muted">{t('tok.account.none')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('tok.account.name')}</th>
                <th>{t('tok.col.role')}</th>
                <th className="num">{t('tok.col.tokens')}</th>
                <th>{t('tok.col.created')}</th>
                {edit && <th className="actions-col" />}
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id}>
                  <td>
                    <div className="cell-main">
                      <Bot size={14} className="muted" /> {a.name}
                    </div>
                    {a.description && <div className="cell-sub muted">{a.description}</div>}
                  </td>
                  <td>
                    <Chip tone="purple" dot={false}>
                      {a.role}
                    </Chip>
                  </td>
                  <td className="num">{a.tokens}</td>
                  <td>
                    <div title={formatDate(a.created_at, locale)}>{relativeTime(a.created_at, locale)}</div>
                    {a.created_by && <div className="cell-sub muted">{t('tok.by', { user: a.created_by })}</div>}
                  </td>
                  {edit && (
                    <td className="actions-col">
                      <div className="row">
                        <Button size="sm" onClick={() => onIssue(a.id)}>
                          <KeyRound size={14} /> {t('tok.issue')}
                        </Button>
                        <button type="button" className="icon-btn danger-icon" aria-label={t('tok.account.delete')} title={t('tok.account.delete')} onClick={() => setDeleting(a)}>
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={deleting !== null}
        title={t('tok.account.delete')}
        onClose={() => setDeleting(null)}
        footer={
          <>
            <Button onClick={() => setDeleting(null)}>{t('cancel')}</Button>
            <Button variant="danger" busy={remove.isPending} onClick={() => deleting && remove.mutate(deleting.id)}>
              {t('delete')}
            </Button>
          </>
        }
      >
        <p>{t('tok.account.delete.text', { name: deleting?.name ?? '' })}</p>
      </Modal>
    </Card>
  )
}

function TokensCard({ tokens, edit }: { tokens: ApiToken[]; edit: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const [revoking, setRevoking] = useState<ApiToken | null>(null)
  const revoke = useMutation({
    mutationFn: (id: number) => del<ApiToken>(`/api/tokens/${id}`),
    onSuccess: () => {
      setRevoking(null)
      void qc.invalidateQueries({ queryKey: ['tokens'] })
      void qc.invalidateQueries({ queryKey: ['service-accounts'] })
      notify('ok', t('tok.revoked'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  return (
    <Card title={t('tok.tokens')} actions={<Chip tone="info">{tokens.filter((x) => tokenState(x) === 'active').length}</Chip>} pad={false}>
      {tokens.length === 0 ? (
        <p className="card-pad muted">{t('tok.tokens.none')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('tok.col.name')}</th>
                <th>{t('tok.col.account')}</th>
                <th>{t('tok.col.token')}</th>
                <th>{t('tok.col.state')}</th>
                <th>{t('tok.col.expires')}</th>
                <th>{t('tok.col.used')}</th>
                <th>{t('tok.col.created')}</th>
                {edit && <th className="actions-col" />}
              </tr>
            </thead>
            <tbody>
              {tokens.map((x) => {
                const state = tokenState(x)
                return (
                  <tr key={x.id}>
                    <td className="cell-main">{x.name}</td>
                    <td>{x.service_account}</td>
                    <td className="mono">{x.display}</td>
                    <td>
                      <Chip tone={STATE_TONE[state]}>{t(`tok.state.${state}`)}</Chip>
                    </td>
                    <td>{x.expires_at ? formatDate(x.expires_at, locale) : t('tok.never')}</td>
                    <td>
                      {x.last_used_at ? (
                        <>
                          <div title={formatDate(x.last_used_at, locale)}>{relativeTime(x.last_used_at, locale)}</div>
                          {x.last_used_from && <div className="cell-sub muted mono">{x.last_used_from}</div>}
                        </>
                      ) : (
                        <span className="muted">{t('tok.unused')}</span>
                      )}
                    </td>
                    <td>
                      <div title={formatDate(x.created_at, locale)}>{relativeTime(x.created_at, locale)}</div>
                      {x.created_by && <div className="cell-sub muted">{t('tok.by', { user: x.created_by })}</div>}
                    </td>
                    {edit && (
                      <td className="actions-col">
                        {state !== 'revoked' && (
                          <Button size="sm" variant="danger-soft" onClick={() => setRevoking(x)}>
                            <Ban size={14} /> {t('tok.revoke')}
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={revoking !== null}
        title={t('tok.revoke.title')}
        onClose={() => setRevoking(null)}
        footer={
          <>
            <Button onClick={() => setRevoking(null)}>{t('cancel')}</Button>
            <Button variant="danger" busy={revoke.isPending} onClick={() => revoking && revoke.mutate(revoking.id)}>
              {t('tok.revoke')}
            </Button>
          </>
        }
      >
        <p>{t('tok.revoke.text', { name: revoking ? `${revoking.service_account}/${revoking.name}` : '' })}</p>
      </Modal>
    </Card>
  )
}

function NewAccountDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const roles = useQuery({ queryKey: ['roles'], queryFn: ({ signal }) => get<{ results: Role[] }>('/api/roles', signal), enabled: open })
  const [draft, setDraft] = useState({ name: '', description: '', role_id: 0 })
  const roleId = draft.role_id || roles.data?.results.find((r) => !r.builtin)?.id || roles.data?.results[0]?.id || 0
  const close = () => {
    setDraft({ name: '', description: '', role_id: 0 })
    onClose()
  }
  const create = useMutation({
    mutationFn: () => post<ServiceAccount>('/api/service-accounts', { name: draft.name.trim(), description: draft.description.trim(), role_id: roleId }),
    onSuccess: (a) => {
      void qc.invalidateQueries({ queryKey: ['service-accounts'] })
      notify('ok', t('tok.account.created', { name: a.name }))
      close()
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const ok = validAccountName(draft.name) && roleId > 0
  return (
    <Modal
      open={open}
      title={t('tok.account.new')}
      onClose={close}
      footer={
        <>
          <Button onClick={close}>{t('cancel')}</Button>
          <Button variant="primary" busy={create.isPending} disabled={!ok} onClick={() => create.mutate()}>
            {t('save')}
          </Button>
        </>
      }
    >
      <Field label={t('tok.account.name')} hint={t('tok.account.name.hint')}>
        {(id) => <Input id={id} value={draft.name} spellCheck={false} aria-invalid={draft.name !== '' && !validAccountName(draft.name)} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />}
      </Field>
      <Field label={t('tok.account.description')} optional={t('tok.optional')}>
        {(id) => <Input id={id} value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />}
      </Field>
      {roles.error ? (
        <Banner kind="warn" title={t('tok.roles.error')} />
      ) : (
        <Field label={t('tok.account.role')} hint={t('tok.account.role.hint')}>
          {(id) => (
            <Select id={id} value={String(roleId)} onChange={(e) => setDraft({ ...draft, role_id: Number(e.target.value) })}>
              {(roles.data?.results ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
    </Modal>
  )
}

function IssueDialog({ accountId, accounts, onClose }: { accountId: number | null; accounts: ServiceAccount[]; onClose: () => void }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [days, setDays] = useState<number>(90)
  const [issued, setIssued] = useState<IssuedToken | null>(null)
  const [copied, setCopied] = useState(false)
  const account = accounts.find((a) => a.id === accountId)
  const close = () => {
    setName('')
    setDays(90)
    setIssued(null)
    setCopied(false)
    onClose()
  }
  const issue = useMutation({
    mutationFn: () => post<IssuedToken>('/api/tokens', { service_account_id: accountId, name: name.trim(), expires_at: expiryDate(days) }),
    onSuccess: (x) => {
      setIssued(x)
      void qc.invalidateQueries({ queryKey: ['tokens'] })
      void qc.invalidateQueries({ queryKey: ['service-accounts'] })
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const copy = async () => {
    if (!issued) return
    try {
      await navigator.clipboard.writeText(issued.token)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }
  return (
    <Modal
      open={accountId !== null}
      title={issued ? t('tok.issued') : `${t('tok.issue.title')} · ${account?.name ?? ''}`}
      onClose={close}
      footer={
        issued ? (
          <Button variant="primary" onClick={close}>
            {t('tok.done')}
          </Button>
        ) : (
          <>
            <Button onClick={close}>{t('cancel')}</Button>
            <Button variant="primary" busy={issue.isPending} disabled={!name.trim()} onClick={() => issue.mutate()}>
              <KeyRound size={15} /> {t('tok.issue')}
            </Button>
          </>
        )
      }
    >
      {issued ? (
        <Banner kind="warn" title={t('tok.once')}>
          <div className="row" style={{ alignItems: 'center', flexWrap: 'wrap', marginTop: 8 }}>
            <code className="mono" style={{ wordBreak: 'break-all', userSelect: 'all' }}>
              {issued.token}
            </code>
            <Button size="sm" onClick={() => void copy()}>
              <Copy size={14} /> {copied ? t('tok.copied') : t('tok.copy')}
            </Button>
          </div>
        </Banner>
      ) : (
        <>
          <Field label={t('tok.name')} hint={t('tok.name.hint')}>
            {(id) => <Input id={id} value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <Field label={t('tok.expiry')}>
            {(id) => (
              <Select id={id} value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
                {EXPIRY_PRESETS.map((d) => (
                  <option key={d} value={d}>
                    {t(`tok.expiry.${d}`)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </>
      )}
    </Modal>
  )
}
