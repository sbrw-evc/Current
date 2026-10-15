import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Plus, Trash2 } from 'lucide-react'
import { del, get, post, put } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { checkPassword, defaultPolicy, policyError, type PasswordPolicy } from '../../lib/policy'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Modal, Password, Select, Switch } from '../../ui/ui'
import { PolicyChecklist, PolicyEditor } from './components'
import { usePolicy, type PolicyView } from './Profile'
import { strings } from './strings'

type Role = { id: number; name: string }
type User = { id: number; username: string; name: string; email: string; source: string; role_id: number; role: string; disabled: boolean; last_login_at?: string }

const fail = (t: (k: string) => string) => (e: unknown) => {
  const x = errorText(t, e)
  notify('error', x.message, x.detail)
}

// UsersPage: Settings → Users. Every account of Flow with its sign-in source; local accounts are
// created here, accounts of Umbrella single sign-in follow the hub.
export default function UsersPage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const edit = can('users:edit')
  const users = useQuery({ queryKey: ['users'], queryFn: ({ signal }) => get<{ results: User[] }>('/api/users', signal) })
  const roles = useQuery({ queryKey: ['roles'], queryFn: ({ signal }) => get<{ results: Role[] }>('/api/roles', signal) })
  const [open, setOpen] = useState<User | 'new' | null>(null)
  return (
    <Page
      id="users"
      title={t('us.title')}
      subtitle={t('us.sub')}
      actions={
        edit && (
          <Button variant="primary" onClick={() => setOpen('new')} disabled={!roles.data}>
            <Plus size={16} /> {t('us.add')}
          </Button>
        )
      }
    >
      <Card pad={false}>
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('us.col.user')}</th>
              <th>{t('us.col.source')}</th>
              <th>{t('us.col.role')}</th>
              <th>{t('us.col.last')}</th>
              <th>{t('us.col.state')}</th>
            </tr>
          </thead>
          <tbody>
            {users.data?.results.map((u) => (
              <tr key={u.id} className="clickable" onClick={() => setOpen(u)}>
                <td>
                  <strong>{u.name || u.username}</strong>
                  <div className="hint">
                    {u.username}
                    {u.email && ` · ${u.email}`}
                  </div>
                </td>
                <td>{t(`pr.source.${u.source}`)}</td>
                <td>{u.role}</td>
                <td className="muted">{u.last_login_at ? formatDate(u.last_login_at, locale) : t('us.never')}</td>
                <td>
                  <Chip tone={u.disabled ? 'off' : 'ok'}>{u.disabled ? t('us.disabled') : t('us.active')}</Chip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {open && roles.data && <UserDialog user={open === 'new' ? null : open} roles={roles.data.results} edit={edit} onClose={() => setOpen(null)} />}
    </Page>
  )
}

function UserDialog({ user, roles, edit, onClose }: { user: User | null; roles: Role[]; edit: boolean; onClose: () => void }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const pol = usePolicy()
  const policy = pol.data?.policy ?? defaultPolicy
  const [form, setForm] = useState({ username: user?.username ?? '', name: user?.name ?? '', email: user?.email ?? '', role_id: user?.role_id ?? roles[roles.length - 1]?.id ?? 0, disabled: user?.disabled ?? false })
  const [password, setPassword] = useState('')
  const keys = useQuery({ queryKey: ['users', user?.id, 'passkeys'], queryFn: ({ signal }) => get<unknown[]>(`/api/users/${user!.id}/passkeys`, signal), enabled: !!user })
  const done = () => {
    void qc.invalidateQueries({ queryKey: ['users'] })
    notify('ok', t('us.saved'))
    onClose()
  }
  const save = useMutation({
    mutationFn: async () => {
      if (!user) return post('/api/users', { ...form, password })
      await put(`/api/users/${user.id}`, { name: form.name, email: form.email, role_id: form.role_id, disabled: form.disabled })
      if (password) await put(`/api/users/${user.id}/password`, { password })
    },
    onSuccess: done,
    onError: fail(t),
  })
  const remove = useMutation({ mutationFn: () => del(`/api/users/${user!.id}`), onSuccess: done, onError: fail(t) })
  const dropKeys = useMutation({ mutationFn: () => del(`/api/users/${user!.id}/passkeys`), onSuccess: done, onError: fail(t) })
  const local = !user || user.source === 'local'
  const hub = user?.source === 'umbrella'
  const pwOk = password === '' ? !!user : checkPassword(password, form.username, policy).length === 0
  return (
    <Modal
      open
      title={user ? user.name || user.username : t('us.add')}
      onClose={onClose}
      footer={
        edit && (
          <>
            {user && (
              <Button onClick={() => window.confirm(t('us.delete.ask', { name: user.username })) && remove.mutate()}>
                <Trash2 size={14} /> {t('us.delete')}
              </Button>
            )}
            <Button variant="primary" busy={save.isPending} disabled={!form.username || !pwOk} onClick={() => save.mutate()}>
              {user ? t('us.save') : t('us.create')}
            </Button>
          </>
        )
      }
    >
      {hub && <Banner kind="info" title={t('us.hub')} />}
      <fieldset className="plain-fieldset stack" disabled={!edit}>
        {!user && <Field label={t('pr.username')}>{(id) => <Input id={id} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="off" />}</Field>}
        <Field label={t('us.name')}>{(id) => <Input id={id} value={form.name} disabled={hub} onChange={(e) => setForm({ ...form, name: e.target.value })} />}</Field>
        <Field label={t('us.email')}>{(id) => <Input id={id} value={form.email} disabled={hub} onChange={(e) => setForm({ ...form, email: e.target.value })} />}</Field>
        <Field label={t('pr.role')}>
          {(id) => (
            <Select id={id} value={String(form.role_id)} disabled={hub} onChange={(e) => setForm({ ...form, role_id: Number(e.target.value) })}>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {user && <Switch checked={form.disabled} onChange={(v) => setForm({ ...form, disabled: v })} label={t('us.disable')} disabled={!edit || hub} />}
        {local && (
          <>
            <Field label={user ? t('us.setpw') : t('us.password')}>{(id) => <Password id={id} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}</Field>
            {password !== '' && <PolicyChecklist policy={policy} password={password} username={form.username} />}
          </>
        )}
        {user && (keys.data?.length ?? 0) > 0 && (
          <div className="row wrap">
            <span>{t('us.passkeys', { n: keys.data!.length })}</span>
            <Button size="sm" busy={dropKeys.isPending} onClick={() => window.confirm(t('us.passkeys.ask', { name: user.username })) && dropKeys.mutate()}>
              <Fingerprint size={14} /> {t('us.passkeys.remove')}
            </Button>
          </div>
        )}
      </fieldset>
    </Modal>
  )
}

// PolicyPage: Settings → Password policy.
export function PolicyPage() {
  const t = useT(strings)
  const qc = useQueryClient()
  const { can } = useSession()
  const q = usePolicy()
  const [draft, setDraft] = useState<PasswordPolicy>(defaultPolicy)
  useEffect(() => {
    if (q.data) setDraft(q.data.policy)
  }, [q.data])
  const save = useMutation({
    mutationFn: () => put<PolicyView>('/api/settings/password-policy', draft),
    onSuccess: (v) => {
      qc.setQueryData(['password-policy'], v)
      notify('ok', t('pol.saved'))
    },
    onError: fail(t),
  })
  const managed = q.data?.managed_by_hub ?? false
  const edit = can('users:edit') && !managed
  const [sample, setSample] = useState('')
  return (
    <Page
      id="password-policy"
      title={t('pol.title')}
      subtitle={t('pol.sub')}
      actions={
        edit && (
          <Button variant="primary" busy={save.isPending} disabled={policyError(draft) !== null} onClick={() => save.mutate()}>
            {t('ss.save')}
          </Button>
        )
      }
    >
      {managed && <Banner kind="info" title={t('pol.hub')} />}
      <div className="cards">
        <Card title={t('pol.title')}>
          <PolicyEditor value={draft} onChange={setDraft} disabled={!edit} />
        </Card>
        <Card title={t('pr.password.new')}>
          <Field label={t('pr.password.new')}>{(id) => <Password id={id} value={sample} onChange={(e) => setSample(e.target.value)} autoComplete="off" />}</Field>
          <PolicyChecklist policy={draft} password={sample} username="" />
        </Card>
      </div>
    </Page>
  )
}
