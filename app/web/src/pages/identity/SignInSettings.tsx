import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, CheckCircle2, Plus, RefreshCw, Trash2, Umbrella, XCircle } from 'lucide-react'
import { del, get, post, put } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { SecretField } from '../../ui/SecretField'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Modal, Rows, Select, Switch, Textarea } from '../../ui/ui'
import { ProviderMark } from './components'
import { strings } from './strings'

type Role = { id: number; name: string }
type Method = { id: string; title: string }
type Mapping = { match: string; role_id: number; role?: string }
type Identity = {
  enabled: boolean
  connected: boolean
  hub: string
  client_id: string
  application: string
  role_map: Mapping[]
  default_role_id: number
  admin_role_id: number
  link_local: boolean
  sso: boolean
  sync_users: boolean
  sync_policy: boolean
  sync_passkeys: boolean
  methods: Method[]
  hub_passkeys: { enabled: boolean; rp_id: string }
  redirect_uri: string
  public_url: string
  status: { last_sync?: string; ok: boolean; error?: string; created: number; updated: number; disabled: number; users: number; conflicts: string[] }
}
type Check = { hub: string; application: string; methods: Method[]; passkeys: { enabled: boolean; rp_id: string }; passkeys_here: boolean; users: number; roles: string[]; groups: string[]; conflicts: string[] }

const fail = (t: (k: string) => string) => (e: unknown) => {
  const x = errorText(t, e)
  notify('error', x.message, x.detail)
}

// SignInSettings: Settings → Sign-in. Umbrella single sign-in (connected in three steps with the
// key made by Umbrella Monitoring), passkeys and Google / Apple / OpenID Connect providers.
export default function SignInSettings() {
  const t = useT(strings)
  const { can } = useSession()
  const edit = can('users:edit')
  const roles = useQuery({ queryKey: ['roles'], queryFn: ({ signal }) => get<{ results: Role[] }>('/api/roles', signal) })
  return (
    <Page id="signin" title={t('ss.title')} subtitle={t('ss.sub')}>
      <UmbrellaCard edit={edit} roles={roles.data?.results ?? []} />
      <div className="cards">
        <PasskeySettingsCard edit={edit} />
        <ProvidersCard edit={edit} roles={roles.data?.results ?? []} />
      </div>
    </Page>
  )
}

function UmbrellaCard({ edit, roles }: { edit: boolean; roles: Role[] }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['identity'], queryFn: ({ signal }) => get<Identity>('/api/settings/identity', signal) })
  const [wizard, setWizard] = useState(false)
  const set = (v: Identity) => qc.setQueryData(['identity'], v)
  const sync = useMutation({ mutationFn: () => post<Identity>('/api/settings/identity/sync'), onSuccess: set, onError: fail(t) })
  const disconnect = useMutation({ mutationFn: () => del<Identity>('/api/settings/identity'), onSuccess: set, onError: fail(t) })
  const v = q.data
  const st = v?.status
  return (
    <Card
      title={
        <span className="row">
          <Umbrella size={18} aria-hidden /> {t('ss.umb')}
        </span>
      }
      actions={
        edit &&
        v && (
          <>
            {v.connected && (
              <Button size="sm" busy={sync.isPending} onClick={() => sync.mutate()}>
                <RefreshCw size={14} /> {t('ss.umb.sync')}
              </Button>
            )}
            <Button size="sm" variant={v.connected ? 'secondary' : 'primary'} onClick={() => setWizard(true)}>
              {v.connected ? t('ss.umb.change') : t('ss.umb.connect')}
            </Button>
            {v.connected && (
              <Button size="sm" onClick={() => window.confirm(t('ss.umb.disconnect.ask')) && disconnect.mutate()}>
                {t('ss.umb.disconnect')}
              </Button>
            )}
          </>
        )
      }
    >
      <p className="muted">{t('ss.umb.text')}</p>
      {v && (
        <Rows
          rows={[
            [t('ss.wiz.enabled'), v.connected ? <Chip tone={v.enabled ? 'ok' : 'warn'}>{v.enabled ? t('ss.umb.connected', { hub: v.hub }) : t('ss.umb.paused')}</Chip> : <Chip tone="off">{t('ss.umb.off')}</Chip>],
            ...(st?.last_sync
              ? ([
                  [t('ss.umb.last'), <span key="s">{st.ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />} {formatDate(st.last_sync, locale)} · {t('ss.umb.result', { users: st.users, created: st.created, disabled: st.disabled })}</span>],
                ] as [string, React.ReactNode][])
              : []),
          ]}
        />
      )}
      {st?.error && <Banner kind="error" title={t('ss.umb.error')}>{st.error}</Banner>}
      {st && st.conflicts.length > 0 && <Banner kind="warn" title={t('ss.umb.conflicts', { list: st.conflicts.join(', ') })} />}
      {wizard && v && <ConnectWizard current={v} roles={roles} onClose={() => setWizard(false)} onSaved={(x) => { set(x); setWizard(false) }} />}
    </Card>
  )
}

function Steps({ step }: { step: number }) {
  const t = useT(strings)
  return (
    <ol className="id-steps">
      {[1, 2, 3].map((n) => (
        <li key={n} className={n === step ? 'current' : ''} aria-current={n === step ? 'step' : undefined}>
          <span className="id-step-n">{n < step ? <Check size={13} /> : n}</span>
          {t(`ss.wiz.s${n}`)}
        </li>
      ))}
    </ol>
  )
}

function ConnectWizard({ current, roles, onClose, onSaved }: { current: Identity; roles: Role[]; onClose: () => void; onSaved: (v: Identity) => void }) {
  const t = useT(strings)
  const [step, setStep] = useState(1)
  const [key, setKey] = useState('')
  const [check, setCheck] = useState<Check | null>(null)
  const admin = roles.find((r) => /admin/i.test(r.name))
  const [form, setForm] = useState(() => ({
    role_map: current.role_map.length ? current.role_map : [],
    default_role_id: current.default_role_id,
    admin_role_id: current.admin_role_id || admin?.id || 0,
    link_local: current.connected ? current.link_local : true,
    sso: current.connected ? current.sso : true,
    sync_users: current.connected ? current.sync_users : true,
    sync_policy: current.connected ? current.sync_policy : true,
    sync_passkeys: current.connected ? current.sync_passkeys : true,
    enabled: true,
  }))
  const verify = useMutation({ mutationFn: () => post<Check>('/api/settings/identity/check', { key }), onSuccess: setCheck, onError: fail(t) })
  const save = useMutation({
    mutationFn: () => put<Identity>('/api/settings/identity', { key, ...form }),
    onSuccess: (v) => {
      notify('ok', t('ss.wiz.saved'))
      onSaved(v)
    },
    onError: fail(t),
  })
  useEffect(() => {
    if (current.connected && key === '') verify.mutate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const options = check ? [...check.roles, ...check.groups] : []
  const setRow = (i: number, m: Partial<Mapping>) => setForm({ ...form, role_map: form.role_map.map((x, j) => (j === i ? { ...x, ...m } : x)) })
  const roleSelect = (value: number, onChange: (v: number) => void, label: string, none = true) => (
    <Select aria-label={label} value={String(value)} onChange={(e) => onChange(Number(e.target.value))}>
      {none && <option value="0">{t('ss.wiz.noaccess')}</option>}
      {roles.map((r) => (
        <option key={r.id} value={r.id}>
          {r.name}
        </option>
      ))}
    </Select>
  )
  return (
    <Modal
      open
      title={t('ss.umb')}
      onClose={onClose}
      footer={
        <>
          {step > 1 && <Button onClick={() => setStep(step - 1)}>{t('ss.wiz.back')}</Button>}
          {step < 3 ? (
            <Button variant="primary" disabled={!check} onClick={() => setStep(step + 1)}>
              {t('ss.wiz.next')}
            </Button>
          ) : (
            <Button variant="primary" busy={save.isPending} onClick={() => save.mutate()}>
              {t('ss.wiz.save')}
            </Button>
          )}
        </>
      }
    >
      <Steps step={step} />
      {step === 1 && (
        <div className="stack">
          <Field label={t('ss.wiz.key')} hint={t('ss.wiz.key.hint', { redirect: current.redirect_uri || '—' })}>
            {(id) => <Textarea id={id} rows={4} value={key} placeholder={current.connected ? '••••••' : 'umbid1.…'} spellCheck={false} onChange={(e) => { setKey(e.target.value); setCheck(null) }} />}
          </Field>
          <div>
            <Button busy={verify.isPending} disabled={!key.trim() && !current.connected} onClick={() => verify.mutate()}>
              {t('ss.wiz.check')}
            </Button>
          </div>
          {check && (
            <>
              <Banner kind="ok" title={t('ss.wiz.checked', { app: check.application, hub: check.hub, users: check.users })} />
              {check.passkeys.enabled && (
                <p className="hint">{check.passkeys_here ? t('ss.wiz.passkeys.here', { domain: check.passkeys.rp_id }) : t('ss.wiz.passkeys.not', { domain: check.passkeys.rp_id })}</p>
              )}
            </>
          )}
        </div>
      )}
      {step === 2 && (
        <div className="stack">
          <div className="field">
            <label>{t('ss.wiz.map')}</label>
            <datalist id="hub-roles">
              {options.map((o) => (
                <option key={o} value={o} />
              ))}
            </datalist>
            <div className="stack">
              {form.role_map.map((m, i) => (
                <div key={i} className="id-map-row">
                  <Input aria-label={t('ss.wiz.match')} placeholder={t('ss.wiz.match')} list="hub-roles" value={m.match} onChange={(e) => setRow(i, { match: e.target.value })} />
                  {roleSelect(m.role_id, (v) => setRow(i, { role_id: v }), t('ss.wiz.match'), false)}
                  <button type="button" className="icon-btn danger-icon" aria-label="×" onClick={() => setForm({ ...form, role_map: form.role_map.filter((_, j) => j !== i) })}>
                    <Trash2 size={16} />
                  </button>
                </div>
              ))}
              <div>
                <Button size="sm" onClick={() => setForm({ ...form, role_map: [...form.role_map, { match: check?.roles[0] ?? '', role_id: roles[roles.length - 1]?.id ?? 0 }] })}>
                  <Plus size={14} /> {t('ss.wiz.map.add')}
                </Button>
              </div>
            </div>
            <div className="hint">{t('ss.wiz.map.hint')}</div>
          </div>
          <Field label={t('ss.wiz.admin')}>{() => roleSelect(form.admin_role_id, (v) => setForm({ ...form, admin_role_id: v }), t('ss.wiz.admin'))}</Field>
          <Field label={t('ss.wiz.default')}>{() => roleSelect(form.default_role_id, (v) => setForm({ ...form, default_role_id: v }), t('ss.wiz.default'))}</Field>
          <Switch checked={form.link_local} onChange={(v) => setForm({ ...form, link_local: v })} label={t('ss.wiz.link')} hint={t('ss.wiz.link.hint')} />
          {check && check.conflicts.length > 0 && <p className="hint">{t('ss.umb.conflicts', { list: check.conflicts.join(', ') })}</p>}
        </div>
      )}
      {step === 3 && (
        <div className="stack">
          <Switch checked={form.sso} onChange={(v) => setForm({ ...form, sso: v })} label={t('ss.wiz.sso')} />
          <Switch checked={form.sync_users} onChange={(v) => setForm({ ...form, sync_users: v })} label={t('ss.wiz.users')} />
          <Switch checked={form.sync_policy} onChange={(v) => setForm({ ...form, sync_policy: v })} label={t('ss.wiz.policy')} />
          <Switch checked={form.sync_passkeys} onChange={(v) => setForm({ ...form, sync_passkeys: v })} label={t('ss.wiz.passkeys')} />
          <Switch checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label={t('ss.wiz.enabled')} />
        </div>
      )}
    </Modal>
  )
}

type PasskeyView = { enabled: boolean; rp_id: string; from_hub: boolean; effective_rp_id: string }

function PasskeySettingsCard({ edit }: { edit: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['passkey-settings'], queryFn: ({ signal }) => get<PasskeyView>('/api/settings/passkeys', signal) })
  const [draft, setDraft] = useState({ enabled: false, rp_id: '' })
  useEffect(() => {
    if (q.data) setDraft({ enabled: q.data.enabled, rp_id: q.data.rp_id })
  }, [q.data])
  const save = useMutation({
    mutationFn: () => put<PasskeyView>('/api/settings/passkeys', draft),
    onSuccess: (v) => {
      qc.setQueryData(['passkey-settings'], v)
      notify('ok', t('ss.saved'))
    },
    onError: fail(t),
  })
  const v = q.data
  return (
    <Card title={t('ss.pk')} actions={edit && v && !v.from_hub && <Button size="sm" variant="primary" busy={save.isPending} onClick={() => save.mutate()}>{t('ss.save')}</Button>}>
      <p className="muted">{t('ss.pk.text')}</p>
      {v?.from_hub ? (
        <Banner kind="info" title={t('ss.pk.hub', { domain: v.effective_rp_id })} />
      ) : (
        <fieldset className="plain-fieldset stack" disabled={!edit}>
          <Switch checked={draft.enabled} onChange={(x) => setDraft({ ...draft, enabled: x })} label={t('ss.pk.on')} disabled={!edit} />
          <Field label={t('ss.pk.domain')} hint={t('ss.pk.domain.hint', { host: v?.effective_rp_id || '—' })}>
            {(id) => <Input id={id} value={draft.rp_id} placeholder={v?.effective_rp_id} onChange={(e) => setDraft({ ...draft, rp_id: e.target.value })} />}
          </Field>
        </fieldset>
      )}
    </Card>
  )
}

type Provider = {
  enabled: boolean
  title: string
  issuer: string
  client_id: string
  team_id?: string
  key_id?: string
  allowed_domains: string[]
  existing_only: boolean
  scopes?: string
  groups_claim?: string
  admin_group?: string
  role_id: number
  admin_role_id: number
}
type ProviderView = { kind: 'google' | 'apple' | 'oidc'; config: Provider; client_secret_set: boolean; private_key_set: boolean; redirect_uri: string; users: number }

function ProvidersCard({ edit, roles }: { edit: boolean; roles: Role[] }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['providers'], queryFn: ({ signal }) => get<{ public_url: string; providers: ProviderView[] }>('/api/settings/providers', signal) })
  const [open, setOpen] = useState<ProviderView | null>(null)
  return (
    <Card title={t('ss.prov')}>
      <p className="muted">{t('ss.prov.text')}</p>
      <ul className="id-list">
        {q.data?.providers.map((p) => (
          <li key={p.kind}>
            <ProviderMark id={p.kind} />
            <div className="id-grow">
              <strong>{p.kind === 'oidc' && p.config.title ? p.config.title : t(`ss.prov.${p.kind}`)}</strong>
            </div>
            <Chip tone={p.config.enabled ? 'ok' : 'off'}>{p.config.enabled ? t('ss.prov.on') : t('ss.prov.off')}</Chip>
            <Button size="sm" onClick={() => setOpen(p)}>
              {t('ss.prov.edit')}
            </Button>
          </li>
        ))}
      </ul>
      {open && (
        <ProviderDialog
          view={open}
          edit={edit}
          roles={roles}
          onClose={() => setOpen(null)}
          onSaved={() => {
            setOpen(null)
            void qc.invalidateQueries({ queryKey: ['providers'] })
          }}
        />
      )}
    </Card>
  )
}

function ProviderDialog({ view, edit, roles, onClose, onSaved }: { view: ProviderView; edit: boolean; roles: Role[]; onClose: () => void; onSaved: () => void }) {
  const t = useT(strings)
  const [c, setC] = useState<Provider>(view.config)
  const [domains, setDomains] = useState(view.config.allowed_domains.join(' '))
  const [secret, setSecret] = useState('')
  const [pkey, setPkey] = useState('')
  const set = (p: Partial<Provider>) => setC({ ...c, ...p })
  const save = useMutation({
    mutationFn: () =>
      put(`/api/settings/providers/${view.kind}`, {
        config: { ...c, allowed_domains: domains.split(/[\s,;]+/).filter(Boolean) },
        client_secret: secret,
        private_key: pkey,
      }),
    onSuccess: () => {
      notify('ok', t('ss.saved'))
      onSaved()
    },
    onError: fail(t),
  })
  const apple = view.kind === 'apple'
  const roleSelect = (value: number, onChange: (v: number) => void, label: string) => (
    <Select aria-label={label} value={String(value)} onChange={(e) => onChange(Number(e.target.value))}>
      <option value="0">—</option>
      {roles.map((r) => (
        <option key={r.id} value={r.id}>
          {r.name}
        </option>
      ))}
    </Select>
  )
  return (
    <Modal
      open
      title={t(`ss.prov.${view.kind}`)}
      onClose={onClose}
      footer={
        edit && (
          <Button variant="primary" busy={save.isPending} onClick={() => save.mutate()}>
            {t('ss.save')}
          </Button>
        )
      }
    >
      <fieldset className="plain-fieldset stack" disabled={!edit}>
        <Switch checked={c.enabled} onChange={(v) => set({ enabled: v })} label={t('ss.prov.enabled')} disabled={!edit} />
        {view.kind === 'oidc' && (
          <>
            <Field label={t('ss.prov.title')}>{(id) => <Input id={id} value={c.title} placeholder="Keycloak" onChange={(e) => set({ title: e.target.value })} />}</Field>
            <Field label={t('ss.prov.issuer')}>{(id) => <Input id={id} value={c.issuer} onChange={(e) => set({ issuer: e.target.value })} />}</Field>
          </>
        )}
        <Field label={t('ss.prov.client')}>{(id) => <Input id={id} value={c.client_id} onChange={(e) => set({ client_id: e.target.value })} />}</Field>
        {apple ? (
          <>
            <Field label={t('ss.prov.team')}>{(id) => <Input id={id} value={c.team_id ?? ''} onChange={(e) => set({ team_id: e.target.value })} />}</Field>
            <Field label={t('ss.prov.key')}>{(id) => <Input id={id} value={c.key_id ?? ''} onChange={(e) => set({ key_id: e.target.value })} />}</Field>
            <Field label={t('ss.prov.pkey')} hint={view.private_key_set ? t('ss.prov.secret.set') : undefined}>
              {(id) => <Textarea id={id} rows={4} value={pkey} placeholder="-----BEGIN PRIVATE KEY-----" onChange={(e) => setPkey(e.target.value)} />}
            </Field>
          </>
        ) : (
          <SecretField label={t('ss.prov.secret')} value={secret} onChange={setSecret} isSet={view.client_secret_set} hint={t('ss.prov.secret.set')} />
        )}
        <Field label={t('ss.prov.domains')}>{(id) => <Input id={id} value={domains} placeholder="example.com" onChange={(e) => setDomains(e.target.value)} />}</Field>
        <Switch checked={c.existing_only} onChange={(v) => set({ existing_only: v })} label={t('ss.prov.existing')} disabled={!edit} />
        <Field label={t('ss.prov.role')}>{() => roleSelect(c.role_id, (v) => set({ role_id: v }), t('ss.prov.role'))}</Field>
        {view.kind === 'oidc' && (
          <>
            <Field label={t('ss.prov.groups')}>{(id) => <Input id={id} value={c.groups_claim ?? ''} placeholder="groups" onChange={(e) => set({ groups_claim: e.target.value })} />}</Field>
            <Field label={t('ss.prov.admin')}>{(id) => <Input id={id} value={c.admin_group ?? ''} onChange={(e) => set({ admin_group: e.target.value })} />}</Field>
            <Field label={t('ss.prov.adminrole')}>{() => roleSelect(c.admin_role_id, (v) => set({ admin_role_id: v }), t('ss.prov.adminrole'))}</Field>
          </>
        )}
        {view.redirect_uri && <Field label={t('ss.prov.redirect')}>{(id) => <Input id={id} value={view.redirect_uri} readOnly onFocus={(e) => e.target.select()} />}</Field>}
      </fieldset>
    </Modal>
  )
}
