import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Plus, PlugZap, Trash2, XCircle } from 'lucide-react'
import { get, post, put } from '../../api/client'
import { errorText, useT, type Dict } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { SecretField } from '../../ui/SecretField'
import { Banner, Button, Card, Chip, Field, Input, Loading, Rows, Select, Switch } from '../../ui/ui'
import { CLOUDS, defaultRedirect, isGuid, validTenant, type EntraGroupRole, type EntraInput, type EntraTest, type EntraView } from './EntraModel'

// Settings → Entra ID: sign-in with Microsoft Entra ID (OpenID Connect, authorization code + PKCE),
// as in Umbrella (app/settings/directory/EntraSettings). The client secret goes to OpenBao.

const strings: Dict = {
  en: {
    'en.sub': 'Sign-in with Microsoft accounts of your tenant; users are created on their first sign-in',
    'en.state': 'State',
    'en.on': 'On',
    'en.off': 'Off',
    'en.users': 'Users signed in through Entra ID',
    'en.secret': 'Client secret',
    'en.secret.set': 'Set · kept in OpenBao',
    'en.secret.unset': 'Not set',
    'en.register': 'Register the application',
    'en.register.text': 'In Entra ID → App registrations create a web application with this redirect URI, add a client secret, and either add the groups claim to the ID token or grant the delegated Microsoft Graph permission GroupMember.Read.All.',
    'en.settings': 'Settings',
    'en.enable': 'Allow sign-in with Microsoft Entra ID',
    'en.enable.hint': 'A "Sign in with Microsoft" button appears on the sign-in page',
    'en.cloud': 'Microsoft cloud',
    'en.cloud.global': 'Global (login.microsoftonline.com)',
    'en.cloud.usgov': 'US Government',
    'en.cloud.china': 'China (21Vianet)',
    'en.tenant': 'Tenant',
    'en.tenant.hint': 'Directory (tenant) ID or a domain such as contoso.onmicrosoft.com',
    'en.client': 'Application (client) ID',
    'en.redirect': 'Redirect URI',
    'en.redirect.hint': 'Must match the URI registered in Entra ID',
    'en.secret.hint': 'A client secret of the application.',
    'en.default': 'Default role',
    'en.default.hint': 'For users in none of the groups below',
    'en.default.none': 'No access',
    'en.groups': 'Group → role',
    'en.groups.hint': 'The first group the user belongs to (directly or through nested groups) gives the role.',
    'en.group': 'Group object ID',
    'en.group.add': 'Add a group',
    'en.test': 'Check',
    'en.test.ok': 'The tenant answers, the application ID and the secret are valid',
    'en.test.fail': 'Check failed',
    'en.saved': 'Settings saved',
    'en.roles.error': 'The list of roles is not available.',
  },
  ru: {
    'en.sub': 'Вход учётными записями Microsoft вашего тенанта; пользователи создаются при первом входе',
    'en.state': 'Состояние',
    'en.on': 'Включено',
    'en.off': 'Выключено',
    'en.users': 'Пользователей, входивших через Entra ID',
    'en.secret': 'Секрет клиента',
    'en.secret.set': 'Задан · хранится в OpenBao',
    'en.secret.unset': 'Не задан',
    'en.register': 'Регистрация приложения',
    'en.register.text': 'В Entra ID → App registrations создайте веб-приложение с этим redirect URI, добавьте секрет клиента и либо включите claim groups в ID-токене, либо выдайте делегированное право Microsoft Graph GroupMember.Read.All.',
    'en.settings': 'Настройки',
    'en.enable': 'Разрешить вход через Microsoft Entra ID',
    'en.enable.hint': 'На странице входа появится кнопка «Войти через Microsoft»',
    'en.cloud': 'Облако Microsoft',
    'en.cloud.global': 'Глобальное (login.microsoftonline.com)',
    'en.cloud.usgov': 'US Government',
    'en.cloud.china': 'Китай (21Vianet)',
    'en.tenant': 'Тенант',
    'en.tenant.hint': 'Directory (tenant) ID или домен, например contoso.onmicrosoft.com',
    'en.client': 'Application (client) ID',
    'en.redirect': 'Redirect URI',
    'en.redirect.hint': 'Должен совпадать с URI, зарегистрированным в Entra ID',
    'en.secret.hint': 'Секрет клиента приложения.',
    'en.default': 'Роль по умолчанию',
    'en.default.hint': 'Для пользователей, не входящих ни в одну группу ниже',
    'en.default.none': 'Нет доступа',
    'en.groups': 'Группа → роль',
    'en.groups.hint': 'Роль даёт первая группа, в которую пользователь входит (напрямую или через вложенные группы).',
    'en.group': 'Object ID группы',
    'en.group.add': 'Добавить группу',
    'en.test': 'Проверить',
    'en.test.ok': 'Тенант отвечает, ID приложения и секрет верны',
    'en.test.fail': 'Проверка не прошла',
    'en.saved': 'Настройки сохранены',
    'en.roles.error': 'Список ролей недоступен.',
  },
}

type Role = { id: number; name: string }

function toInput(v: EntraView): EntraInput {
  return {
    enabled: v.enabled,
    cloud: v.cloud || 'global',
    tenant_id: v.tenant_id,
    client_id: v.client_id,
    redirect_url: v.redirect_url || defaultRedirect(window.location.origin),
    default_role_id: v.default_role_id,
    group_roles: v.group_roles.map(({ group_id, role_id }) => ({ group_id, role_id })),
  }
}

export default function EntraPage() {
  const t = useT(strings)
  const { can } = useSession()
  const q = useQuery({ queryKey: ['entra'], queryFn: ({ signal }) => get<EntraView>('/api/settings/entra', signal) })
  const roles = useQuery({ queryKey: ['roles'], queryFn: ({ signal }) => get<{ results: Role[] }>('/api/roles', signal) })
  return (
    <Page id="entra" subtitle={t('en.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? (
        <Loading />
      ) : q.data ? (
        <div className="settings-grid">
          <Card title={t('en.state')} actions={<Chip tone={q.data.enabled ? 'ok' : 'off'}>{t(q.data.enabled ? 'en.on' : 'en.off')}</Chip>} className="span-side">
            <Rows
              align="end"
              rows={[
                [t('en.tenant'), q.data.tenant_id ? <code key="t">{q.data.tenant_id}</code> : '—'],
                [t('en.client'), q.data.client_id ? <code key="c">{q.data.client_id}</code> : '—'],
                [t('en.secret'), t(q.data.client_secret_set ? 'en.secret.set' : 'en.secret.unset')],
                [t('en.users'), String(q.data.users)],
              ]}
            />
            <h3 className="card-title">{t('en.register')}</h3>
            <p className="muted">{t('en.register.text')}</p>
            <pre className="code-block">{q.data.redirect_url || defaultRedirect(window.location.origin)}</pre>
          </Card>
          <SettingsForm view={q.data} roles={roles.data?.results ?? []} rolesError={!!roles.error} canEdit={can('users:edit')} />
        </div>
      ) : null}
    </Page>
  )
}

function SettingsForm({ view, roles, rolesError, canEdit }: { view: EntraView; roles: Role[]; rolesError: boolean; canEdit: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [draft, setDraft] = useState<EntraInput>(() => toInput(view))
  const [secret, setSecret] = useState('')
  const [test, setTest] = useState<EntraTest | null>(null)
  useEffect(() => setDraft(toInput(view)), [view])
  const body = (): EntraInput => ({ ...draft, ...(secret ? { client_secret: secret } : {}) })
  const groupsOk = draft.group_roles.every((g) => isGuid(g.group_id) && g.role_id > 0)
  const formOk = !draft.enabled || (validTenant(draft.tenant_id) && isGuid(draft.client_id) && /^https?:\/\/[^/\s]+\/api\/auth\/entra\/callback$/.test(draft.redirect_url.trim()) && groupsOk && (view.client_secret_set || secret !== ''))
  const save = useMutation({
    mutationFn: () => put<EntraView>('/api/settings/entra', body()),
    onSuccess: (v) => {
      qc.setQueryData(['entra'], v)
      setSecret('')
      notify('ok', t('en.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const check = useMutation({
    mutationFn: () => post<EntraTest>('/api/settings/entra/test', body()),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, probe: { credentials: false }, error: errorText(t, e).detail ?? errorText(t, e).message }),
  })
  const setGroup = (i: number, g: Partial<EntraGroupRole>) => setDraft({ ...draft, group_roles: draft.group_roles.map((x, j) => (j === i ? { ...x, ...g } : x)) })
  return (
    <form
      className="card status-card"
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
      noValidate
    >
      <header>
        <h2 className="card-title">{t('en.settings')}</h2>
      </header>
      <fieldset className="plain-fieldset stack" disabled={!canEdit}>
        <Switch checked={draft.enabled} onChange={(enabled) => setDraft({ ...draft, enabled })} label={t('en.enable')} hint={t('en.enable.hint')} disabled={!canEdit} />
        <Field label={t('en.cloud')}>
          {(id) => (
            <Select id={id} value={draft.cloud} onChange={(e) => setDraft({ ...draft, cloud: e.target.value })}>
              {CLOUDS.map((c) => (
                <option key={c} value={c}>
                  {t(`en.cloud.${c}`)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('en.tenant')} hint={t('en.tenant.hint')}>
          {(id) => <Input id={id} value={draft.tenant_id} spellCheck={false} aria-invalid={draft.tenant_id !== '' && !validTenant(draft.tenant_id)} onChange={(e) => setDraft({ ...draft, tenant_id: e.target.value })} />}
        </Field>
        <Field label={t('en.client')}>
          {(id) => <Input id={id} value={draft.client_id} spellCheck={false} placeholder="00000000-0000-0000-0000-000000000000" aria-invalid={draft.client_id !== '' && !isGuid(draft.client_id)} onChange={(e) => setDraft({ ...draft, client_id: e.target.value })} />}
        </Field>
        <SecretField label={t('en.secret')} value={secret} onChange={setSecret} isSet={view.client_secret_set} hint={t('en.secret.hint')} />
        <Field label={t('en.redirect')} hint={t('en.redirect.hint')}>
          {(id) => <Input id={id} value={draft.redirect_url} spellCheck={false} onChange={(e) => setDraft({ ...draft, redirect_url: e.target.value })} />}
        </Field>
        {rolesError && <Banner kind="warn" title={t('en.roles.error')} />}
        <Field label={t('en.default')} hint={t('en.default.hint')}>
          {(id) => (
            <Select id={id} value={String(draft.default_role_id)} onChange={(e) => setDraft({ ...draft, default_role_id: Number(e.target.value) })}>
              <option value="0">{t('en.default.none')}</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div className="field">
          <label>{t('en.groups')}</label>
          <div className="stack">
            {draft.group_roles.map((g, i) => (
              <div key={i} className="row">
                <Input aria-label={t('en.group')} placeholder={t('en.group')} value={g.group_id} spellCheck={false} aria-invalid={g.group_id !== '' && !isGuid(g.group_id)} onChange={(e) => setGroup(i, { group_id: e.target.value })} />
                <Select aria-label={t('en.default')} value={String(g.role_id)} onChange={(e) => setGroup(i, { role_id: Number(e.target.value) })}>
                  <option value="0">—</option>
                  {roles.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </Select>
                <button type="button" className="icon-btn danger-icon" aria-label="×" onClick={() => setDraft({ ...draft, group_roles: draft.group_roles.filter((_, j) => j !== i) })}>
                  <Trash2 size={16} />
                </button>
              </div>
            ))}
            <div>
              <Button size="sm" onClick={() => setDraft({ ...draft, group_roles: [...draft.group_roles, { group_id: '', role_id: roles[0]?.id ?? 0 }] })}>
                <Plus size={14} /> {t('en.group.add')}
              </Button>
            </div>
          </div>
          <div className="hint">{t('en.groups.hint')}</div>
        </div>
        {test && (
          <div className={`test-result ${test.ok ? 'good' : 'bad'}`}>
            {test.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            <span>{test.ok ? t('en.test.ok') : `${t('en.test.fail')}: ${test.error ?? ''}`}</span>
          </div>
        )}
      </fieldset>
      {canEdit && (
        <div className="card-actions row">
          <Button onClick={() => check.mutate()} busy={check.isPending} disabled={!validTenant(draft.tenant_id) || !isGuid(draft.client_id)}>
            {!check.isPending && <PlugZap size={15} />}
            {t('en.test')}
          </Button>
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!formOk}>
            {t('save')}
          </Button>
        </div>
      )}
    </form>
  )
}
