import { useMutation, useQuery } from '@tanstack/react-query'
import { LockKeyhole, PlugZap } from 'lucide-react'
import { get, post } from '../api/client'
import { num } from '../lib/format'
import { errorText, useLocale, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { useSession } from '../shell/session'
import { Banner, Button, Card, Chip, formatDate, Loading, Rows } from '../ui/ui'
import { OpenBaoMigrate } from './settings/OpenBaoMigrate'

// Settings → OpenBao, as in Umbrella (app/settings/openbao): where the secrets live and whether
// Flow can reach them. Proposed contract (not yet in docs/api.md):
//   GET  /api/settings/openbao      → OpenBaoView
//   POST /api/settings/openbao/test → {ok, error?, details?}
// Token renewal (secrets.Renewal): renewed in place, or a new AppRole sign-in for a non-renewable token.
type Renewal = { mode: 'renew' | 'login' | 'none'; logged_in_at?: string; logins: number; renewed_at?: string; renewals: number; next_at?: string; last_error?: string; last_error_at?: string }

type OpenBaoView = {
  addr: string
  mount: string
  auth: 'token' | 'approle'
  role_id?: string
  status: { ok: boolean; version?: string; token_expires?: string; renewable?: boolean; policies?: string[]; error?: string; renewal?: Renewal }
  secrets?: number
}

const strings: Dict = {
  en: {
    'ob.sub': 'Every password and token of Flow is kept in OpenBao; nothing secret is stored on disk or shown in the interface',
    'ob.current': 'Current connection',
    'ob.current.text': 'Flow reads its secrets from this KV v2 mount and caches them for 30 seconds.',
    'ob.state.ok': 'Connected',
    'ob.state.fail': 'Unavailable',
    'ob.addr': 'Address',
    'ob.version': 'OpenBao version',
    'ob.mount': 'KV mount',
    'ob.auth': 'Authentication',
    'ob.auth.approle': 'AppRole',
    'ob.auth.token': 'Token',
    'ob.role': 'Role ID',
    'ob.expires': 'Token expires',
    'ob.renewable': 'Renewable',
    'ob.policies': 'Policies',
    'ob.secrets': 'Secrets in the mount',
    'ob.renewal': 'Token renewal',
    'ob.renewal.renew': 'Renewed before expiry',
    'ob.renewal.login': 'AppRole signs in again before expiry',
    'ob.renewal.none': 'Token without expiry',
    'ob.renewed': 'Last renewal',
    'ob.next': 'Next check',
    'ob.login': 'Last sign-in',
    'ob.renewal.error': 'Last renewal failed',
    'ob.test': 'Check',
    'ob.test.ok': 'OpenBao answers, the mount is readable and writable',
    'ob.test.fail': 'Check failed',
    'ob.what': 'What is kept there',
    'ob.what.text': 'PostgreSQL and ClickHouse passwords, the Inventory DB token, the Umbrella ingest token, the NATS credentials. Forms show such fields as "set · kept in OpenBao" with a Replace button.',
    'ob.change': 'The connection to OpenBao itself is set by the setup wizard and the AppRole file of the container (FLOW_SETUP_DEFAULTS_OPENBAO_*), or changed by moving the secrets to another OpenBao.',
  },
  ru: {
    'ob.sub': 'Все пароли и токены Flow хранятся в OpenBao; на диске и в интерфейсе секретов нет',
    'ob.current': 'Текущее подключение',
    'ob.current.text': 'Flow читает секреты из этого хранилища KV v2 и кеширует их на 30 секунд.',
    'ob.state.ok': 'Подключено',
    'ob.state.fail': 'Недоступно',
    'ob.addr': 'Адрес',
    'ob.version': 'Версия OpenBao',
    'ob.mount': 'Хранилище KV',
    'ob.auth': 'Аутентификация',
    'ob.auth.approle': 'AppRole',
    'ob.auth.token': 'Токен',
    'ob.role': 'Role ID',
    'ob.expires': 'Токен действует до',
    'ob.renewable': 'Продлевается',
    'ob.policies': 'Политики',
    'ob.secrets': 'Секретов в хранилище',
    'ob.renewal': 'Продление токена',
    'ob.renewal.renew': 'Продлевается до истечения',
    'ob.renewal.login': 'AppRole входит заново до истечения',
    'ob.renewal.none': 'Токен без срока действия',
    'ob.renewed': 'Последнее продление',
    'ob.next': 'Следующая проверка',
    'ob.login': 'Последний вход',
    'ob.renewal.error': 'Последнее продление не удалось',
    'ob.test': 'Проверить',
    'ob.test.ok': 'OpenBao отвечает, хранилище доступно на чтение и запись',
    'ob.test.fail': 'Проверка не прошла',
    'ob.what': 'Что там хранится',
    'ob.what.text': 'Пароли PostgreSQL и ClickHouse, токен Inventory DB, токен приёма Umbrella, учётные данные NATS. В формах такие поля показываются как «задан · хранится в OpenBao» с кнопкой «Заменить».',
    'ob.change': 'Само подключение к OpenBao задаётся мастером настройки и файлом AppRole контейнера (FLOW_SETUP_DEFAULTS_OPENBAO_*) или меняется переносом секретов в другой OpenBao.',
  },
}

export default function OpenBaoPage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const q = useQuery({ queryKey: ['openbao'], queryFn: ({ signal }) => get<OpenBaoView>('/api/settings/openbao', signal) })
  const test = useMutation({ mutationFn: () => post<{ ok: boolean; error?: string }>('/api/settings/openbao/test') })
  const v = q.data
  return (
    <Page id="openbao" subtitle={t('ob.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? (
        <Loading />
      ) : v ? (
        <div className="settings-grid">
          <Card title={t('ob.current')} actions={<Chip tone={v.status.ok ? 'ok' : 'error'}>{t(v.status.ok ? 'ob.state.ok' : 'ob.state.fail')}</Chip>}>
            <p className="muted">{t('ob.current.text')}</p>
            <Rows
              align="end"
              rows={[
                [t('ob.addr'), <code key="a">{v.addr}</code>],
                [t('ob.version'), v.status.version],
                [t('ob.mount'), <code key="m">{v.mount}</code>],
                [t('ob.auth'), t(`ob.auth.${v.auth}`)],
                ...(v.auth === 'approle' && v.role_id ? ([[t('ob.role'), <code key="r">{v.role_id}</code>]] as [string, React.ReactNode][]) : []),
                [t('ob.expires'), v.status.token_expires ? formatDate(v.status.token_expires, locale) : '—'],
                [t('ob.renewable'), v.status.renewable === undefined ? '—' : t(v.status.renewable ? 'yes' : 'no')],
                [t('ob.policies'), v.status.policies?.join(', ')],
                [t('ob.secrets'), v.secrets === undefined ? '—' : num(v.secrets, locale)],
                ...(v.status.renewal
                  ? ([
                      [t('ob.renewal'), t(`ob.renewal.${v.status.renewal.mode}`)],
                      [t('ob.login'), v.status.renewal.logged_in_at ? formatDate(v.status.renewal.logged_in_at, locale) : '—'],
                      [t('ob.renewed'), v.status.renewal.renewed_at ? `${formatDate(v.status.renewal.renewed_at, locale)} (${num(v.status.renewal.renewals, locale)})` : '—'],
                      [t('ob.next'), v.status.renewal.next_at ? formatDate(v.status.renewal.next_at, locale) : '—'],
                    ] as [string, React.ReactNode][])
                  : []),
              ]}
            />
            {v.status.error && <Banner kind="error" title={t('ob.state.fail')}>{v.status.error}</Banner>}
            {v.status.renewal?.last_error && <Banner kind="warn" title={t('ob.renewal.error')}>{v.status.renewal.last_error}</Banner>}
            {test.data && (
              <Banner kind={test.data.ok ? 'ok' : 'error'} title={test.data.ok ? t('ob.test.ok') : t('ob.test.fail')}>
                {test.data.error}
              </Banner>
            )}
            {test.error && <Banner kind="error" title={errorText(t, test.error).message} />}
            {can('settings.openbao:test') && (
              <div className="card-actions">
                <Button variant="primary" busy={test.isPending} onClick={() => test.mutate()}>
                  {!test.isPending && <PlugZap size={15} />}
                  {t('ob.test')}
                </Button>
              </div>
            )}
          </Card>
          <Card title={t('ob.what')} actions={<LockKeyhole size={18} className="muted" />}>
            <p>{t('ob.what.text')}</p>
            <p className="hint">{t('ob.change')}</p>
          </Card>
          {can('settings.openbao:migrate') && <OpenBaoMigrate />}
        </div>
      ) : null}
    </Page>
  )
}
