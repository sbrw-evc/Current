import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, PlugZap, XCircle } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { get, post, put } from '../../api/client'
import type { CheckResult, ScopeView, UmbrellaAPI, UmbrellaAPIUpdate, UmbrellaIngest, UmbrellaIngestUpdate } from '../../api/umbrella'
import { errorText, useT, type Dict } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Chip, Field, Input, Loading, Rows, Switch } from '../../ui/ui'
import { SecretField } from '../../ui/SecretField'
import { isUrl } from './logic'
import './umbrella.css'

// Settings → Umbrella: the detector's events (ingest URL + token) and the Umbrella API connection
// (address + service-account token) used for visibility scopes and dependency proposals.

export const umbrellaStrings: Dict = {
  en: {
    'um.title': 'Umbrella',
    'um.sub': 'Events to Umbrella incidents, visibility scopes and dependency proposals for the CMDB',
    'um.on': 'On',
    'um.off': 'Off',
    'um.set': 'Set · kept in OpenBao',
    'um.unset': 'Not set',
    'um.saved': 'Settings saved',
    'um.test': 'Test',
    'um.test.ok': 'Umbrella answers',
    'um.test.fail': 'Check failed',
    'ing.title': 'Events',
    'ing.text': 'The detector posts traffic events to the "Umbrella Flow" connector of Umbrella (Connect source → Umbrella Flow).',
    'ing.enable': 'Send events to Umbrella',
    'ing.enable.hint': 'Link overloads, DDoS, anomalies and silent exporters become Umbrella incidents',
    'ing.url': 'Ingest URL',
    'ing.url.hint': 'For example https://umbrella.example.com/api/ingest/umbrella-flow',
    'ing.token': 'Ingest token',
    'ing.test.ok': 'Test event accepted',
    'ing.disabled': 'Events are not sent.',
    'api.title': 'Umbrella API',
    'api.text':
      'A service account of Umbrella (Settings → Service accounts) with the permissions integrations.flow:read and cmdb:propose. Flow asks it for the visibility scope of users whose role has "Restrict traffic to the Umbrella scope" and sends dependency proposals.',
    'api.url': 'Umbrella address',
    'api.url.hint': 'The base URL, without /api',
    'api.token': 'Service-account token',
    'api.token.hint': 'An Umbrella token (umb_…). Kept in OpenBao.',
    'api.test.hint': 'The test asks Umbrella for your own visibility scope.',
    'api.test.ok': 'Umbrella answers: your scope is {scope}',
    'scope.all': 'everything',
    'scope.unknown': 'unknown user (no access)',
    'scope.some': '{mode}: {cis} CIs, {services} services',
    'scope.you': 'Your traffic',
    'scope.restricted': 'restricted to your Umbrella scope',
    'scope.unrestricted': 'not restricted',
  },
  ru: {
    'um.title': 'Umbrella',
    'um.sub': 'События в инциденты Umbrella, области видимости и предложения зависимостей для CMDB',
    'um.on': 'Включено',
    'um.off': 'Выключено',
    'um.set': 'Задан · хранится в OpenBao',
    'um.unset': 'Не задан',
    'um.saved': 'Настройки сохранены',
    'um.test': 'Проверить',
    'um.test.ok': 'Umbrella отвечает',
    'um.test.fail': 'Проверка не прошла',
    'ing.title': 'События',
    'ing.text': 'Детектор отправляет события трафика в коннектор «Umbrella Flow» (Подключить источник → Umbrella Flow).',
    'ing.enable': 'Отправлять события в Umbrella',
    'ing.enable.hint': 'Перегрузки каналов, DDoS, аномалии и замолчавшие экспортёры становятся инцидентами Umbrella',
    'ing.url': 'Адрес приёма',
    'ing.url.hint': 'Например, https://umbrella.example.com/api/ingest/umbrella-flow',
    'ing.token': 'Токен приёма',
    'ing.test.ok': 'Тестовое событие принято',
    'ing.disabled': 'События не отправляются.',
    'api.title': 'API Umbrella',
    'api.text':
      'Сервисная учётная запись Umbrella (Настройки → Сервисные учётные записи) с правами integrations.flow:read и cmdb:propose. Через неё Flow узнаёт область видимости пользователей, чья роль ограничена областью Umbrella, и отправляет предложения зависимостей.',
    'api.url': 'Адрес Umbrella',
    'api.url.hint': 'Базовый URL, без /api',
    'api.token': 'Токен сервисной учётной записи',
    'api.token.hint': 'Токен Umbrella (umb_…). Хранится в OpenBao.',
    'api.test.hint': 'Проверка запрашивает в Umbrella вашу собственную область видимости.',
    'api.test.ok': 'Umbrella отвечает: ваша область — {scope}',
    'scope.all': 'всё',
    'scope.unknown': 'пользователь неизвестен (доступа нет)',
    'scope.some': '{mode}: КЕ {cis}, сервисов {services}',
    'scope.you': 'Ваш трафик',
    'scope.restricted': 'ограничен вашей областью в Umbrella',
    'scope.unrestricted': 'без ограничений',
  },
}

export function scopeText(t: (k: string, v?: Record<string, string | number>) => string, s: ScopeView) {
  if (!s.known) return t('scope.unknown')
  if (s.mode === 'all') return t('scope.all')
  return t('scope.some', { mode: s.mode ?? '', cis: s.cis, services: s.services })
}

export default function UmbrellaSettingsPage() {
  const t = useT(umbrellaStrings)
  const { can } = useSession()
  const canEdit = can('settings.umbrella:edit')
  const ingest = useQuery({ queryKey: ['settings', 'umbrella'], queryFn: ({ signal }) => get<UmbrellaIngest>('/api/settings/umbrella', signal) })
  const api = useQuery({ queryKey: ['settings', 'umbrella', 'api'], queryFn: ({ signal }) => get<UmbrellaAPI>('/api/settings/umbrella/api', signal) })
  const err = ingest.error ?? api.error
  return (
    <Page id="umbrella" title={t('um.title')} subtitle={t('um.sub')}>
      {err && <Banner kind="error" title={errorText(t, err).message}>{errorText(t, err).detail}</Banner>}
      {ingest.isPending || api.isPending ? (
        <Loading />
      ) : (
        <div className="settings-grid">
          {ingest.data && <IngestForm view={ingest.data} canEdit={canEdit} />}
          {api.data && <APIForm view={api.data} canEdit={canEdit} />}
        </div>
      )}
    </Page>
  )
}

function TestLine({ result, okText }: { result: CheckResult | null; okText: string }) {
  const t = useT(umbrellaStrings)
  if (!result) return null
  return (
    <div className={`test-result ${result.ok ? 'good' : 'bad'}`} role="status">
      {result.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
      <span>{result.ok ? okText : `${t('um.test.fail')}: ${result.error ?? ''}`}</span>
    </div>
  )
}

function IngestForm({ view, canEdit }: { view: UmbrellaIngest; canEdit: boolean }) {
  const t = useT(umbrellaStrings)
  const qc = useQueryClient()
  const [draft, setDraft] = useState({ enabled: view.enabled, ingest_url: view.ingest_url })
  const [token, setToken] = useState('')
  const [test, setTest] = useState<CheckResult | null>(null)
  useEffect(() => setDraft({ enabled: view.enabled, ingest_url: view.ingest_url }), [view])
  const dirty = draft.enabled !== view.enabled || draft.ingest_url !== view.ingest_url || token !== ''
  const urlOk = isUrl(draft.ingest_url)
  const body = (): UmbrellaIngestUpdate => ({ ...draft, ingest_url: draft.ingest_url.trim(), ...(token ? { token } : {}) })
  const save = useMutation({
    mutationFn: () => put<UmbrellaIngest>('/api/settings/umbrella', body()),
    onSuccess: (v) => {
      qc.setQueryData(['settings', 'umbrella'], v)
      setToken('')
      notify('ok', t('um.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const check = useMutation({
    mutationFn: () => post<CheckResult>('/api/settings/umbrella/test', body()),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, error: errorText(t, e).detail ?? errorText(t, e).message }),
  })
  const on = view.enabled && view.token_set
  return (
    <form
      className="card status-card"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
    >
      <header>
        <h2 className="card-title">{t('ing.title')}</h2>
        <Chip tone={on ? 'ok' : 'off'}>{t(on ? 'um.on' : 'um.off')}</Chip>
      </header>
      <p className="muted">{t('ing.text')}</p>
      <fieldset className="plain-fieldset stack" disabled={!canEdit}>
        <Switch checked={draft.enabled} onChange={(enabled) => setDraft({ ...draft, enabled })} label={t('ing.enable')} hint={t('ing.enable.hint')} disabled={!canEdit} />
        <AnimatePresence initial={false} mode="wait">
          {draft.enabled ? (
            <motion.div key="on" className="reveal-box" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.25 }}>
              <div className="stack">
                <Field label={t('ing.url')} hint={t('ing.url.hint')}>
                  {(id) => <Input id={id} value={draft.ingest_url} placeholder="https://umbrella.example.com/api/ingest/umbrella-flow" spellCheck={false} aria-invalid={draft.ingest_url !== '' && !urlOk} onChange={(e) => setDraft({ ...draft, ingest_url: e.target.value })} />}
                </Field>
                <SecretField label={t('ing.token')} value={token} onChange={setToken} isSet={view.token_set} />
                <TestLine result={test} okText={t('ing.test.ok')} />
              </div>
            </motion.div>
          ) : (
            <motion.div key="off" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Banner kind="info" title={t('ing.disabled')} />
            </motion.div>
          )}
        </AnimatePresence>
      </fieldset>
      {canEdit && (
        <div className="card-actions row">
          {draft.enabled && (
            <Button onClick={() => check.mutate()} busy={check.isPending} disabled={!urlOk || (!token && !view.token_set)}>
              {!check.isPending && <PlugZap size={15} />}
              {t('um.test')}
            </Button>
          )}
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!dirty || (draft.enabled && !urlOk)}>
            {t('save')}
          </Button>
        </div>
      )}
    </form>
  )
}

function APIForm({ view, canEdit }: { view: UmbrellaAPI; canEdit: boolean }) {
  const t = useT(umbrellaStrings)
  const qc = useQueryClient()
  const [url, setUrl] = useState(view.url)
  const [token, setToken] = useState('')
  const [test, setTest] = useState<CheckResult<ScopeView> | null>(null)
  useEffect(() => setUrl(view.url), [view])
  const dirty = url.trim() !== view.url || token !== ''
  const urlOk = isUrl(url)
  const body = (): UmbrellaAPIUpdate => ({ url: url.trim(), ...(token ? { token } : {}) })
  const save = useMutation({
    mutationFn: () => put<UmbrellaAPI>('/api/settings/umbrella/api', body()),
    onSuccess: (v) => {
      qc.setQueryData(['settings', 'umbrella', 'api'], v)
      void qc.invalidateQueries({ queryKey: ['umbrella', 'scope'] })
      void qc.invalidateQueries({ queryKey: ['dependencies'] })
      setToken('')
      notify('ok', t('um.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const check = useMutation({
    mutationFn: () => post<CheckResult<ScopeView>>('/api/settings/umbrella/api/test', body()),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, error: errorText(t, e).detail ?? errorText(t, e).message }),
  })
  const on = view.url !== '' && view.token_set
  return (
    <form
      className="card status-card"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
    >
      <header>
        <h2 className="card-title">{t('api.title')}</h2>
        <Chip tone={on ? 'ok' : 'off'}>{t(on ? 'um.on' : 'um.off')}</Chip>
      </header>
      <p className="muted">{t('api.text')}</p>
      <Rows align="end" rows={[[t('api.token'), t(view.token_set ? 'um.set' : 'um.unset')]]} />
      <fieldset className="plain-fieldset stack" disabled={!canEdit}>
        <Field label={t('api.url')} hint={t('api.url.hint')}>
          {(id) => <Input id={id} value={url} placeholder="https://umbrella.example.com" spellCheck={false} aria-invalid={url !== '' && !urlOk} onChange={(e) => setUrl(e.target.value)} />}
        </Field>
        <SecretField label={t('api.token')} value={token} onChange={setToken} isSet={view.token_set} hint={t('api.token.hint')} />
        <TestLine result={test} okText={test?.details ? t('api.test.ok', { scope: scopeText(t, test.details) }) : t('um.test.ok')} />
      </fieldset>
      {canEdit && (
        <div className="card-actions row">
          <span className="muted um-grow">{t('api.test.hint')}</span>
          <Button onClick={() => check.mutate()} busy={check.isPending} disabled={!urlOk || (!token && !view.token_set)}>
            {!check.isPending && <PlugZap size={15} />}
            {t('um.test')}
          </Button>
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!dirty || (url.trim() !== '' && !urlOk)}>
            {t('save')}
          </Button>
        </div>
      )}
    </form>
  )
}
