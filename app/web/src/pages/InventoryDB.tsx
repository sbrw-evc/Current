import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, PlugZap, RefreshCw, XCircle } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { Link } from 'react-router-dom'
import { get, post, put } from '../api/client'
import type { InventoryDB, InventoryDBUpdate, SyncStats, Unknown } from '../api/types'
import { formatBytes, num, relativeTime } from '../lib/format'
import { errorText, useLocale, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { useSession } from '../shell/session'
import { notify } from '../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Rows, Select, Switch } from '../ui/ui'
import { SecretField } from '../ui/SecretField'
import { DEFAULT_STATE, visualizeLink } from './visualize/state'

const strings: Dict = {
  en: {
    'inv.sub': 'Exporters, interfaces, prefixes and circuits from Inventory DB enrich every flow',
    'inv.state': 'Connection',
    'inv.state.text': 'Flow reads devices with their primary IPs, interfaces, prefixes and circuits, and classifies links by circuit terminations.',
    'inv.status': 'State',
    'inv.on': 'On',
    'inv.off': 'Off',
    'inv.token': 'API token',
    'inv.token.set': 'Set · kept in OpenBao',
    'inv.token.unset': 'Not set',
    'inv.last': 'Last sync',
    'inv.result': 'Result',
    'inv.ok': 'Success',
    'inv.failed': 'Failed',
    'inv.never': 'Not synchronised yet',
    'inv.devices': 'Devices',
    'inv.interfaces': 'Interfaces',
    'inv.prefixes': 'Prefixes',
    'inv.circuits': 'Circuits',
    'inv.sync': 'Sync now',
    'inv.synced': 'Synchronised: {devices} devices, {interfaces} interfaces',
    'inv.settings': 'Settings',
    'inv.enable': 'Use Inventory DB',
    'inv.enable.hint': 'Enrich flows with names, sites, roles, interface boundaries and providers',
    'inv.url': 'Inventory DB address',
    'inv.url.hint': 'The base URL, without /api/v1',
    'inv.token.keep': 'A token is saved. Leave empty to keep it.',
    'inv.token.hint': 'A read-only token of Inventory DB (xc-token).',
    'inv.interval': 'Sync interval',
    'inv.interval.hint': 'Changes also arrive by webhooks; the periodic sync catches the rest.',
    'inv.test': 'Test connection',
    'inv.test.ok': 'Inventory DB answers',
    'inv.test.fail': 'Connection failed',
    'inv.saved': 'Settings saved',
    'inv.disabled': 'Inventory DB is off: flows are enriched only by classifiers.',
    'unk.exporters': 'Exporters not in Inventory DB',
    'unk.exporters.text': 'They send flows but there is no device with this primary IP.',
    'unk.addresses': 'Active addresses not in IPAM',
    'unk.addresses.text': 'Seen in flows over the last 24 hours, but no IPAM address or prefix covers them.',
    'unk.address': 'Address',
    'unk.seen': 'Last flow',
    'unk.bytes': 'Traffic, 24 h',
    'unk.none': 'Everything is known',
    'unk.visualize': 'Open traffic',
    'interval.5m': 'every 5 minutes',
    'interval.15m': 'every 15 minutes',
    'interval.30m': 'every 30 minutes',
    'interval.1h': 'every hour',
    'interval.6h': 'every 6 hours',
    'interval.24h': 'once a day',
    'interval.0': 'manually only',
  },
  ru: {
    'inv.sub': 'Экспортёры, интерфейсы, префиксы и каналы из Inventory DB обогащают каждый поток',
    'inv.state': 'Подключение',
    'inv.state.text': 'Flow читает устройства с primary IP, интерфейсы, префиксы и каналы связи и по терминациям каналов классифицирует стыки.',
    'inv.status': 'Состояние',
    'inv.on': 'Включено',
    'inv.off': 'Выключено',
    'inv.token': 'API-токен',
    'inv.token.set': 'Задан · хранится в OpenBao',
    'inv.token.unset': 'Не задан',
    'inv.last': 'Последняя синхронизация',
    'inv.result': 'Результат',
    'inv.ok': 'Успешно',
    'inv.failed': 'Ошибка',
    'inv.never': 'Ещё не синхронизировались',
    'inv.devices': 'Устройства',
    'inv.interfaces': 'Интерфейсы',
    'inv.prefixes': 'Префиксы',
    'inv.circuits': 'Каналы связи',
    'inv.sync': 'Синхронизировать',
    'inv.synced': 'Синхронизировано: устройств {devices}, интерфейсов {interfaces}',
    'inv.settings': 'Настройки',
    'inv.enable': 'Использовать Inventory DB',
    'inv.enable.hint': 'Обогащать потоки именами, площадками, ролями, границами интерфейсов и провайдерами',
    'inv.url': 'Адрес Inventory DB',
    'inv.url.hint': 'Базовый URL, без /api/v1',
    'inv.token.keep': 'Токен сохранён. Оставьте поле пустым, чтобы не менять его.',
    'inv.token.hint': 'Токен Inventory DB только на чтение (xc-token).',
    'inv.interval': 'Интервал синхронизации',
    'inv.interval.hint': 'Изменения приходят и вебхуками; периодическая синхронизация подбирает остальное.',
    'inv.test': 'Проверить подключение',
    'inv.test.ok': 'Inventory DB отвечает',
    'inv.test.fail': 'Подключиться не удалось',
    'inv.saved': 'Настройки сохранены',
    'inv.disabled': 'Inventory DB выключена: потоки обогащаются только классификаторами.',
    'unk.exporters': 'Экспортёры, которых нет в Inventory DB',
    'unk.exporters.text': 'Присылают потоки, но устройства с таким primary IP нет.',
    'unk.addresses': 'Активные адреса вне IPAM',
    'unk.addresses.text': 'Встречались в потоках за 24 часа, но их не покрывает ни адрес, ни префикс IPAM.',
    'unk.address': 'Адрес',
    'unk.seen': 'Последний поток',
    'unk.bytes': 'Трафик за 24 ч',
    'unk.none': 'Все известны',
    'unk.visualize': 'Открыть трафик',
    'interval.5m': 'каждые 5 минут',
    'interval.15m': 'каждые 15 минут',
    'interval.30m': 'каждые 30 минут',
    'interval.1h': 'каждый час',
    'interval.6h': 'каждые 6 часов',
    'interval.24h': 'раз в сутки',
    'interval.0': 'только вручную',
  },
}

const INTERVALS = ['5m', '15m', '30m', '1h', '6h', '24h', '0']

export default function InventoryDBPage() {
  const t = useT(strings)
  const { can } = useSession()
  const q = useQuery({ queryKey: ['inventory-db'], queryFn: ({ signal }) => get<InventoryDB>('/api/inventory-db', signal) })
  return (
    <Page id="inventory" subtitle={t('inv.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? (
        <Loading />
      ) : q.data ? (
        <>
          <div className="settings-grid">
            <StatusCard view={q.data} canEdit={can('settings.inventory:edit')} />
            <SettingsForm view={q.data} canEdit={can('settings.inventory:edit')} />
          </div>
          <UnknownLists />
        </>
      ) : null}
    </Page>
  )
}

function StatusCard({ view, canEdit }: { view: InventoryDB; canEdit: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const sync = useMutation({
    mutationFn: () => post<{ ok: boolean; stats: SyncStats }>('/api/inventory-db/sync'),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ['inventory-db'] })
      void qc.invalidateQueries({ queryKey: ['inventory-db', 'unknown'] })
      notify('ok', t('inv.synced', { devices: r.stats.devices, interfaces: r.stats.interfaces }))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const s = view.last_sync
  const on = view.enabled && view.token_set
  return (
    <Card
      title={t('inv.state')}
      actions={<Chip tone={on ? 'ok' : 'off'}>{t(on ? 'inv.on' : 'inv.off')}</Chip>}
      className="span-side"
    >
      <p className="muted">{t('inv.state.text')}</p>
      <Rows
        align="end"
        rows={[
          [t('inv.url'), view.url ? <code key="u">{view.url}</code> : '—'],
          [t('inv.token'), t(view.token_set ? 'inv.token.set' : 'inv.token.unset')],
          [t('inv.last'), s ? <span key="l" title={formatDate(s.at, locale)}>{relativeTime(s.at, locale)}</span> : t('inv.never')],
          ...(s
            ? ([
                [t('inv.result'), <Chip key="r" tone={s.ok ? 'ok' : 'error'}>{t(s.ok ? 'inv.ok' : 'inv.failed')}</Chip>],
              ] as [string, React.ReactNode][])
            : []),
        ]}
      />
      {s && s.ok && (
        <div className="stat-tiles">
          {(['devices', 'interfaces', 'prefixes', 'circuits'] as const).map((k) => (
            <div key={k} className="stat-tile">
              <span className="stat-value">{num(s[k], locale)}</span>
              <span className="stat-label">{t(`inv.${k}`)}</span>
            </div>
          ))}
        </div>
      )}
      {s && !s.ok && s.error && <Banner kind="error" title={t('inv.failed')}>{s.error}</Banner>}
      {canEdit && on && (
        <div className="card-actions">
          <Button variant="primary" busy={sync.isPending} onClick={() => sync.mutate()}>
            {!sync.isPending && <RefreshCw size={15} />}
            {t('inv.sync')}
          </Button>
        </div>
      )}
    </Card>
  )
}

function SettingsForm({ view, canEdit }: { view: InventoryDB; canEdit: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [draft, setDraft] = useState({ enabled: view.enabled, url: view.url, interval: view.interval || '15m' })
  const [token, setToken] = useState('')
  const [test, setTest] = useState<{ ok: boolean; error?: string } | null>(null)
  useEffect(() => setDraft({ enabled: view.enabled, url: view.url, interval: view.interval || '15m' }), [view])
  const dirty = draft.enabled !== view.enabled || draft.url !== view.url || draft.interval !== view.interval || token !== ''
  const urlOk = /^https?:\/\/[^/\s]+/i.test(draft.url.trim())
  const save = useMutation({
    mutationFn: () => {
      const body: InventoryDBUpdate = { ...draft, url: draft.url.trim() }
      if (token) body.token = token
      return put<InventoryDB>('/api/inventory-db', body)
    },
    onSuccess: (v) => {
      qc.setQueryData(['inventory-db'], v)
      setToken('')
      notify('ok', t('inv.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const check = useMutation({
    mutationFn: () => post<{ ok: boolean; error?: string }>('/api/inventory-db/test'),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, error: errorText(t, e).message }),
  })
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
        <h2 className="card-title">{t('inv.settings')}</h2>
      </header>
      <fieldset className="plain-fieldset stack" disabled={!canEdit}>
        <Switch checked={draft.enabled} onChange={(enabled) => setDraft({ ...draft, enabled })} label={t('inv.enable')} hint={t('inv.enable.hint')} disabled={!canEdit} />
        <AnimatePresence initial={false} mode="wait">
          {draft.enabled ? (
            <motion.div key="on" className="reveal-box" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.25 }}>
              <div className="stack">
                <Field label={t('inv.url')} hint={t('inv.url.hint')}>
                  {(id) => <Input id={id} value={draft.url} placeholder="https://inventory.example.net" spellCheck={false} aria-invalid={draft.url !== '' && !urlOk} onChange={(e) => setDraft({ ...draft, url: e.target.value })} />}
                </Field>
                <SecretField label={t('inv.token')} value={token} onChange={setToken} isSet={view.token_set} hint={t('inv.token.hint')} />
                <Field label={t('inv.interval')} hint={t('inv.interval.hint')}>
                  {(id) => (
                    <Select id={id} value={draft.interval} onChange={(e) => setDraft({ ...draft, interval: e.target.value })}>
                      {INTERVALS.map((i) => (
                        <option key={i} value={i}>
                          {t(`interval.${i}`)}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                {test && (
                  <div className={`test-result ${test.ok ? 'good' : 'bad'}`}>
                    {test.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                    <span>{test.ok ? t('inv.test.ok') : `${t('inv.test.fail')}: ${test.error ?? ''}`}</span>
                  </div>
                )}
              </div>
            </motion.div>
          ) : (
            <motion.div key="off" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Banner kind="info" title={t('inv.disabled')} />
            </motion.div>
          )}
        </AnimatePresence>
      </fieldset>
      {canEdit && (
        <div className="card-actions row">
          {draft.enabled && (
            <Button onClick={() => check.mutate()} busy={check.isPending} disabled={!urlOk}>
              {!check.isPending && <PlugZap size={15} />}
              {t('inv.test')}
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

function UnknownLists() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const q = useQuery({ queryKey: ['inventory-db', 'unknown'], queryFn: ({ signal }) => get<Unknown>('/api/inventory-db/unknown', signal) })
  const link = (ip: string, exporter = false) =>
    visualizeLink({ ...DEFAULT_STATE, range: { preset: '24h' }, filter: exporter ? `ExporterAddress = ${ip}` : `SrcAddr = ${ip} OR DstAddr = ${ip}`, dimensions: exporter ? ['InIfName'] : ['SrcAS', 'DstAS'] })
  const vis = can('visualize:view')
  return (
    <div className="grid-2 unknown-grid">
      <Card title={t('unk.exporters')} actions={q.data && <Chip tone={q.data.exporters.length ? 'warn' : 'ok'}>{q.data.exporters.length}</Chip>} pad={false}>
        <p className="muted card-pad">{t('unk.exporters.text')}</p>
        {q.isPending ? (
          <Loading />
        ) : q.data && q.data.exporters.length ? (
          <table className="data-table compact">
            <thead>
              <tr>
                <th>{t('unk.address')}</th>
                <th>{t('unk.seen')}</th>
              </tr>
            </thead>
            <tbody>
              {q.data.exporters.map((e) => (
                <tr key={e.address}>
                  <td className="mono">{vis ? <Link to={link(e.address, true)}>{e.address}</Link> : e.address}</td>
                  <td>{relativeTime(e.last_seen, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="card-pad good-text">{t('unk.none')}</p>
        )}
      </Card>
      <Card title={t('unk.addresses')} actions={q.data && <Chip tone={q.data.addresses.length ? 'warn' : 'ok'}>{q.data.addresses.length}</Chip>} pad={false}>
        <p className="muted card-pad">{t('unk.addresses.text')}</p>
        {q.isPending ? (
          <Loading />
        ) : q.data && q.data.addresses.length ? (
          <table className="data-table compact">
            <thead>
              <tr>
                <th>{t('unk.address')}</th>
                <th className="num">{t('unk.bytes')}</th>
              </tr>
            </thead>
            <tbody>
              {q.data.addresses.map((a) => (
                <tr key={a.address}>
                  <td className="mono">{vis ? <Link to={link(a.address)}>{a.address}</Link> : a.address}</td>
                  <td className="num">{formatBytes(a.bytes, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="card-pad good-text">{t('unk.none')}</p>
        )}
      </Card>
    </div>
  )
}
