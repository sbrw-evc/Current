import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Database, Gauge, ListOrdered, Save, SearchCheck } from 'lucide-react'
import { get, put } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Field, Loading, Segmented, Stepper, Switch, Textarea, Tile } from '../../ui/ui'
import { hitRatio, parseServers, validServer, type RdnsScope, type RdnsSettings, type RdnsView } from './RdnsModel'

// Settings → Reverse DNS (docs/api.md, "Reverse DNS"): asynchronous PTR lookups by the enricher for
// addresses that Inventory DB does not name; never blocks the pipeline.

const strings: Dict = {
  en: {
    'rdns.sub': 'PTR names for addresses without an Inventory DB host name, resolved in the background into SrcHostPTR / DstHostPTR',
    'rdns.settings': 'Resolution',
    'rdns.enabled': 'Resolve addresses to names',
    'rdns.enabled.hint': 'Lookups never delay flows: the first flows of an address get an empty name, later ones the cached name.',
    'rdns.servers': 'DNS servers',
    'rdns.servers.hint': 'One "address" or "host:port" per line, queried in turn. Empty: the system resolver.',
    'rdns.scope': 'Addresses',
    'rdns.scope.all': 'All',
    'rdns.scope.private': 'Private',
    'rdns.scope.public': 'Public',
    'rdns.workers': 'Parallel lookups',
    'rdns.rate': 'Rate limit',
    'rdns.rate.unit': 'queries/s',
    'rdns.ttl.pos': 'Keep found names',
    'rdns.ttl.neg': 'Keep failures',
    'rdns.sec': 's',
    'rdns.ms': 'ms',
    'rdns.timeout': 'Query timeout',
    'rdns.cache': 'Cache size',
    'rdns.queue': 'Queue size',
    'rdns.advanced': 'Limits',
    'rdns.save': 'Save',
    'rdns.saved': 'Reverse DNS settings saved',
    'rdns.err.server': 'Not a DNS server address: {v}',
    'rdns.stats': 'Resolver',
    'rdns.stats.none': 'The resolver runs in the enricher; statistics appear here when it runs in this process.',
    'rdns.cached': 'Cached names',
    'rdns.hit': 'Cache hits',
    'rdns.queued': 'Queued',
    'rdns.found': 'Found / not found / errors',
    'rdns.dropped': 'Dropped (queue full)',
    'rdns.how': 'Inventory DB names win: only addresses Inventory DB does not know are resolved. Filter with SrcHostPTR LIKE \'%.example.net\'.',
  },
  ru: {
    'rdns.sub': 'PTR-имена для адресов без имени в Inventory DB, в фоне записываются в SrcHostPTR / DstHostPTR',
    'rdns.settings': 'Разрешение имён',
    'rdns.enabled': 'Разрешать адреса в имена',
    'rdns.enabled.hint': 'Запросы не задерживают потоки: первые потоки адреса получают пустое имя, следующие — имя из кэша.',
    'rdns.servers': 'DNS-серверы',
    'rdns.servers.hint': 'По одному «адрес» или «хост:порт» на строку, опрашиваются по очереди. Пусто — системный резолвер.',
    'rdns.scope': 'Адреса',
    'rdns.scope.all': 'Все',
    'rdns.scope.private': 'Частные',
    'rdns.scope.public': 'Публичные',
    'rdns.workers': 'Параллельных запросов',
    'rdns.rate': 'Ограничение частоты',
    'rdns.rate.unit': 'запросов/с',
    'rdns.ttl.pos': 'Хранить найденные имена',
    'rdns.ttl.neg': 'Хранить неудачи',
    'rdns.sec': 'с',
    'rdns.ms': 'мс',
    'rdns.timeout': 'Тайм-аут запроса',
    'rdns.cache': 'Размер кэша',
    'rdns.queue': 'Размер очереди',
    'rdns.advanced': 'Ограничения',
    'rdns.save': 'Сохранить',
    'rdns.saved': 'Настройки обратного DNS сохранены',
    'rdns.err.server': 'Не адрес DNS-сервера: {v}',
    'rdns.stats': 'Резолвер',
    'rdns.stats.none': 'Резолвер работает в обогатителе; статистика появится здесь, когда он работает в этом процессе.',
    'rdns.cached': 'Имён в кэше',
    'rdns.hit': 'Попаданий в кэш',
    'rdns.queued': 'В очереди',
    'rdns.found': 'Найдено / не найдено / ошибок',
    'rdns.dropped': 'Отброшено (очередь полна)',
    'rdns.how': 'Имена из Inventory DB важнее: разрешаются только адреса, которых нет в Inventory DB. Фильтр: SrcHostPTR LIKE \'%.example.net\'.',
  },
}

export default function RdnsPage() {
  const t = useT(strings)
  const q = useQuery({ queryKey: ['rdns'], queryFn: ({ signal }) => get<RdnsView>('/api/settings/rdns', signal), refetchInterval: 30_000 })
  return (
    <Page id="rdns" subtitle={t('rdns.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? <Loading /> : q.data ? <RdnsForm view={q.data} key={JSON.stringify(q.data.settings)} /> : null}
    </Page>
  )
}

function RdnsForm({ view }: { view: RdnsView }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const qc = useQueryClient()
  const editable = can('settings.rdns:edit')
  const [draft, setDraft] = useState<RdnsSettings>(view.settings)
  const [servers, setServers] = useState((view.settings.servers ?? []).join('\n'))
  const list = parseServers(servers)
  const bad = list.filter((s) => !validServer(s))
  const set = (p: Partial<RdnsSettings>) => setDraft({ ...draft, ...p })
  const save = useMutation({
    mutationFn: () => put<RdnsView>('/api/settings/rdns', { ...draft, servers: list }),
    onSuccess: (v) => {
      qc.setQueryData(['rdns'], v)
      notify('ok', t('rdns.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const st = view.stats
  const ratio = hitRatio(st)
  const step = (key: keyof RdnsSettings, label: string, min: number, max: number, suffix?: string) => (
    <Field label={label}>{(id) => <Stepper id={id} value={draft[key] as number} min={min} max={max} suffix={suffix} onChange={(v) => set({ [key]: v } as Partial<RdnsSettings>)} />}</Field>
  )
  return (
    <>
      {st && (
        <div className="tiles">
          <Tile label={t('rdns.cached')} icon={<Database size={16} />} value={num(st.cached, locale)} />
          <Tile label={t('rdns.hit')} icon={<Gauge size={16} />} value={ratio === null ? '—' : `${Math.round(ratio * 100)} %`} />
          <Tile label={t('rdns.queued')} icon={<ListOrdered size={16} />} value={num(st.queued, locale)} sub={`${t('rdns.dropped')}: ${num(st.dropped, locale)}`} tone={st.dropped > 0 ? 'warn' : undefined} />
          <Tile label={t('rdns.found')} icon={<SearchCheck size={16} />} value={`${num(st.found, locale)} / ${num(st.not_found, locale)} / ${num(st.errors, locale)}`} tone={st.errors > 0 ? 'warn' : undefined} />
        </div>
      )}
      <div className="settings-grid">
        <Card title={t('rdns.settings')}>
          <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })} label={t('rdns.enabled')} hint={t('rdns.enabled.hint')} disabled={!editable} />
          <Field label={t('rdns.servers')} hint={t('rdns.servers.hint')}>
            {(id) => <Textarea id={id} rows={3} value={servers} disabled={!editable} onChange={(e) => setServers(e.target.value)} placeholder={'192.0.2.53\ndns.example:5353'} />}
          </Field>
          {bad.length > 0 && <Banner kind="warn" title={t('rdns.err.server', { v: bad.join(', ') })} />}
          <Field label={t('rdns.scope')}>
            {() => (
              <Segmented<RdnsScope>
                label={t('rdns.scope')}
                value={draft.scope}
                options={(['all', 'private', 'public'] as const).map((s) => ({ value: s, label: t(`rdns.scope.${s}`) }))}
                onChange={(v) => editable && set({ scope: v })}
              />
            )}
          </Field>
          <h3>{t('rdns.advanced')}</h3>
          {step('workers', t('rdns.workers'), 1, 256)}
          {step('rate_limit', t('rdns.rate'), 1, 100000, t('rdns.rate.unit'))}
          {step('positive_ttl', t('rdns.ttl.pos'), 60, 7 * 86400, t('rdns.sec'))}
          {step('negative_ttl', t('rdns.ttl.neg'), 10, 86400, t('rdns.sec'))}
          {step('timeout_ms', t('rdns.timeout'), 100, 30000, t('rdns.ms'))}
          {step('cache_size', t('rdns.cache'), 1000, 10000000)}
          {step('queue_size', t('rdns.queue'), 100, 1000000)}
          {editable && (
            <div className="card-actions">
              <Button variant="primary" busy={save.isPending} disabled={bad.length > 0} onClick={() => save.mutate()}>
                {!save.isPending && <Save size={15} />}
                {t('rdns.save')}
              </Button>
            </div>
          )}
        </Card>
        <Card title={t('rdns.stats')}>
          {!st && <p className="muted">{t('rdns.stats.none')}</p>}
          <p className="hint">{t('rdns.how')}</p>
        </Card>
      </div>
    </>
  )
}
