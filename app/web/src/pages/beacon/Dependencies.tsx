import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Eye, Play, Search } from 'lucide-react'
import { get, post, put } from '../../api/client'
import type { Dependencies, DependencyRun, DependencyRunReply, DependencySettings, Proposal } from '../../api/beacon'
import { formatBytes, num, relativeTime } from '../../lib/format'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Rows, Select, Stepper, Switch, type Tone } from '../../ui/ui'
import { endLabel, filterProposals, runState, serviceLabel, sortProposals, type SortKey } from './logic'
import './beacon.css'

// Dependencies: steady CI ↔ CI traffic found by Current and proposed to Beacon's CMDB as
// "depends on" relations (docs/integrations.md §3.3).

const strings: Dict = {
  en: {
    'dep.title': 'Dependencies',
    'dep.sub': 'Steady CI ↔ CI traffic of the last 7 days, proposed to Beacon’s CMDB as “depends on”',
    'dep.run': 'Run and send',
    'dep.preview': 'Preview',
    'dep.sent': 'Sent to Beacon: {sent} proposals ({accepted} new, {updated} updated, {ignored} ignored)',
    'dep.previewed': 'Found {n} dependencies (not sent)',
    'dep.failed': 'Discovery failed',
    'dep.not_configured': 'The Beacon API connection is not configured: proposals cannot be sent. Settings → Beacon.',
    'dep.unavailable': 'Discovery needs ClickHouse in this process.',
    'dep.last': 'Last run',
    'dep.never': 'Never run',
    'dep.next': 'Next scheduled run',
    'dep.schedule.off': 'Daily run is off',
    'dep.state.running': 'Running',
    'dep.state.ok': 'Sent',
    'dep.state.failed': 'Failed',
    'dep.state.preview': 'Preview',
    'dep.trigger.schedule': 'schedule',
    'dep.trigger.manual': 'manual',
    'dep.pairs': 'Pairs found',
    'dep.sent.n': 'Sent',
    'dep.accepted': 'New',
    'dep.updated': 'Updated',
    'dep.found': 'Proposals',
    'dep.search': 'Filter by name, address, port, application',
    'dep.from': 'Depends',
    'dep.to': 'On',
    'dep.service': 'Service',
    'dep.bytes': 'Traffic, 7 d',
    'dep.flows': 'Flows',
    'dep.days': 'Days',
    'dep.seen': 'Last seen',
    'dep.open': 'Open in Visualize',
    'dep.none': 'No steady CI ↔ CI traffic above the thresholds. Both ends need a Ledger reference (SrcCI / DstCI).',
    'dep.sort': 'Sort',
    'dep.sort.bytes': 'by traffic',
    'dep.sort.flows': 'by flows',
    'dep.sort.days': 'by days seen',
    'dep.sort.from': 'by client',
    'dep.sort.to': 'by server',
    'dep.runs': 'Runs',
    'dep.started': 'Started',
    'dep.by': 'By',
    'dep.result': 'Result',
    'dep.settings': 'Thresholds and schedule',
    'dep.enabled': 'Run daily and send to Beacon',
    'dep.enabled.hint': 'Beacon refreshes the proposals it already has; proposals not refreshed for 14 days expire there.',
    'dep.hour': 'Daily run after (UTC hour)',
    'dep.min_flows': 'Minimum flows in 7 days',
    'dep.min_days': 'Minimum days with traffic',
    'dep.max': 'Maximum proposals',
    'dep.saved': 'Settings saved',
    'dep.running': 'A run is in progress…',
  },
  ru: {
    'dep.title': 'Зависимости',
    'dep.sub': 'Устойчивый трафик КЕ ↔ КЕ за 7 дней, предлагаемый в CMDB Beacon как «зависит от»',
    'dep.run': 'Запустить и отправить',
    'dep.preview': 'Предпросмотр',
    'dep.sent': 'Отправлено в Beacon: {sent} предложений (новых {accepted}, обновлено {updated}, пропущено {ignored})',
    'dep.previewed': 'Найдено зависимостей: {n} (не отправлены)',
    'dep.failed': 'Поиск не удался',
    'dep.not_configured': 'Подключение к API Beacon не настроено: предложения не отправить. Настройки → Beacon.',
    'dep.unavailable': 'Для поиска нужен ClickHouse в этом процессе.',
    'dep.last': 'Последний запуск',
    'dep.never': 'Ещё не запускался',
    'dep.next': 'Следующий запуск по расписанию',
    'dep.schedule.off': 'Ежедневный запуск выключен',
    'dep.state.running': 'Выполняется',
    'dep.state.ok': 'Отправлено',
    'dep.state.failed': 'Ошибка',
    'dep.state.preview': 'Предпросмотр',
    'dep.trigger.schedule': 'по расписанию',
    'dep.trigger.manual': 'вручную',
    'dep.pairs': 'Найдено пар',
    'dep.sent.n': 'Отправлено',
    'dep.accepted': 'Новых',
    'dep.updated': 'Обновлено',
    'dep.found': 'Предложения',
    'dep.search': 'Фильтр по имени, адресу, порту, приложению',
    'dep.from': 'Зависит',
    'dep.to': 'От',
    'dep.service': 'Сервис',
    'dep.bytes': 'Трафик за 7 дн.',
    'dep.flows': 'Потоков',
    'dep.days': 'Дней',
    'dep.seen': 'Последний раз',
    'dep.open': 'Открыть в визуализации',
    'dep.none': 'Нет устойчивого трафика КЕ ↔ КЕ выше порогов. У обоих концов должна быть ссылка Ledger (SrcCI / DstCI).',
    'dep.sort': 'Сортировка',
    'dep.sort.bytes': 'по трафику',
    'dep.sort.flows': 'по потокам',
    'dep.sort.days': 'по дням',
    'dep.sort.from': 'по клиенту',
    'dep.sort.to': 'по серверу',
    'dep.runs': 'Запуски',
    'dep.started': 'Начало',
    'dep.by': 'Кто',
    'dep.result': 'Результат',
    'dep.settings': 'Пороги и расписание',
    'dep.enabled': 'Запускать ежедневно и отправлять в Beacon',
    'dep.enabled.hint': 'Beacon обновляет уже известные предложения; не обновлявшиеся 14 дней там истекают.',
    'dep.hour': 'Ежедневный запуск после (час UTC)',
    'dep.min_flows': 'Минимум потоков за 7 дней',
    'dep.min_days': 'Минимум дней с трафиком',
    'dep.max': 'Максимум предложений',
    'dep.saved': 'Настройки сохранены',
    'dep.running': 'Идёт запуск…',
  },
}

const STATE_TONE: Record<ReturnType<typeof runState>, Tone> = { running: 'info', ok: 'ok', failed: 'error', preview: 'low' }
const SORTS: SortKey[] = ['bytes', 'flows', 'days', 'from', 'to']

export default function DependenciesPage() {
  const t = useT(strings)
  const { can } = useSession()
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['dependencies'],
    queryFn: ({ signal }) => get<Dependencies>('/api/dependencies', signal),
    refetchInterval: (query) => (query.state.data?.running ? 5000 : false),
  })
  // A fresh preview replaces the stored proposals until the next refetch.
  const [preview, setPreview] = useState<Proposal[] | null>(null)
  const run = useMutation({
    mutationFn: (dryRun: boolean) => post<DependencyRunReply>('/api/dependencies/run', { dry_run: dryRun }),
    onSuccess: (r) => {
      setPreview(r.proposals)
      void qc.invalidateQueries({ queryKey: ['dependencies'] })
      if (r.run.ok === false) notify('error', t('dep.failed'), r.run.error)
      else if (r.run.dry_run) notify('ok', t('dep.previewed', { n: r.proposals.length }))
      else notify('ok', t('dep.sent', { sent: r.run.sent, accepted: r.run.accepted, updated: r.run.updated, ignored: r.run.ignored }))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const canRun = can('dependencies:run')
  const d = q.data
  const actions = canRun && d?.available && (
    <>
      <Button onClick={() => run.mutate(true)} busy={run.isPending && run.variables === true} disabled={run.isPending || d.running}>
        {!(run.isPending && run.variables === true) && <Eye size={15} />}
        {t('dep.preview')}
      </Button>
      <Button variant="primary" onClick={() => run.mutate(false)} busy={run.isPending && run.variables === false} disabled={run.isPending || d.running || !d.configured}>
        {!(run.isPending && run.variables === false) && <Play size={15} />}
        {t('dep.run')}
      </Button>
    </>
  )
  return (
    <Page id="dependencies" title={t('dep.title')} subtitle={t('dep.sub')} actions={actions || undefined} wide>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message}>{errorText(t, q.error).detail}</Banner>}
      {q.isPending ? (
        <Loading />
      ) : d ? (
        <>
          {!d.available && <Banner kind="warn" title={t('dep.unavailable')} />}
          {d.available && !d.configured && <Banner kind="warn" title={t('dep.not_configured')} />}
          {d.running && <Banner kind="info" title={t('dep.running')} />}
          <div className="settings-grid">
            <LastRunCard d={d} />
            <SettingsCard settings={d.settings} canEdit={can('settings.umbrella:edit')} />
          </div>
          <ProposalTable proposals={preview ?? d.proposals} />
          <RunsTable runs={d.runs} />
        </>
      ) : null}
    </Page>
  )
}

function StateChip({ r }: { r: DependencyRun }) {
  const t = useT(strings)
  const s = runState(r)
  return (
    <Chip tone={STATE_TONE[s]} title={r.error || undefined}>
      {t(`dep.state.${s}`)}
    </Chip>
  )
}

function LastRunCard({ d }: { d: Dependencies }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const r = d.last_run
  return (
    <Card title={t('dep.last')} actions={r && <StateChip r={r} />}>
      <Rows
        align="end"
        rows={[
          [t('dep.last'), r ? <span key="l" title={formatDate(r.started_at, locale)}>{relativeTime(r.started_at, locale)} · {t(`dep.trigger.${r.trigger}`)}{r.actor ? ` · ${r.actor}` : ''}</span> : t('dep.never')],
          [t('dep.next'), d.next_run ? <span key="n" title={formatDate(d.next_run, locale)}>{formatDate(d.next_run, locale)}</span> : t('dep.schedule.off')],
        ]}
      />
      {r && (
        <div className="stat-tiles">
          {([
            ['dep.pairs', r.pairs],
            ['dep.sent.n', r.sent],
            ['dep.accepted', r.accepted],
            ['dep.updated', r.updated],
          ] as const).map(([k, v]) => (
            <div key={k} className="stat-tile">
              <span className="stat-value">{num(v, locale)}</span>
              <span className="stat-label">{t(k)}</span>
            </div>
          ))}
        </div>
      )}
      {r && r.ok === false && r.error && <Banner kind="error" title={t('dep.failed')}>{r.error}</Banner>}
    </Card>
  )
}

function SettingsCard({ settings, canEdit }: { settings: DependencySettings; canEdit: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [draft, setDraft] = useState(settings)
  useEffect(() => setDraft(settings), [settings])
  const dirty = (Object.keys(settings) as (keyof DependencySettings)[]).some((k) => settings[k] !== draft[k])
  const save = useMutation({
    mutationFn: () => put<Dependencies>('/api/dependencies/settings', draft),
    onSuccess: (v) => {
      qc.setQueryData(['dependencies'], v)
      notify('ok', t('dep.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
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
        <h2 className="card-title">{t('dep.settings')}</h2>
      </header>
      <fieldset className="plain-fieldset stack" disabled={!canEdit}>
        <Switch checked={draft.enabled} onChange={(enabled) => setDraft({ ...draft, enabled })} label={t('dep.enabled')} hint={t('dep.enabled.hint')} disabled={!canEdit} />
        <div className="grid-2">
          <Field label={t('dep.hour')}>{(id) => <Stepper id={id} value={draft.hour} min={0} max={23} onChange={(hour) => setDraft({ ...draft, hour })} />}</Field>
          <Field label={t('dep.min_days')}>{(id) => <Stepper id={id} value={draft.min_days} min={1} max={7} onChange={(min_days) => setDraft({ ...draft, min_days })} />}</Field>
          <Field label={t('dep.min_flows')}>{(id) => <Stepper id={id} value={draft.min_flows} min={1} max={100000000} onChange={(min_flows) => setDraft({ ...draft, min_flows })} />}</Field>
          <Field label={t('dep.max')}>{(id) => <Stepper id={id} value={draft.max_proposals} min={1} max={5000} onChange={(max_proposals) => setDraft({ ...draft, max_proposals })} />}</Field>
        </div>
      </fieldset>
      {canEdit && (
        <div className="card-actions row">
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!dirty}>
            {t('save')}
          </Button>
        </div>
      )}
    </form>
  )
}

function ProposalTable({ proposals }: { proposals: Proposal[] }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<SortKey>('bytes')
  const shown = useMemo(() => sortProposals(filterProposals(proposals, query), sort), [proposals, query, sort])
  return (
    <Card
      title={t('dep.found')}
      pad={false}
      actions={
        <>
          <Chip tone={proposals.length ? 'info' : 'off'}>{num(proposals.length, locale)}</Chip>
          <div className="dep-search">
            <Search size={15} aria-hidden className="muted" />
            <Input value={query} placeholder={t('dep.search')} aria-label={t('dep.search')} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <Select aria-label={t('dep.sort')} value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            {SORTS.map((s) => (
              <option key={s} value={s}>
                {t(`dep.sort.${s}`)}
              </option>
            ))}
          </Select>
        </>
      }
    >
      {shown.length === 0 ? (
        <p className="card-pad muted">{t('dep.none')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table compact">
            <thead>
              <tr>
                <th>{t('dep.from')}</th>
                <th>{t('dep.to')}</th>
                <th>{t('dep.service')}</th>
                <th className="num">{t('dep.bytes')}</th>
                <th className="num">{t('dep.flows')}</th>
                <th className="num">{t('dep.days')}</th>
                <th>{t('dep.seen')}</th>
                <th aria-label={t('dep.open')} />
              </tr>
            </thead>
            <tbody>
              {shown.map((p) => (
                <tr key={p.key}>
                  <td title={p.from.source_ref}>
                    <div>{endLabel(p.from)}</div>
                    <div className="muted mono um-sub">{p.from.ip && p.from.ip !== endLabel(p.from) ? p.from.ip : p.from.source_ref}</div>
                  </td>
                  <td title={p.to.source_ref}>
                    <div>{endLabel(p.to)}</div>
                    <div className="muted mono um-sub">{p.to.ip && p.to.ip !== endLabel(p.to) ? p.to.ip : p.to.source_ref}</div>
                  </td>
                  <td className="mono">{serviceLabel(p)}</td>
                  <td className="num">{formatBytes(p.evidence.bytes_7d, locale)}</td>
                  <td className="num">{num(p.evidence.flows_7d, locale)}</td>
                  <td className="num">{p.evidence.days_seen}</td>
                  <td>{p.evidence.last_seen ? <span title={formatDate(p.evidence.last_seen, locale)}>{relativeTime(p.evidence.last_seen, locale)}</span> : '—'}</td>
                  <td>
                    {p.evidence.flow_url && (
                      <a href={toLocal(p.evidence.flow_url)} title={t('dep.open')} aria-label={t('dep.open')}>
                        <ExternalLink size={15} />
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// toLocal keeps the Visualize link inside this console when it points at the same app
// (the public URL may differ from the address the console was opened with).
function toLocal(url: string) {
  try {
    const u = new URL(url)
    return u.pathname === '/visualize' ? `/visualize${u.search}` : url
  } catch {
    return url
  }
}

function RunsTable({ runs }: { runs: DependencyRun[] }) {
  const t = useT(strings)
  const { locale } = useLocale()
  if (runs.length === 0) return null
  return (
    <Card title={t('dep.runs')} pad={false}>
      <div className="table-wrap">
        <table className="data-table compact">
          <thead>
            <tr>
              <th>{t('dep.started')}</th>
              <th>{t('dep.by')}</th>
              <th>{t('dep.result')}</th>
              <th className="num">{t('dep.pairs')}</th>
              <th className="num">{t('dep.sent.n')}</th>
              <th className="num">{t('dep.accepted')}</th>
              <th className="num">{t('dep.updated')}</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td title={formatDate(r.started_at, locale)}>{relativeTime(r.started_at, locale)}</td>
                <td>{r.actor || t(`dep.trigger.${r.trigger}`)}</td>
                <td>
                  <StateChip r={r} />
                  {r.ok === false && r.error && <div className="muted um-sub">{r.error}</div>}
                </td>
                <td className="num">{num(r.pairs, locale)}</td>
                <td className="num">{num(r.sent, locale)}</td>
                <td className="num">{num(r.accepted, locale)}</td>
                <td className="num">{num(r.updated, locale)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
