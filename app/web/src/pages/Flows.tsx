import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Columns3, Search } from 'lucide-react'
import { post } from '../api/client'
import type { FlowsRequest, FlowsResult } from '../api/types'
import { FilterEditor, type FilterStatus } from '../filter/FilterEditor'
import { formatBytes, num } from '../lib/format'
import { resolve, type Range } from '../lib/time'
import { errorText, useLocale, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { TimeRange } from '../ui/TimeRange'
import { Banner, Button, Loading, Segmented, Stepper } from '../ui/ui'

const strings: Dict = {
  en: {
    'flows.sub': 'Raw flow records, newest or largest first',
    'flows.range': 'Time range',
    'flows.filter': 'Filter',
    'flows.filter.ph': 'e.g. DstPort = 443 AND SrcAS = AS15169',
    'flows.limit': 'Limit',
    'flows.order': 'Order',
    'order.time': 'Newest',
    'order.bytes': 'Largest',
    'flows.columns': 'Columns',
    'flows.found': '{n} flows',
    'flows.empty': 'No flows match the filter.',
    'flows.start': 'Set the filter and press Search.',
  },
  ru: {
    'flows.sub': 'Сырые записи потоков, сначала новые или крупные',
    'flows.range': 'Период',
    'flows.filter': 'Фильтр',
    'flows.filter.ph': 'например, DstPort = 443 AND SrcAS = AS15169',
    'flows.limit': 'Сколько',
    'flows.order': 'Порядок',
    'order.time': 'Новые',
    'order.bytes': 'Крупные',
    'flows.columns': 'Столбцы',
    'flows.found': 'Потоков: {n}',
    'flows.empty': 'Под фильтр не подходит ни один поток.',
    'flows.start': 'Задайте фильтр и нажмите «Найти».',
  },
}

const DEFAULT_COLUMNS = ['TimeReceived', 'ExporterName', 'SrcAddr', 'DstAddr', 'SrcAS', 'DstAS', 'SrcPort', 'DstPort', 'Proto', 'App', 'Bytes', 'Packets']
const COLS_KEY = 'flow.flows.columns'

export default function FlowsPage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const [range, setRange] = useState<Range>({ preset: '15m' })
  const [filter, setFilter] = useState('')
  const [limit, setLimit] = useState(100)
  const [order, setOrder] = useState<'time' | 'bytes'>('time')
  const [status, setStatus] = useState<FilterStatus>({ valid: true, checking: false })
  const [shown, setShown] = useState<string[]>(() => {
    try {
      const v = JSON.parse(localStorage.getItem(COLS_KEY) ?? 'null')
      return Array.isArray(v) ? v : DEFAULT_COLUMNS
    } catch {
      return DEFAULT_COLUMNS
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem(COLS_KEY, JSON.stringify(shown))
    } catch {
      // Kept until reload.
    }
  }, [shown])

  const search = useMutation({ mutationFn: (req: FlowsRequest) => post<FlowsResult>('/api/flows/search', req) })
  const run = () => search.mutate({ ...resolve(range), filter, limit, order })
  useEffect(run, []) // eslint-disable-line react-hooks/exhaustive-deps

  const data = search.data
  const visible = useMemo(() => (data ? data.columns.map((c, i) => [c, i] as const).filter(([c]) => shown.includes(c)) : []), [data, shown])
  const cell = (c: string, v: string | number) => {
    if (c === 'TimeReceived') return new Date(String(v)).toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-GB')
    if (c === 'Bytes') return formatBytes(Number(v), locale)
    if (c === 'Packets' || c === 'SamplingRate') return num(Number(v), locale)
    if (c.endsWith('AS')) return `AS${v}`
    return String(v)
  }

  return (
    <Page id="flows" wide subtitle={t('flows.sub')}>
      <section className="card toolbar-card">
        <div className="toolbar-grid">
          <div className="opt-section">
            <span className="opt-label">{t('flows.range')}</span>
            <TimeRange value={range} onChange={setRange} />
          </div>
          <div className="row toolbar-right">
            <div className="opt-section">
              <span className="opt-label">{t('flows.order')}</span>
              <Segmented label={t('flows.order')} value={order} onChange={setOrder} options={[{ value: 'time', label: t('order.time') }, { value: 'bytes', label: t('order.bytes') }]} />
            </div>
            <div className="opt-section">
              <span className="opt-label">{t('flows.limit')}</span>
              <Stepper value={limit} min={1} max={1000} onChange={setLimit} />
            </div>
          </div>
        </div>
        <div className="opt-section">
          <span className="opt-label">{t('flows.filter')}</span>
          <div className="filter-row">
            <FilterEditor value={filter} onChange={setFilter} onStatus={setStatus} onSubmit={() => status.valid && run()} placeholder={t('flows.filter.ph')} />
            <Button variant="primary" onClick={run} busy={search.isPending} disabled={!status.valid}>
              {!search.isPending && <Search size={15} />}
              {t('search')}
            </Button>
          </div>
          {!status.valid && <p className="filter-status bad">{status.message}</p>}
        </div>
      </section>
      {search.error && <Banner kind="error" title={errorText(t, search.error).message}>{errorText(t, search.error).detail}</Banner>}
      <section className="card flush-card">
        <div className="flush-head">
          <h2 className="card-title">{data ? t('flows.found', { n: num(data.rows.length, locale) }) : t('flows.start')}</h2>
          {data && <ColumnChooser all={data.columns} shown={shown} onChange={setShown} />}
        </div>
        {search.isPending && !data ? (
          <div className="status-card"><Loading /></div>
        ) : data && data.rows.length === 0 ? (
          <p className="muted empty-pad">{t('flows.empty')}</p>
        ) : data ? (
          <div className="table-wrap">
            <table className="data-table compact">
              <thead>
                <tr>
                  {visible.map(([c]) => (
                    <th key={c} className={['Bytes', 'Packets', 'SrcPort', 'DstPort', 'SamplingRate'].includes(c) ? 'num' : undefined}>
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.rows.map((r, i) => (
                  <tr key={i}>
                    {visible.map(([c, j]) => (
                      <td key={c} className={['Bytes', 'Packets', 'SrcPort', 'DstPort', 'SamplingRate'].includes(c) ? 'num' : c.endsWith('Addr') ? 'mono' : undefined}>
                        {cell(c, r[j])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </Page>
  )
}

function ColumnChooser({ all, shown, onChange }: { all: string[]; shown: string[]; onChange: (v: string[]) => void }) {
  const t = useT(strings)
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: PointerEvent) => !root.current?.contains(e.target as Node) && setOpen(false)
    document.addEventListener('pointerdown', close)
    return () => document.removeEventListener('pointerdown', close)
  }, [open])
  return (
    <div className="popover-root" ref={root}>
      <Button variant="secondary" size="sm" onClick={() => setOpen(!open)} aria-expanded={open}>
        <Columns3 size={15} /> {t('flows.columns')} ({all.filter((c) => shown.includes(c)).length}/{all.length})
      </Button>
      {open && (
        <div className="card popover column-chooser">
          {all.map((c) => (
            <label key={c} className="check-row">
              <input type="checkbox" checked={shown.includes(c)} onChange={(e) => onChange(e.target.checked ? all.filter((x) => x === c || shown.includes(x)) : shown.filter((x) => x !== c))} />
              <span>{c}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}
