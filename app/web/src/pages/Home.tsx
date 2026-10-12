import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowDownToLine, ArrowUpFromLine, Gauge, LineChart, Router } from 'lucide-react'
import { Link } from 'react-router-dom'
import { get } from '../api/client'
import type { Graph24, LastFlow, Summary, Top, TopWhat } from '../api/types'
import { chartTheme, EChart, FONT } from '../charts/EChart'
import { formatBps, formatBytes, formatCount, num } from '../lib/format'
import { useLocale, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { useSession } from '../shell/session'
import { useTheme } from '../theme'
import { Banner, Card, Loading, Tile } from '../ui/ui'
import { visualizeLink, DEFAULT_STATE } from './visualize/state'

const strings: Dict = {
  en: {
    'home.sub': 'Traffic of the network right now and over the last day',
    'tile.fps': 'Flows per second',
    'tile.exporters': 'Exporters',
    'tile.in': 'External, inbound',
    'tile.out': 'External, outbound',
    'tile.fps.sub': 'received by the collector',
    'tile.exporters.sub': 'sending flows',
    'tile.in.sub': 'into the network over the border',
    'tile.out.sub': 'out of the network',
    'graph.title': 'External traffic, 24 hours',
    'graph.open': 'Open in Visualize',
    'top.src-as': 'Top source AS',
    'top.dst-as': 'Top destination AS',
    'top.src-country': 'Top source countries',
    'top.dst-country': 'Top destination countries',
    'top.app': 'Top applications',
    'top.exporter': 'Top exporters',
    'top.src-port': 'Top source ports',
    'top.dst-port': 'Top destination ports',
    'last.title': 'Last flow',
    'top.empty': 'No data',
  },
  ru: {
    'home.sub': 'Трафик сети сейчас и за последние сутки',
    'tile.fps': 'Потоков в секунду',
    'tile.exporters': 'Экспортёры',
    'tile.in': 'Внешний, входящий',
    'tile.out': 'Внешний, исходящий',
    'tile.fps.sub': 'принимает коллектор',
    'tile.exporters.sub': 'присылают потоки',
    'tile.in.sub': 'в сеть через границу',
    'tile.out.sub': 'из сети наружу',
    'graph.title': 'Внешний трафик за 24 часа',
    'graph.open': 'Открыть в визуализации',
    'top.src-as': 'Топ AS источников',
    'top.dst-as': 'Топ AS получателей',
    'top.src-country': 'Топ стран источников',
    'top.dst-country': 'Топ стран получателей',
    'top.app': 'Топ приложений',
    'top.exporter': 'Топ экспортёров',
    'top.src-port': 'Топ портов источников',
    'top.dst-port': 'Топ портов получателей',
    'last.title': 'Последний поток',
    'top.empty': 'Нет данных',
  },
}

const TOPS: TopWhat[] = ['src-as', 'dst-as', 'src-country', 'dst-country', 'app', 'exporter', 'src-port', 'dst-port']

export function HomePage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const summary = useQuery({ queryKey: ['w', 'summary'], queryFn: ({ signal }) => get<Summary>('/api/widgets/summary', signal), refetchInterval: 15e3 })
  const s = summary.data
  return (
    <Page id="home" subtitle={t('home.sub')} wide>
      {summary.error && <Banner kind="error" title={t('err.network')} />}
      <div className="tiles">
        <Tile label={t('tile.fps')} icon={<Gauge size={16} />} value={s ? formatCount(s.flows_per_second, locale) : '—'} sub={t('tile.fps.sub')} />
        <Tile label={t('tile.exporters')} icon={<Router size={16} />} value={s ? num(s.exporters, locale) : '—'} sub={t('tile.exporters.sub')} />
        <Tile label={t('tile.in')} icon={<ArrowDownToLine size={16} />} tone="info" value={s ? formatBps(s.bps_in_external, locale) : '—'} sub={t('tile.in.sub')} />
        <Tile label={t('tile.out')} icon={<ArrowUpFromLine size={16} />} tone="orange" value={s ? formatBps(s.bps_out_external, locale) : '—'} sub={t('tile.out.sub')} />
      </div>
      <Card
        title={t('graph.title')}
        actions={
          can('visualize:view') && (
            <Link className="btn btn-ghost btn-sm" to={visualizeLink({ ...DEFAULT_STATE, range: { preset: '24h' }, dimensions: [], filter: "InIfBoundary = 'external'" })}>
              <LineChart size={15} /> {t('graph.open')}
            </Link>
          )
        }
      >
        <Graph />
      </Card>
      <div className="top-grid">
        {TOPS.map((w) => (
          <TopCard key={w} what={w} />
        ))}
      </div>
      <LastFlowCard />
    </Page>
  )
}

function Graph() {
  const { locale } = useLocale()
  const { theme } = useTheme()
  const q = useQuery({ queryKey: ['w', 'graph'], queryFn: ({ signal }) => get<Graph24>('/api/widgets/graph?points=200', signal), refetchInterval: 60e3 })
  const option = useMemo(() => {
    if (!q.data) return null
    const c = chartTheme()
    const color = c.dark ? '#3987e5' : '#2a78d6'
    const fmt = new Intl.DateTimeFormat(locale === 'ru' ? 'ru-RU' : 'en-GB', { hour: '2-digit', minute: '2-digit' })
    return {
      animationDuration: 400,
      textStyle: { fontFamily: FONT },
      grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
      tooltip: {
        trigger: 'axis',
        backgroundColor: c.surface,
        borderColor: c.border,
        textStyle: { color: c.text, fontSize: 12.5 },
        valueFormatter: (v: number) => formatBps(v * 1e9, locale),
      },
      xAxis: { type: 'time', axisLine: { lineStyle: { color: c.border } }, axisTick: { show: false }, axisLabel: { color: c.muted, formatter: (v: number) => fmt.format(v), hideOverlap: true }, splitLine: { show: false } },
      yAxis: { type: 'value', axisLabel: { color: c.muted, formatter: (v: number) => formatBps(v * 1e9, locale) }, splitLine: { lineStyle: { color: c.grid } } },
      series: [
        {
          type: 'line',
          name: 'Gbps',
          showSymbol: false,
          smooth: 0.2,
          lineStyle: { width: 2, color },
          itemStyle: { color },
          areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: color + '55' }, { offset: 1, color: color + '05' }] } },
          data: q.data.t.map((x, i) => [x, q.data.gbps[i]]),
        },
      ],
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data, locale, theme])
  if (q.isPending) return <div className="chart-placeholder"><Loading /></div>
  if (!option) return <Banner kind="error" title="—" />
  return <EChart option={option} height={260} />
}

function TopCard({ what }: { what: TopWhat }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const q = useQuery({ queryKey: ['w', 'top', what], queryFn: ({ signal }) => get<Top>(`/api/widgets/top/${what}`, signal), refetchInterval: 60e3 })
  const max = Math.max(1, ...(q.data?.top.map((x) => x.percent) ?? [1]))
  return (
    <section className="card top-card">
      <h3>{t(`top.${what}`)}</h3>
      {q.isPending ? (
        <Loading />
      ) : !q.data || q.data.top.length === 0 ? (
        <p className="muted">{t('top.empty')}</p>
      ) : (
        <ol className="bar-list">
          {q.data.top.map((x) => (
            <li key={x.name}>
              <div className="bar-list-row">
                <span className="bar-list-name" title={x.name}>
                  {x.name}
                </span>
                <span className="bar-list-value">{num(x.percent, locale, 1)}&nbsp;%</span>
              </div>
              <div className="bar-track">
                <span style={{ width: `${(x.percent / max) * 100}%` }} />
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}

function LastFlowCard() {
  const t = useT(strings)
  const { locale } = useLocale()
  const q = useQuery({ queryKey: ['w', 'last'], queryFn: ({ signal }) => get<LastFlow>('/api/widgets/last-flow', signal), refetchInterval: 10e3 })
  return (
    <Card title={t('last.title')}>
      {q.isPending ? (
        <Loading />
      ) : q.data ? (
        <dl className="kv-grid">
          {Object.entries(q.data).map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{k === 'Bytes' ? formatBytes(Number(v), locale) : k === 'TimeReceived' ? new Date(String(v)).toLocaleString(locale === 'ru' ? 'ru-RU' : 'en-GB') : String(v)}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </Card>
  )
}
