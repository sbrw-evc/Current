import { Fragment, useMemo, useState } from 'react'
import { ChevronRight, Gauge, LineChart, Network, Router, Search, ShieldAlert } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { Link } from 'react-router-dom'
import { useExporters } from '../api/queries'
import type { Exporter, Interface } from '../api/types'
import { formatBps, formatCount, num, relativeTime } from '../lib/format'
import { errorText, useLocale, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { useSession } from '../shell/session'
import { Banner, Chip, Loading, Tile, spring, type Tone } from '../ui/ui'
import { DEFAULT_STATE, visualizeLink } from './visualize/state'
import { SamplingOverrides } from './ExportersSampling'

const strings: Dict = {
  en: {
    'exp.sub': 'Routers and switches sending NetFlow, IPFIX or sFlow',
    'tile.exporters': 'Exporters',
    'tile.fps': 'Flows per second',
    'tile.ifs': 'Interfaces',
    'tile.ext': 'External links',
    'tile.silent': 'Silent > 5 min',
    'tile.exporters.sub': 'known to the collector',
    'tile.ifs.sub': 'seen in flows',
    'tile.ext.sub': 'transit, IX, peering',
    'tile.silent.sub': 'no flows recently',
    'exp.search': 'Name, address, site…',
    'col.exporter': 'Exporter',
    'col.site': 'Site',
    'col.role': 'Role',
    'col.fps': 'Flows/s',
    'col.sampling': 'Sampling',
    'col.seen': 'Last flow',
    'col.ifs': 'Interfaces',
    'col.index': 'Index',
    'col.name': 'Interface',
    'col.desc': 'Description',
    'col.speed': 'Speed',
    'col.boundary': 'Boundary',
    'col.provider': 'Provider',
    'col.in': 'In',
    'col.out': 'Out',
    visualize: 'Visualize',
    'exp.inventory': 'In Inventory DB',
    'exp.noinventory': 'Not in Inventory DB',
    'boundary.external': 'external',
    'boundary.internal': 'internal',
    'boundary.': 'unknown',
    'exp.empty': 'No exporters yet. Point NetFlow / IPFIX / sFlow of a router at the collector.',
    'exp.nomatch': 'Nothing matches the search.',
    expand: 'Show interfaces',
  },
  ru: {
    'exp.sub': 'Маршрутизаторы и коммутаторы, присылающие NetFlow, IPFIX или sFlow',
    'tile.exporters': 'Экспортёры',
    'tile.fps': 'Потоков в секунду',
    'tile.ifs': 'Интерфейсы',
    'tile.ext': 'Внешние каналы',
    'tile.silent': 'Молчат > 5 мин',
    'tile.exporters.sub': 'известны коллектору',
    'tile.ifs.sub': 'встречались в потоках',
    'tile.ext.sub': 'транзит, IX, пиринг',
    'tile.silent.sub': 'давно нет потоков',
    'exp.search': 'Имя, адрес, площадка…',
    'col.exporter': 'Экспортёр',
    'col.site': 'Площадка',
    'col.role': 'Роль',
    'col.fps': 'Потоков/с',
    'col.sampling': 'Сэмплирование',
    'col.seen': 'Последний поток',
    'col.ifs': 'Интерфейсы',
    'col.index': 'Индекс',
    'col.name': 'Интерфейс',
    'col.desc': 'Описание',
    'col.speed': 'Скорость',
    'col.boundary': 'Граница',
    'col.provider': 'Провайдер',
    'col.in': 'Вход',
    'col.out': 'Выход',
    visualize: 'Визуализация',
    'exp.inventory': 'Есть в Inventory DB',
    'exp.noinventory': 'Нет в Inventory DB',
    'boundary.external': 'внешний',
    'boundary.internal': 'внутренний',
    'boundary.': 'не задана',
    'exp.empty': 'Экспортёров пока нет. Направьте NetFlow / IPFIX / sFlow маршрутизатора на коллектор.',
    'exp.nomatch': 'Под поиск ничего не подходит.',
    expand: 'Показать интерфейсы',
  },
}

const SILENT_MS = 5 * 60e3
const boundaryTone = (b: string): Tone => (b === 'external' ? 'orange' : b === 'internal' ? 'low' : 'off')

function ifLink(e: Exporter, i?: Interface) {
  const filter = i ? `ExporterAddress = ${e.address} AND (InIfName = '${i.name}' OR OutIfName = '${i.name}')` : `ExporterAddress = ${e.address}`
  return visualizeLink({ ...DEFAULT_STATE, range: { preset: '6h' }, filter, dimensions: i ? ['SrcAS'] : ['InIfName'], bidirectional: !!i })
}

export default function ExportersPage() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const q = useExporters()
  const [search, setSearch] = useState('')
  const [open, setOpen] = useState<Set<string>>(new Set())
  const list = useMemo(() => q.data?.results ?? [], [q.data])
  const shown = useMemo(() => {
    const s = search.trim().toLowerCase()
    return s ? list.filter((e) => [e.name, e.address, e.site, e.role].some((v) => v.toLowerCase().includes(s))) : list
  }, [list, search])
  const now = Date.now()
  const ifs = list.flatMap((e) => e.interfaces)
  const silent = list.filter((e) => now - Date.parse(e.last_seen) > SILENT_MS).length
  const visualize = can('visualize:view')
  const toggle = (a: string) =>
    setOpen((o) => {
      const n = new Set(o)
      if (n.has(a)) n.delete(a)
      else n.add(a)
      return n
    })

  return (
    <Page id="exporters" wide subtitle={t('exp.sub')}>
      <div className="tiles tiles-5">
        <Tile label={t('tile.exporters')} icon={<Router size={16} />} value={num(list.length, locale)} sub={t('tile.exporters.sub')} />
        <Tile label={t('tile.fps')} icon={<Gauge size={16} />} value={formatCount(list.reduce((a, e) => a + e.flows_per_second, 0), locale)} />
        <Tile label={t('tile.ifs')} icon={<Network size={16} />} value={num(ifs.length, locale)} sub={t('tile.ifs.sub')} />
        <Tile label={t('tile.ext')} icon={<Network size={16} />} tone="orange" value={num(ifs.filter((i) => i.boundary === 'external').length, locale)} sub={t('tile.ext.sub')} />
        <Tile label={t('tile.silent')} icon={<ShieldAlert size={16} />} tone={silent ? 'warn' : undefined} value={num(silent, locale)} sub={t('tile.silent.sub')} />
      </div>
      <section className="card toolbar-card">
        <label className="search-field">
          <Search size={16} />
          <input className="input" value={search} placeholder={t('exp.search')} onChange={(e) => setSearch(e.target.value)} />
        </label>
      </section>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      <section className="card flush-card">
        {q.isPending ? (
          <div className="status-card">
            <Loading />
          </div>
        ) : shown.length === 0 ? (
          <p className="muted empty-pad">{list.length ? t('exp.nomatch') : t('exp.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table exp-table m-cards">
              <thead>
                <tr>
                  <th className="expand-col" aria-label="" />
                  <th>{t('col.exporter')}</th>
                  <th>{t('col.site')}</th>
                  <th>{t('col.role')}</th>
                  <th className="num">{t('col.fps')}</th>
                  <th>{t('col.sampling')}</th>
                  <th>{t('col.seen')}</th>
                  <th className="num">{t('col.ifs')}</th>
                  {visualize && <th aria-label="" />}
                </tr>
              </thead>
              <tbody>
                {shown.map((e) => {
                  const isOpen = open.has(e.address)
                  const stale = now - Date.parse(e.last_seen) > SILENT_MS
                  return (
                    <Fragment key={e.address}>
                      <tr className={`clickable ${isOpen ? 'expanded' : ''}`} onClick={() => toggle(e.address)}>
                        <td className="expand-col m-hide">
                          <motion.span className="pop-icon muted" animate={{ rotate: isOpen ? 90 : 0 }} transition={spring} aria-label={t('expand')}>
                            <ChevronRight size={16} />
                          </motion.span>
                        </td>
                        <td className="m-name">
                          <div className="cell-main">{e.name || e.address}</div>
                          <div className="cell-sub">
                            <span className="mono">{e.address}</span>
                            {e.ref ? <Chip tone="ok">{t('exp.inventory')}</Chip> : <Chip tone="warn">{t('exp.noinventory')}</Chip>}
                          </div>
                        </td>
                        <td data-label={t('col.site')}>{e.site || '—'}</td>
                        <td data-label={t('col.role')}>{e.role ? <Chip tone="info" dot={false}>{e.role}</Chip> : '—'}</td>
                        <td className="num" data-label={t('col.fps')}>{num(e.flows_per_second, locale)}</td>
                        <td className="mono" data-label={t('col.sampling')}>{e.sampling_rates.map((r) => `1:${r}`).join(', ')}</td>
                        <td data-label={t('col.seen')}>
                          <Chip tone={stale ? 'warn' : 'ok'}>{relativeTime(e.last_seen, locale, now)}</Chip>
                        </td>
                        <td className="num" data-label={t('col.ifs')}>{e.interfaces.length}</td>
                        {visualize && (
                          <td className="actions-col" onClick={(ev) => ev.stopPropagation()}>
                            <Link className="btn btn-ghost btn-sm" to={ifLink(e)}>
                              <LineChart size={15} /> {t('visualize')}
                            </Link>
                          </td>
                        )}
                      </tr>
                      <AnimatePresence initial={false}>
                        {isOpen && (
                          <tr className="sub-row">
                            <td colSpan={visualize ? 9 : 8}>
                              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.22 }} style={{ overflow: 'hidden' }}>
                                <Interfaces exporter={e} visualize={visualize} />
                              </motion.div>
                            </td>
                          </tr>
                        )}
                      </AnimatePresence>
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <SamplingOverrides exporters={list} />
    </Page>
  )
}

function Util({ bps, speed }: { bps: number; speed: number }) {
  const { locale } = useLocale()
  const pct = speed > 0 ? Math.min(100, (bps / speed) * 100) : 0
  const tone = pct >= 85 ? 'error' : pct >= 60 ? 'warn' : 'ok'
  return (
    <div className="util">
      <span className="util-value">{formatBps(bps, locale)}</span>
      <span className={`util-bar tone-${tone}`} title={`${num(pct, locale, 1)} %`}>
        <span style={{ width: `${pct}%` }} />
      </span>
    </div>
  )
}

function Interfaces({ exporter, visualize }: { exporter: Exporter; visualize: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  return (
    <div className="sub-table">
      <table className="data-table compact">
        <thead>
          <tr>
            <th className="num">{t('col.index')}</th>
            <th>{t('col.name')}</th>
            <th>{t('col.desc')}</th>
            <th className="num">{t('col.speed')}</th>
            <th>{t('col.boundary')}</th>
            <th>{t('col.provider')}</th>
            <th>{t('col.in')}</th>
            <th>{t('col.out')}</th>
            {visualize && <th aria-label="" />}
          </tr>
        </thead>
        <tbody>
          {exporter.interfaces.map((i) => (
            <tr key={i.index}>
              <td className="num muted">{i.index}</td>
              <td className="mono">{i.name}</td>
              <td>{i.description || '—'}</td>
              <td className="num">{formatBps(i.speed, locale)}</td>
              <td>
                <Chip tone={boundaryTone(i.boundary)}>{t(`boundary.${i.boundary}`)}</Chip>
              </td>
              <td>{i.provider ? <Chip tone="purple">{i.provider}</Chip> : <span className="muted">—</span>}</td>
              <td>
                <Util bps={i.in_bps} speed={i.speed} />
              </td>
              <td>
                <Util bps={i.out_bps} speed={i.speed} />
              </td>
              {visualize && (
                <td className="actions-col">
                  <Link className="icon-btn" to={ifLink(exporter, i)} title={t('visualize')} aria-label={t('visualize')}>
                    <LineChart size={16} />
                  </Link>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
