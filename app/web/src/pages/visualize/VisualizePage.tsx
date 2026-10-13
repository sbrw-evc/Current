import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, CheckCircle2, ChevronsLeft, Link2, Loader2, Play, SlidersHorizontal } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useSearchParams } from 'react-router-dom'
import { ApiError, post } from '../../api/client'
import { useSchema } from '../../api/queries'
import type { GraphType, SankeyResult, TimeSeriesResult, Units } from '../../api/types'
import { FilterEditor, type FilterStatus } from '../../filter/FilterEditor'
import { errorText, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useTheme } from '../../theme'
import { notify } from '../../ui/notify'
import { TimeRange } from '../../ui/TimeRange'
import { Banner, Button, Loading, Segmented, Stepper, Switch } from '../../ui/ui'
import { GridChart, SankeyChart, seriesOf, TimeChart } from './Chart'
import { Dimensions } from './Dimensions'
import { SankeyTable, SeriesTable } from './ResultTable'
import { SavedViews } from './SavedViews'
import { decodeState, encodeState, GRAPHS, toRequest, UNITS, visualizeLink, type VisState } from './state'
import { visStrings } from './strings'
import { Sheet } from '../../shell/mobile/Sheet'
import { useMobile } from '../../shell/mobile/useMobile'

const PANEL_KEY = 'flow.visualize.panel'

export default function VisualizePage() {
  const t = useT(visStrings)
  const [params, setParams] = useSearchParams()
  const q = params.get('q')
  const committed = useMemo(() => decodeState(q), [q])
  const [draft, setDraft] = useState<VisState>(committed)
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<FilterStatus>({ valid: true, checking: false })
  const [panel, setPanel] = useState(() => {
    try {
      return localStorage.getItem(PANEL_KEY) !== '0'
    } catch {
      return true
    }
  })
  // On the phone the options open in a bottom sheet (Umbrella's filters sheet).
  const mobile = useMobile()
  const [sheet, setSheet] = useState(false)
  useEffect(() => setDraft(committed), [committed])
  useEffect(() => {
    try {
      localStorage.setItem(PANEL_KEY, panel ? '1' : '0')
    } catch {
      // Kept until reload.
    }
  }, [panel])

  const schema = useSchema()
  const sankeyShort = committed.graph === 'sankey' && committed.dimensions.length < 2
  const result = useQuery({
    queryKey: ['visualize', q ?? '', nonce],
    queryFn: ({ signal }) => post<TimeSeriesResult | SankeyResult>('/api/visualize', toRequest(committed), signal),
    enabled: !sankeyShort,
    staleTime: 60e3,
    retry: false,
  })

  const dirty = encodeState(draft) !== encodeState(committed)
  const set = (p: Partial<VisState>) => setDraft((d) => ({ ...d, ...p }))
  const apply = (s: VisState = draft) => {
    const next = encodeState(s)
    if (next === (q ?? encodeState(committed))) setNonce((n) => n + 1)
    else setParams({ q: next })
  }
  const copyLink = async () => {
    const url = window.location.origin + visualizeLink(committed)
    try {
      await navigator.clipboard.writeText(url)
      notify('ok', t('link.copied'))
    } catch {
      window.prompt(t('link.copy'), url)
    }
  }

  const columns = schema.data?.columns ?? []
  const options = (
    <>
      <div className="opt-section">
        <span className="opt-label">{t('opt.range')}</span>
        <TimeRange value={draft.range} onChange={(range) => set({ range })} />
      </div>
      <div className="opt-section">
        <span className="opt-label">{t('opt.graph')}</span>
        <Segmented<GraphType> label={t('opt.graph')} value={draft.graph} onChange={(graph) => set({ graph })} options={GRAPHS.map((g) => ({ value: g, label: t(`graph.${g}`) }))} />
      </div>
      <div className="opt-section">
        <span className="opt-label">{t('opt.units')}</span>
        <div className="chip-row">
          {UNITS.map((u) => (
            <button key={u} type="button" title={t(`units.${u}.t`)} className={`chip ${draft.units === u ? 'on' : ''}`} onClick={() => set({ units: u as Units })}>
              {t(`units.${u}`)}
            </button>
          ))}
        </div>
      </div>
      <div className="opt-section">
        <span className="opt-label">{t('opt.dims')}</span>
        <Dimensions value={draft.dimensions} onChange={(dimensions) => set({ dimensions })} columns={columns} />
        {draft.graph === 'sankey' && draft.dimensions.length < 2 && <p className="hint warn-text">{t('opt.dims.sankey')}</p>}
      </div>
      <div className="opt-row">
        <div className="opt-section">
          <span className="opt-label">{t('opt.limit')}</span>
          <Stepper value={draft.limit} min={1} max={50} onChange={(limit) => set({ limit })} label={t('opt.limit')} />
        </div>
        <div className="opt-section opt-grow">
          <span className="opt-label">&nbsp;</span>
          <Switch checked={draft.bidirectional && draft.graph !== 'sankey'} disabled={draft.graph === 'sankey'} onChange={(bidirectional) => set({ bidirectional })} label={t('opt.bidi')} />
        </div>
      </div>
      <div className="opt-section">
        <span className="opt-label">{t('opt.filter')}</span>
        <FilterEditor value={draft.filter} onChange={(filter) => set({ filter })} onSubmit={() => status.valid && apply()} onStatus={setStatus} placeholder={t('opt.filter.ph')} />
        <FilterLine status={status} filter={draft.filter} />
      </div>
      <div className="opt-apply">
        <Button
          variant="primary"
          onClick={() => {
            apply()
            setSheet(false)
          }}
          disabled={!status.valid}
          busy={result.isFetching}
        >
          {!result.isFetching && <Play size={15} />}
          {t('opt.apply')}
        </Button>
        {dirty && <span className="hint">{t('opt.dirty')}</span>}
      </div>
      <div className="opt-section opt-views">
        <SavedViews
          current={committed}
          onLoad={(s) => {
            setDraft(s)
            apply(s)
            setSheet(false)
          }}
        />
      </div>
    </>
  )
  return (
    <Page
      id="visualize"
      wide
      subtitle={t('vis.sub')}
      actions={
        <>
          {(mobile || !panel) && (
            <Button variant="secondary" onClick={() => (mobile ? setSheet(true) : setPanel(true))}>
              <SlidersHorizontal size={16} /> {t('opt.show')}
            </Button>
          )}
          <Button variant="secondary" onClick={copyLink}>
            <Link2 size={16} /> {t('link.copy')}
          </Button>
        </>
      }
    >
      {mobile && (
        <Sheet open={sheet} title={t('opt.title')} onClose={() => setSheet(false)}>
          <div className="vis-options vis-options-sheet">{options}</div>
        </Sheet>
      )}
      <div className={`vis-layout ${panel && !mobile ? '' : 'panel-closed'}`}>
        <AnimatePresence initial={false}>
          {panel && !mobile && (
            <motion.aside
              className="card vis-options"
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              transition={{ duration: 0.2 }}
              aria-label={t('opt.title')}
            >
              <div className="opt-head">
                <h2>{t('opt.title')}</h2>
                <button type="button" className="icon-btn" onClick={() => setPanel(false)} aria-label={t('opt.hide')} title={t('opt.hide')}>
                  <ChevronsLeft size={18} />
                </button>
              </div>
              {options}
            </motion.aside>
          )}
        </AnimatePresence>
        <div className="vis-results">
          {sankeyShort ? (
            <div className="card status-card">
              <Banner kind="info" title={t('opt.dims.sankey')} />
            </div>
          ) : (
            <Results state={committed} result={result} />
          )}
        </div>
      </div>
    </Page>
  )
}

function FilterLine({ status, filter }: { status: FilterStatus; filter: string }) {
  const t = useT(visStrings)
  if (status.checking)
    return (
      <p className="filter-status muted">
        <Loader2 size={13} className="spin" /> {t('opt.filter.checking')}
      </p>
    )
  if (!status.valid)
    return (
      <p className="filter-status bad">
        <AlertCircle size={13} /> {status.message}
      </p>
    )
  if (filter.trim())
    return (
      <p className="filter-status good">
        <CheckCircle2 size={13} /> {t('opt.filter.ok')}
      </p>
    )
  return <p className="hint">{t('opt.filter.hint')}</p>
}

type ResultQuery = { data?: TimeSeriesResult | SankeyResult; error: unknown; isPending: boolean; isFetching: boolean }

function Results({ state, result }: { state: VisState; result: ResultQuery }) {
  const t = useT(visStrings)
  const { theme } = useTheme()
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set())
  const data = result.data
  useEffect(() => setHighlighted(new Set()), [data])
  const ts = data && 't' in data ? data : null
  const sk = data && !('t' in data) ? data : null
  const series = useMemo(() => (ts ? seriesOf(ts, theme === 'dark', t) : []), [ts, theme, t])
  const toggle = (key: string) =>
    setHighlighted((h) => {
      const n = new Set(h)
      if (n.has(key)) n.delete(key)
      else n.add(key)
      return n
    })

  if (result.isPending) {
    return (
      <div className="card status-card chart-placeholder tall">
        <Loading />
      </div>
    )
  }
  if (result.error) {
    const e = errorText(t, result.error)
    return (
      <div className="card status-card">
        <Banner kind="error" title={t('res.error')}>
          {result.error instanceof ApiError && result.error.code === 'invalid_filter' ? `${e.message} ${e.detail ?? ''}` : e.detail ?? e.message}
        </Banner>
      </div>
    )
  }
  const empty = ts ? ts.rows.length === 0 || ts.t.length === 0 : sk ? sk.links.length === 0 : true
  const dims = sk ? (state.dimensions.length >= 2 ? state.dimensions : state.dimensions) : state.dimensions
  return (
    <>
      <section className={`card vis-chart-card ${result.isFetching ? 'refreshing' : ''}`}>
        <div className="vis-chart-head">
          <div className="row vis-meta">
            <span className="pill pill-off">{t(`graph.${state.graph}`)}</span>
            <span className="pill pill-off">{t(`units.${state.units}`)}</span>
            {ts && <span className="pill pill-off">{t('res.resolution', { r: ts.resolution })}</span>}
            {ts && <span className="hint">{t('res.points', { n: ts.t.length })}</span>}
          </div>
          {result.isFetching && <Loader2 size={16} className="spin muted" />}
        </div>
        {empty ? (
          <div className="chart-placeholder">
            <p className="muted">{t('res.empty')}</p>
          </div>
        ) : ts ? (
          state.graph === 'grid' ? (
            <GridChart data={ts} series={series} units={state.units} highlighted={highlighted} />
          ) : (
            <TimeChart data={ts} series={series} units={state.units} graph={state.graph} highlighted={highlighted} />
          )
        ) : sk ? (
          <SankeyChart data={sk} units={state.units} dimensions={dims} />
        ) : null}
      </section>
      {!empty && (
        <section className="card flush-card">
          {ts && <SeriesTable data={ts} series={series} dimensions={state.dimensions} units={state.units} highlighted={highlighted} onToggle={toggle} />}
          {sk && <SankeyTable data={sk} dimensions={dims} units={state.units} />}
          {ts && <p className="table-foot hint">{t('row.highlight')}</p>}
        </section>
      )}
      {data && 'sql' in data && data.sql && <SqlBox sql={data.sql} />}
    </>
  )
}

function SqlBox({ sql }: { sql: string }) {
  const t = useT(visStrings)
  return (
    <details className="card sql-box">
      <summary>{t('res.sql')}</summary>
      <pre>{sql}</pre>
      <div className="sql-actions">
        <button type="button" className="link-button" onClick={() => void navigator.clipboard?.writeText(sql).then(() => notify('ok', t('res.copySql')))}>
          {t('res.copySql')}
        </button>
      </div>
    </details>
  )
}
