import { useMemo } from 'react'
import type { GraphType, Locale, SankeyResult, TimeSeriesResult, Units } from '../../api/types'
import { chartTheme, EChart, FONT } from '../../charts/EChart'
import { isOther, seriesColor } from '../../lib/colors'
import { formatUnits } from '../../lib/format'
import { useLocale, useT, type TFunc } from '../../i18n'
import { useTheme } from '../../theme'
import { visStrings } from './strings'

export type Series = { key: string; label: string; row: string[]; axis: number; color: string; index: number }

export function rowLabel(row: string[], t: TFunc) {
  if (row.length === 1 && row[0] === 'Total') return t('total')
  if (isOther(row)) return t('other')
  return row.join(' · ')
}

// seriesOf names and colours the rows. A row keeps its colour in both directions.
export function seriesOf(data: TimeSeriesResult, dark: boolean, t: TFunc): Series[] {
  const order = new Map<string, number>()
  return data.rows.map((row, i) => {
    const key = row.join('\u0000')
    if (!order.has(key)) order.set(key, order.size)
    const n = order.get(key)!
    return { key, label: rowLabel(row, t), row, axis: data.axis[i] ?? 1, color: seriesColor(n, dark, isOther(row)), index: i }
  })
}

function timeFormatter(locale: Locale, spanMs: number) {
  const tag = locale === 'ru' ? 'ru-RU' : 'en-GB'
  const time = new Intl.DateTimeFormat(tag, { hour: '2-digit', minute: '2-digit' })
  const date = new Intl.DateTimeFormat(tag, { day: '2-digit', month: '2-digit' })
  return (v: number) => (spanMs > 36 * 3600e3 ? `${date.format(v)}\n${time.format(v)}` : time.format(v))
}

function tooltipHTML(items: { color: string; name: string; value: number }[], head: string, units: Units, locale: Locale) {
  const rows = items
    .filter((x) => Number.isFinite(x.value))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 14)
    .map(
      (x) =>
        `<div class="tt-row"><span class="tt-swatch" style="background:${x.color}"></span><span class="tt-name">${escapeHTML(x.name)}</span><span class="tt-val">${formatUnits(Math.abs(x.value), units, locale)}</span></div>`,
    )
  return `<div class="tt"><div class="tt-head">${escapeHTML(head)}</div>${rows.join('')}</div>`
}

function escapeHTML(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

type Opts = { data: TimeSeriesResult; series: Series[]; units: Units; graph: GraphType; highlighted: Set<string>; locale: Locale; t: TFunc }

function timeOption({ data, series, units, graph, highlighted, locale }: Opts) {
  const c = chartTheme()
  const times = data.t.map((x) => Date.parse(x))
  const span = (times[times.length - 1] ?? 0) - (times[0] ?? 0)
  const fmtTime = timeFormatter(locale, span)
  const fullTime = new Intl.DateTimeFormat(locale === 'ru' ? 'ru-RU' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' })
  const stacked = graph === 'stacked'
  const bidi = series.some((s) => s.axis === 2)
  const dim = (s: Series) => highlighted.size > 0 && !highlighted.has(s.key)
  return {
    animationDuration: 350,
    textStyle: { fontFamily: FONT },
    grid: { left: 8, right: 18, top: 14, bottom: 6, containLabel: true },
    tooltip: {
      trigger: 'axis',
      confine: true,
      backgroundColor: c.surface,
      borderColor: c.border,
      padding: 0,
      extraCssText: 'box-shadow: var(--shadow); border-radius: 10px;',
      axisPointer: { type: 'line', lineStyle: { color: c.muted, width: 1, type: 'dashed' } },
      formatter: (params: { seriesIndex: number; value: [number, number]; axisValue: number }[]) => {
        if (!params.length) return ''
        const items = params.map((p) => {
          const s = series[p.seriesIndex]
          return { color: s.color, name: (s.axis === 2 ? '↓ ' : '') + s.label, value: p.value[1] }
        })
        return tooltipHTML(items, fullTime.format(params[0].axisValue), units, locale)
      },
    },
    xAxis: {
      type: 'time',
      boundaryGap: false,
      axisLine: { onZero: false, lineStyle: { color: c.border } },
      axisTick: { show: false },
      axisLabel: { color: c.muted, formatter: fmtTime, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: c.muted, formatter: (v: number) => formatUnits(Math.abs(v), units, locale) },
      splitLine: { lineStyle: { color: c.grid } },
    },
    series: series.map((s) => {
      const sign = s.axis === 2 ? -1 : 1
      const faded = dim(s)
      return {
        type: 'line',
        name: s.label,
        stack: stacked ? (s.axis === 2 ? 'rev' : 'fwd') : undefined,
        showSymbol: false,
        symbol: 'circle',
        symbolSize: 6,
        sampling: 'lttb',
        smooth: false,
        z: highlighted.has(s.key) ? 5 : 2,
        lineStyle: stacked ? { width: 0.75, color: c.surface, opacity: faded ? 0.3 : 1 } : { width: highlighted.has(s.key) ? 3 : 2, color: s.color, opacity: faded ? 0.18 : 1 },
        itemStyle: { color: s.color, opacity: faded ? 0.25 : 1 },
        areaStyle: stacked ? { color: s.color, opacity: faded ? 0.12 : 0.88 } : undefined,
        emphasis: { disabled: true },
        markLine:
          bidi && s.index === 0
            ? { silent: true, symbol: 'none', label: { show: false }, lineStyle: { color: c.muted, width: 1, type: 'solid', opacity: 0.6 }, data: [{ yAxis: 0 }] }
            : undefined,
        data: data.points[s.index].map((v, i) => [times[i], v * sign]),
      }
    }),
  }
}

export function TimeChart(props: { data: TimeSeriesResult; series: Series[]; units: Units; graph: GraphType; highlighted: Set<string> }) {
  const { locale } = useLocale()
  const { theme } = useTheme()
  const t = useT(visStrings)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const option = useMemo(() => timeOption({ ...props, locale, t }), [props.data, props.series, props.units, props.graph, props.highlighted, locale, theme, t])
  return <EChart option={option} height={420} className="vis-chart" />
}

// GridChart: small multiples, one panel per row (both directions in the same panel), on a shared
// scale so the panels compare.
export function GridChart({ data, series, units, highlighted }: { data: TimeSeriesResult; series: Series[]; units: Units; highlighted: Set<string> }) {
  const { locale } = useLocale()
  const { theme } = useTheme()
  const t = useT(visStrings)
  const panels = useMemo(() => {
    const byKey = new Map<string, Series[]>()
    for (const s of series) byKey.set(s.key, [...(byKey.get(s.key) ?? []), s])
    return [...byKey.values()].slice(0, 24)
  }, [series])
  const max = useMemo(() => Math.max(1, ...series.filter((s) => s.axis === 1).map((s) => Math.max(...data.points[s.index]))), [series, data])
  const min = useMemo(() => -Math.max(0, ...series.filter((s) => s.axis === 2).map((s) => Math.max(...data.points[s.index]))), [series, data])
  return (
    <div className="vis-grid">
      {panels.map((group) => {
        const head = group[0]
        const faded = highlighted.size > 0 && !highlighted.has(head.key)
        return (
          <div key={head.key} className={`vis-grid-cell ${faded ? 'faded' : ''}`}>
            <div className="vis-grid-title">
              <span className="swatch-dot" style={{ background: head.color }} />
              <span className="vis-grid-name" title={head.label}>
                {head.label}
              </span>
              <span className="vis-grid-avg">{formatUnits(data.average[head.index], units, locale)}</span>
            </div>
            <SmallChart data={data} group={group} units={units} max={max} min={min} locale={locale} theme={theme} t={t} />
          </div>
        )
      })}
    </div>
  )
}

function niceCeil(v: number) {
  const p = 10 ** Math.floor(Math.log10(v))
  for (const m of [1, 2, 2.5, 4, 5, 10]) if (m * p >= v) return m * p
  return 10 * p
}

function SmallChart({ data, group, units, max, min, locale, theme, t }: { data: TimeSeriesResult; group: Series[]; units: Units; max: number; min: number; locale: Locale; theme: string; t: TFunc }) {
  const option = useMemo(() => {
    const base = timeOption({ data, series: group, units, graph: 'lines', highlighted: new Set(), locale, t }) as Record<string, unknown>
    // A shared, round scale: two steps above zero, as many below as the reverse direction needs.
    const step = niceCeil(max) / 2
    const scale = { step, max: step * 2, min: min < 0 ? -Math.ceil(-min / step) * step : 0 }
    const c = chartTheme()
    return {
      ...base,
      grid: { left: 4, right: 8, top: 8, bottom: 2, containLabel: true },
      yAxis: { type: 'value', max: scale.max, min: scale.min, interval: scale.step, axisLabel: { color: c.muted, fontSize: 10, formatter: (v: number) => formatUnits(Math.abs(v), units, locale) }, splitLine: { lineStyle: { color: c.grid } } },
      xAxis: { ...(base.xAxis as object), axisLabel: { show: false } },
      series: (base.series as Record<string, unknown>[]).map((s, i) => ({ ...s, areaStyle: { color: group[i].color, opacity: 0.18 }, markLine: undefined })),
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, group, units, max, min, locale, theme, t])
  return <EChart option={option} height={130} />
}

export function SankeyChart({ data, units, dimensions }: { data: SankeyResult; units: Units; dimensions: string[] }) {
  const { locale } = useLocale()
  const { theme } = useTheme()
  const t = useT(visStrings)
  const option = useMemo(() => {
    const c = chartTheme()
    const level = (n: string) => Math.max(0, dimensions.findIndex((d) => n.startsWith(d + ': ')))
    const value = (n: string) => n.slice(n.indexOf(': ') + 2)
    // A node's colour follows its rank within its column.
    const rank = new Map<string, number>()
    const sums = new Map<string, number>()
    for (const l of data.links) {
      sums.set(l.source, (sums.get(l.source) ?? 0) + l.xps)
      sums.set(l.target, (sums.get(l.target) ?? 0) + l.xps)
    }
    for (let i = 0; i < dimensions.length; i++) {
      data.nodes
        .filter((n) => level(n) === i)
        .sort((a, b) => (sums.get(b) ?? 0) - (sums.get(a) ?? 0))
        .forEach((n, k) => rank.set(n, k))
    }
    const color = (n: string) => seriesColor(rank.get(n) ?? 0, c.dark, value(n) === 'Other')
    return {
      animationDuration: 400,
      textStyle: { fontFamily: FONT },
      tooltip: {
        trigger: 'item',
        confine: true,
        backgroundColor: c.surface,
        borderColor: c.border,
        textStyle: { color: c.text, fontSize: 12.5 },
        formatter: (p: { dataType: string; data: { source?: string; target?: string; value: number; name?: string } }) => {
          const show = (n?: string) => escapeHTML(n ? (value(n) === 'Other' ? `${n.split(': ')[0]}: ${t('other')}` : n) : '')
          if (p.dataType === 'edge') return `${show(p.data.source)} → ${show(p.data.target)}<br/><b>${formatUnits(p.data.value, units, locale)}</b>`
          return `${show(p.data.name)}<br/><b>${formatUnits(p.data.value, units, locale)}</b>`
        },
      },
      series: [
        {
          type: 'sankey',
          left: 8,
          right: 150,
          top: 12,
          bottom: 12,
          nodeWidth: 14,
          nodeGap: 10,
          nodeAlign: 'justify',
          layoutIterations: 48,
          draggable: true,
          emphasis: { focus: 'adjacency' },
          label: {
            color: c.text,
            fontSize: 12,
            textBorderColor: c.surface,
            textBorderWidth: 3,
            formatter: (p: { name: string; value: number }) => `${value(p.name) === 'Other' ? t('other') : value(p.name)}  {v|${formatUnits(p.value, units, locale)}}`,
            rich: { v: { color: c.muted, fontSize: 11 } },
          },
          lineStyle: { color: 'gradient', opacity: c.dark ? 0.35 : 0.28, curveness: 0.5 },
          itemStyle: { borderWidth: 0 },
          data: data.nodes.map((n) => ({ name: n, depth: level(n), itemStyle: { color: color(n) } })),
          links: data.links.map((l) => ({ source: l.source, target: l.target, value: l.xps })),
        },
      ],
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, units, dimensions, locale, theme, t])
  const height = Math.max(380, Math.min(900, 26 * Math.max(...dimensions.map((d) => data.nodes.filter((n) => n.startsWith(d + ': ')).length), 1) + 60))
  return (
    <div className="sankey-wrap">
      <div className="sankey-heads" style={{ gridTemplateColumns: `repeat(${dimensions.length}, 1fr)` }}>
        {dimensions.map((d) => (
          <span key={d}>{d}</span>
        ))}
      </div>
      <EChart option={option} height={height} className="vis-chart" />
    </div>
  )
}
