import { ArrowDown, ArrowUp } from 'lucide-react'
import type { SankeyResult, TimeSeriesResult, Units } from '../../api/types'
import { isOther } from '../../lib/colors'
import { formatUnits, num } from '../../lib/format'
import { useLocale, useT } from '../../i18n'
import type { Series } from './Chart'
import { visStrings } from './strings'

function DimCells({ row, t }: { row: string[]; t: (k: string) => string }) {
  return (
    <>
      {row.map((v, i) => (
        <td key={i} className={`dim-cell ${v === 'Other' ? 'muted' : ''}`} title={v}>
          {v === 'Other' ? t('other') : v === 'Total' && row.length === 1 ? t('total') : v}
        </td>
      ))}
    </>
  )
}

export function SeriesTable({ data, series, dimensions, units, highlighted, onToggle }: { data: TimeSeriesResult; series: Series[]; dimensions: string[]; units: Units; highlighted: Set<string>; onToggle: (key: string) => void }) {
  const t = useT(visStrings)
  const { locale } = useLocale()
  const bidi = series.some((s) => s.axis === 2)
  const dims = dimensions.length ? dimensions : [t('total')]
  const f = (v: number) => formatUnits(v, units, locale)
  return (
    <div className="table-wrap">
      <table className="data-table vis-table">
        <thead>
          <tr>
            <th className="swatch-col" aria-label="" />
            {bidi && <th>{t('col.dir')}</th>}
            {dims.map((d) => (
              <th key={d}>{d}</th>
            ))}
            <th className="num">{t('col.avg')}</th>
            <th className="num">{t('col.min')}</th>
            <th className="num">{t('col.max')}</th>
            <th className="num">{t('col.p95')}</th>
          </tr>
        </thead>
        <tbody>
          {series.map((s) => {
            const on = highlighted.has(s.key)
            const faded = highlighted.size > 0 && !on
            return (
              <tr key={s.index} className={`clickable ${on ? 'selected' : ''} ${faded ? 'faded' : ''} ${isOther(s.row) ? 'other-row' : ''}`} onClick={() => onToggle(s.key)} aria-selected={on}>
                <td className="swatch-col">
                  <span className="swatch-dot" style={{ background: s.color }} />
                </td>
                {bidi && (
                  <td className="dir-cell" title={t(s.axis === 2 ? 'dir.out' : 'dir.in')}>
                    {s.axis === 2 ? <ArrowDown size={14} /> : <ArrowUp size={14} />}
                  </td>
                )}
                <DimCells row={s.row} t={t} />
                <td className="num">{f(data.average[s.index])}</td>
                <td className="num">{f(data.min[s.index])}</td>
                <td className="num">{f(data.max[s.index])}</td>
                <td className="num">{f(data.p95[s.index])}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function SankeyTable({ data, dimensions, units }: { data: SankeyResult; dimensions: string[]; units: Units }) {
  const t = useT(visStrings)
  const { locale } = useLocale()
  const total = data.xps.reduce((a, b) => a + b, 0) || 1
  const order = data.rows.map((_, i) => i).sort((a, b) => data.xps[b] - data.xps[a])
  return (
    <div className="table-wrap">
      <table className="data-table vis-table">
        <thead>
          <tr>
            {dimensions.map((d) => (
              <th key={d}>{d}</th>
            ))}
            <th className="num">{t('col.rate')}</th>
            <th className="num">{t('col.share')}</th>
          </tr>
        </thead>
        <tbody>
          {order.map((i) => (
            <tr key={i} className={isOther(data.rows[i]) ? 'other-row' : undefined}>
              <DimCells row={data.rows[i]} t={t} />
              <td className="num">{formatUnits(data.xps[i], units, locale)}</td>
              <td className="num">
                <span className="share">
                  <span className="share-bar">
                    <span style={{ width: `${(data.xps[i] / total) * 100}%` }} />
                  </span>
                  {num((data.xps[i] / total) * 100, locale, 1)}&nbsp;%
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
