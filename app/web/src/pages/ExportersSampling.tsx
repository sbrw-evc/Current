import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { get, put } from '../api/client'
import type { Exporter } from '../api/types'
import { errorText, useT, type Dict } from '../i18n'
import { useSession } from '../shell/session'
import { notify } from '../ui/notify'
import { Banner, Button, Card, Chip, Field, Input, Loading, Select } from '../ui/ui'
import './exporters-sampling.css'

// Sampling overrides on the Exporters page (GET/PUT /api/sampling-overrides): force the sampling
// rate of an exporter (or every exporter of a prefix), or of one interface of it.

export type SamplingOverride = { exporter: string; if_index: number; rate: number; comment: string }

const strings: Dict = {
  en: {
    'smp.title': 'Sampling overrides',
    'smp.text':
      'Force the sampling rate when an exporter reports none or a wrong one. A per-interface rate applies to the flows whose input interface (else output interface) is that one and wins over the exporter-wide rate. Collectors apply changes at once in the same process, others within a minute.',
    'smp.empty': 'No overrides: the rates the exporters report are used.',
    'smp.col.exporter': 'Exporter',
    'smp.col.if': 'Interface',
    'smp.col.rate': 'Rate',
    'smp.col.comment': 'Comment',
    'smp.all': 'All interfaces',
    'smp.other.exporter': 'Another address or prefix…',
    'smp.other.if': 'Another ifIndex…',
    'smp.exporter': 'Exporter',
    'smp.address': 'Address or prefix',
    'smp.if': 'Interface',
    'smp.ifindex': 'ifIndex',
    'smp.rate': 'Rate 1:N',
    'smp.comment': 'Comment',
    'smp.add': 'Add',
    'smp.added': 'Override added',
    'smp.removed': 'Override removed',
    'smp.delete': 'Delete the override',
    'smp.bad.address': 'An IPv4 / IPv6 address or prefix.',
    'smp.bad.rate': 'A whole number from 1.',
    'smp.bad.ifindex': 'A whole number from 1.',
    'smp.dup': 'There is already an override for this exporter and interface.',
    'smp.prefix': 'prefix',
  },
  ru: {
    'smp.title': 'Переопределение сэмплирования',
    'smp.text':
      'Задаёт коэффициент сэмплирования, когда экспортёр не сообщает его или сообщает неверный. Коэффициент интерфейса действует на потоки, у которых это входной (иначе выходной) интерфейс, и важнее коэффициента экспортёра. Коллектор в том же процессе применяет изменения сразу, остальные — в течение минуты.',
    'smp.empty': 'Переопределений нет: используются коэффициенты, которые сообщают экспортёры.',
    'smp.col.exporter': 'Экспортёр',
    'smp.col.if': 'Интерфейс',
    'smp.col.rate': 'Коэффициент',
    'smp.col.comment': 'Комментарий',
    'smp.all': 'Все интерфейсы',
    'smp.other.exporter': 'Другой адрес или префикс…',
    'smp.other.if': 'Другой ifIndex…',
    'smp.exporter': 'Экспортёр',
    'smp.address': 'Адрес или префикс',
    'smp.if': 'Интерфейс',
    'smp.ifindex': 'ifIndex',
    'smp.rate': 'Коэффициент 1:N',
    'smp.comment': 'Комментарий',
    'smp.add': 'Добавить',
    'smp.added': 'Переопределение добавлено',
    'smp.removed': 'Переопределение удалено',
    'smp.delete': 'Удалить переопределение',
    'smp.bad.address': 'Адрес или префикс IPv4 / IPv6.',
    'smp.bad.rate': 'Целое число от 1.',
    'smp.bad.ifindex': 'Целое число от 1.',
    'smp.dup': 'Для этого экспортёра и интерфейса переопределение уже есть.',
    'smp.prefix': 'префикс',
  },
}

const OTHER = '__other'
const ADDR = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(?:\/\d{1,3})?$/

// hostOf strips a host prefix length ("10.0.0.1/32" → "10.0.0.1").
export function hostOf(prefix: string) {
  return prefix.replace(/\/(32|128)$/, '')
}

export function SamplingOverrides({ exporters }: { exporters: Exporter[] }) {
  const t = useT(strings)
  const { can } = useSession()
  const edit = can('exporters:edit')
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['sampling-overrides'], queryFn: ({ signal }) => get<{ results: SamplingOverride[] }>('/api/sampling-overrides', signal) })
  const list = useMemo(() => q.data?.results ?? [], [q.data])
  const byAddr = useMemo(() => new Map(exporters.map((e) => [e.address, e])), [exporters])
  const save = useMutation({
    mutationFn: (results: SamplingOverride[]) => put<{ results: SamplingOverride[] }>('/api/sampling-overrides', { results }),
    onSuccess: (v) => qc.setQueryData(['sampling-overrides'], v),
  })
  const store = (next: SamplingOverride[], msg: string) =>
    save.mutateAsync(next).then(
      () => {
        notify('ok', msg)
        return true
      },
      (e) => {
        notify('error', errorText(t, e).message, errorText(t, e).detail)
        return false
      },
    )

  const ifLabel = (o: SamplingOverride) => {
    if (!o.if_index) return <span className="muted">{t('smp.all')}</span>
    const itf = byAddr.get(hostOf(o.exporter))?.interfaces.find((i) => i.index === o.if_index)
    return (
      <span className="mono">
        {itf ? `${itf.name} ` : ''}
        <span className="muted">#{o.if_index}</span>
      </span>
    )
  }

  return (
    <Card title={t('smp.title')} pad={false}>
      <p className="muted smp-text">{t('smp.text')}</p>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? (
        <div className="status-card">
          <Loading />
        </div>
      ) : list.length === 0 ? (
        <p className="muted empty-pad">{t('smp.empty')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table compact">
            <thead>
              <tr>
                <th>{t('smp.col.exporter')}</th>
                <th>{t('smp.col.if')}</th>
                <th className="num">{t('smp.col.rate')}</th>
                <th>{t('smp.col.comment')}</th>
                {edit && <th aria-label="" />}
              </tr>
            </thead>
            <tbody>
              {list.map((o, i) => {
                const e = byAddr.get(hostOf(o.exporter))
                const single = /\/(32|128)$/.test(o.exporter) || !o.exporter.includes('/')
                return (
                  <tr key={`${o.exporter}/${o.if_index}`}>
                    <td>
                      <div className="cell-main">{e?.name || <span className="mono">{hostOf(o.exporter)}</span>}</div>
                      <div className="cell-sub">
                        {e && <span className="mono">{hostOf(o.exporter)}</span>}
                        {!single && <Chip tone="info" dot={false}>{t('smp.prefix')}</Chip>}
                      </div>
                    </td>
                    <td>{ifLabel(o)}</td>
                    <td className="num mono">1:{o.rate}</td>
                    <td>{o.comment || <span className="muted">—</span>}</td>
                    {edit && (
                      <td className="actions-col">
                        <button
                          type="button"
                          className="icon-btn danger-icon"
                          title={t('smp.delete')}
                          aria-label={t('smp.delete')}
                          disabled={save.isPending}
                          onClick={() => void store(list.filter((_, j) => j !== i), t('smp.removed'))}
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {edit && <AddOverride exporters={exporters} list={list} busy={save.isPending} onAdd={(o) => store([...list, o], t('smp.added'))} />}
    </Card>
  )
}

function AddOverride({ exporters, list, busy, onAdd }: { exporters: Exporter[]; list: SamplingOverride[]; busy: boolean; onAdd: (o: SamplingOverride) => Promise<boolean> }) {
  const t = useT(strings)
  const [chosen, setExp] = useState<string | null>(null)
  const exp = chosen ?? exporters[0]?.address ?? OTHER
  const [addr, setAddr] = useState('')
  const [itf, setItf] = useState('0')
  const [ifIndex, setIfIndex] = useState('')
  const [rate, setRate] = useState('')
  const [comment, setComment] = useState('')
  const [tried, setTried] = useState(false)
  const exporter = exp === OTHER ? addr.trim() : exp
  const interfaces = exporters.find((e) => e.address === exp)?.interfaces ?? []
  const idx = itf === OTHER ? Number(ifIndex) : Number(itf)
  const errAddr = !ADDR.test(exporter) ? t('smp.bad.address') : ''
  const errIf = itf === OTHER && !(Number.isInteger(idx) && idx > 0) ? t('smp.bad.ifindex') : ''
  const n = Number(rate)
  const errRate = !(Number.isInteger(n) && n >= 1 && n <= 2 ** 31) ? t('smp.bad.rate') : ''
  const norm = (a: string) => hostOf(a.trim().toLowerCase())
  const dup = !errAddr && list.some((o) => norm(o.exporter) === norm(exporter) && o.if_index === (itf === OTHER ? idx : Number(itf)))
  const show = (e: string) => (tried && e ? e : undefined)

  return (
    <form
      className="status-card"
      style={{ borderTop: '1px solid var(--border)' }}
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        setTried(true)
        if (errAddr || errIf || errRate || dup) return
        void onAdd({ exporter, if_index: idx || 0, rate: n, comment: comment.trim() }).then((ok) => {
          if (!ok) return
          setTried(false)
          setRate('')
          setComment('')
        })
      }}
    >
      <div className="smp-add">
        <Field label={t('smp.exporter')}>
          {(id) => (
            <Select
              id={id}
              value={exp}
              onChange={(e) => {
                setExp(e.target.value)
                setItf('0')
              }}
            >
              {exporters.map((e) => (
                <option key={e.address} value={e.address}>
                  {e.name ? `${e.name} (${e.address})` : e.address}
                </option>
              ))}
              <option value={OTHER}>{t('smp.other.exporter')}</option>
            </Select>
          )}
        </Field>
        {exp === OTHER && (
          <Field label={t('smp.address')} hint={show(errAddr)}>
            {(id) => <Input id={id} className="mono" value={addr} placeholder="192.0.2.0/24" aria-invalid={!!show(errAddr)} onChange={(e) => setAddr(e.target.value)} />}
          </Field>
        )}
        <Field label={t('smp.if')}>
          {(id) => (
            <Select id={id} value={itf} onChange={(e) => setItf(e.target.value)}>
              <option value="0">{t('smp.all')}</option>
              {interfaces.map((i) => (
                <option key={i.index} value={String(i.index)}>
                  {`${i.name || '?'} (#${i.index})`}
                </option>
              ))}
              <option value={OTHER}>{t('smp.other.if')}</option>
            </Select>
          )}
        </Field>
        {itf === OTHER && (
          <Field label={t('smp.ifindex')} hint={show(errIf)}>
            {(id) => <Input id={id} value={ifIndex} inputMode="numeric" placeholder="17" aria-invalid={!!show(errIf)} onChange={(e) => setIfIndex(e.target.value.replace(/[^0-9]/g, ''))} />}
          </Field>
        )}
        <Field label={t('smp.rate')} hint={show(errRate)}>
          {(id) => <Input id={id} value={rate} inputMode="numeric" placeholder="1000" aria-invalid={!!show(errRate)} onChange={(e) => setRate(e.target.value.replace(/[^0-9]/g, ''))} />}
        </Field>
        <Field label={t('smp.comment')}>{(id) => <Input id={id} value={comment} onChange={(e) => setComment(e.target.value)} />}</Field>
        <div className="smp-add-btn">
          <Button type="submit" variant="primary" busy={busy}>
            {!busy && <Plus size={15} />}
            {t('smp.add')}
          </Button>
        </div>
      </div>
      {tried && dup && <Banner kind="warn" title={t('smp.dup')} />}
    </form>
  )
}
