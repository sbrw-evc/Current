import { useId, useMemo, useState, type ReactNode } from 'react'
import { RotateCcw, Trash2 } from 'lucide-react'
import { ApiError } from '../../api/client'
import type { Column } from '../../api/types'
import { FilterEditor } from '../../filter/FilterEditor'
import { errorText, useT } from '../../i18n'
import { Banner, Button, Card, Input, Select, Switch } from '../../ui/ui'
import { Dimensions } from '../visualize/Dimensions'
import { fromDraft, KIND_SPECS, KINDS, serverProblems, SEVERITIES, slug, toDraft, validateDraft, type Draft, type FieldName, type Kind, type Problems, type Rule } from './model'
import { detStrings } from './strings'

// The rule form: fields by kind, client checks as you go (after the first save attempt) and the
// server's 400 invalid_rule message mapped back onto the fields.

type Props = {
  initial: Draft
  isNew: boolean
  takenIds: string[] // ids of the other rules
  builtin?: Rule // the built-in rule with this id ("restore default")
  columns: Column[]
  readOnly?: boolean
  onSave: (r: Rule) => Promise<unknown>
  onCancel: () => void
  onDelete?: () => void
}

export function RuleForm({ initial, isNew, takenIds, builtin, columns, readOnly, onSave, onCancel, onDelete }: Props) {
  const t = useT(detStrings)
  const [d, setD] = useState<Draft>(initial)
  const [idTouched, setIdTouched] = useState(!isNew)
  const [tried, setTried] = useState(false)
  const [server, setServer] = useState<{ fields: Problems; other: string[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')
  const spec = KIND_SPECS[d.kind]
  const local = useMemo(() => validateDraft(d, takenIds), [d, takenIds])
  const shownProblems: Problems = { ...(tried ? local : {}), ...(server?.fields ?? {}) }
  const err = (f: FieldName) => {
    const p = shownProblems[f]
    if (!p) return undefined
    return p.startsWith('v.') ? t(p) : p
  }
  const set = (patch: Partial<Draft>) => {
    setD((x) => ({ ...x, ...patch }))
    setServer(null)
    setNote('')
  }
  const setT = (k: keyof Draft['t'], v: string) => set({ t: { ...d.t, [k]: v } })
  const setB = (k: keyof Draft['b'], v: string) => set({ b: { ...d.b, [k]: v } })
  const dimColumns = useMemo(() => (spec.rollupOnly ? columns.filter((c) => c.rollup) : columns), [columns, spec.rollupOnly])

  const submit = async () => {
    setTried(true)
    if (Object.keys(local).length > 0) return
    setBusy(true)
    try {
      await onSave(fromDraft(d))
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'invalid_rule' || e.code === 'duplicate_rule')) {
        const sp = serverProblems(e.detail ?? e.code, d.metric)
        if (e.code === 'duplicate_rule') sp.fields.id = e.detail ?? e.code
        setServer(sp)
      } else {
        setServer({ fields: {}, other: [errorText(t, e).message + (errorText(t, e).detail ? `: ${errorText(t, e).detail}` : '')] })
      }
    } finally {
      setBusy(false)
    }
  }

  const rateField = (k: 'bps' | 'pps', label: string) => (
    <F label={label} hint={t('form.rate.hint')} error={err(`t.${k}`)}>
      {(id, invalid) => <Input id={id} value={d.t[k]} inputMode="decimal" placeholder={k === 'bps' ? '1G' : '100k'} aria-invalid={invalid} onChange={(e) => setT(k, e.target.value)} />}
    </F>
  )

  const thresholdFields: ReactNode[] = []
  for (const k of spec.thresholds) {
    if (d.kind === 'custom' && k !== (d.metric === 'pps' ? 'pps' : 'bps')) continue
    if (k === 'bps') thresholdFields.push(<div key="bps">{rateField('bps', t('form.t.bps'))}</div>)
    else if (k === 'pps') thresholdFields.push(<div key="pps">{rateField('pps', t('form.t.pps'))}</div>)
    else if (k === 'percent')
      thresholdFields.push(
        <F key="pct" label={t(d.kind === 'link_commit' ? 'form.t.percent.commit' : 'form.t.percent')} error={err('t.percent')}>
          {(id, invalid) => <Input id={id} value={d.t.percent} inputMode="decimal" placeholder={d.kind === 'link_commit' ? '100' : '85'} aria-invalid={invalid} onChange={(e) => setT('percent', e.target.value)} />}
        </F>,
      )
    else if (k === 'ratio')
      thresholdFields.push(
        <F key="ratio" label={t(d.kind === 'ddos_syn' ? 'form.t.ratio.syn' : d.kind === 'traffic_drop' ? 'form.t.ratio.drop' : 'form.t.ratio')} error={err('t.ratio')}>
          {(id, invalid) => <Input id={id} value={d.t.ratio} inputMode="decimal" placeholder={d.kind === 'ddos_syn' ? '0.5' : '0.1'} aria-invalid={invalid} onChange={(e) => setT('ratio', e.target.value)} />}
        </F>,
      )
    else if (k === 'silence')
      thresholdFields.push(
        <F key="silence" label={t('form.t.silence')} error={err('t.silence')}>
          {(id, invalid) => <Input id={id} value={d.t.silence} placeholder="10m" aria-invalid={invalid} onChange={(e) => setT('silence', e.target.value)} />}
        </F>,
      )
  }

  const duration = (k: 'window' | 'for' | 'interval' | 'hysteresis', placeholder: string) => (
    <F label={t(`form.${k}`)} hint={t(`form.${k}.hint`)} error={err(k)}>
      {(id, invalid) => <Input id={id} value={d[k]} placeholder={placeholder ? t('form.default', { v: placeholder }) : '—'} aria-invalid={invalid} onChange={(e) => set({ [k]: e.target.value } as Partial<Draft>)} />}
    </F>
  )

  const baselineField = (k: keyof Draft['b']) => {
    if (k === 'direction')
      return (
        <F key={k} label={t('form.b.direction')} error={err('b.direction')}>
          {(id) => (
            <Select id={id} value={d.b.direction || 'up'} onChange={(e) => setB('direction', e.target.value)}>
              {['up', 'down', 'both'].map((v) => (
                <option key={v} value={v}>
                  {t(`dir.${v}`)}
                </option>
              ))}
            </Select>
          )}
        </F>
      )
    const placeholders: Record<string, string> = { weeks: '4', min_samples: '2', window: '1h', k: '3', ratio: '0.5', min_volume: '10M' }
    const hint = k === 'k' ? t(d.kind === 'ddos_volumetric' ? 'form.b.k.hint.ddos' : 'form.b.k.hint.anomaly') : k === 'min_volume' ? t('form.rate.hint') : undefined
    return (
      <F key={k} label={t(`form.b.${k}`)} hint={hint} error={err(`b.${k}` as FieldName)}>
        {(id, invalid) => <Input id={id} value={d.b[k]} placeholder={placeholders[k]} aria-invalid={invalid} onChange={(e) => setB(k, e.target.value)} />}
      </F>
    )
  }

  const problems = tried && Object.keys(local).length > 0

  return (
    <form
      className="det-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        if (!readOnly) void submit()
      }}
    >
      {(problems || server) && (
        <div className="det-span">
          {server ? (
            <Banner kind="error" title={t('form.rejected')}>
              {[...Object.values(server.fields), ...server.other].map((m, i) => (
                <div key={i}>{m}</div>
              ))}
            </Banner>
          ) : (
            <Banner kind="error" title={t('form.invalid')} />
          )}
        </div>
      )}
      {note && (
        <div className="det-span">
          <Banner kind="info" title={note} />
        </div>
      )}
      <Card title={t('form.general')}>
        <fieldset className="plain-fieldset stack" disabled={readOnly}>
          <F label={t('form.name')} error={err('name')}>
            {(id, invalid) => (
              <Input
                id={id}
                value={d.name}
                aria-invalid={invalid}
                onChange={(e) => {
                  const name = e.target.value
                  set(idTouched ? { name } : { name, id: slug(name) })
                }}
              />
            )}
          </F>
          <F label={t('form.id')} hint={t('form.id.hint')} error={err('id')}>
            {(id, invalid) => (
              <Input
                id={id}
                className="mono"
                value={d.id}
                spellCheck={false}
                aria-invalid={invalid}
                onChange={(e) => {
                  setIdTouched(true)
                  set({ id: e.target.value })
                }}
              />
            )}
          </F>
          <div className="grid-2">
            <F label={t('form.kind')} error={err('kind')}>
              {(id) => (
                <Select id={id} value={d.kind} disabled={readOnly} onChange={(e) => set(kindPatch(d, e.target.value as Kind))}>
                  {KINDS.map((k) => (
                    <option key={k} value={k}>
                      {t(`kind.${k}`)}
                    </option>
                  ))}
                </Select>
              )}
            </F>
            <F label={t('form.severity')} error={err('severity')}>
              {(id) => (
                <Select id={id} value={d.severity} disabled={readOnly} onChange={(e) => set({ severity: e.target.value })}>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {t(`sev.${s}`)}
                    </option>
                  ))}
                </Select>
              )}
            </F>
          </div>
          <p className="muted det-kind-hint">{t(`kind.${d.kind}.hint`)}</p>
          <Switch checked={d.enabled} onChange={(enabled) => set({ enabled })} label={t('form.enabled')} hint={t('form.enabled.hint')} disabled={readOnly} />
        </fieldset>
      </Card>

      <Card title={t('form.timing')}>
        <fieldset className="plain-fieldset det-fields" disabled={readOnly}>
          {duration('window', spec.window)}
          {duration('for', '0s')}
          {duration('interval', spec.interval)}
          {duration('hysteresis', '0s')}
        </fieldset>
      </Card>

      <Card title={t('form.condition')} className="det-span">
        <fieldset className="plain-fieldset stack" disabled={readOnly}>
          {(d.kind === 'custom' || thresholdFields.length > 0) && (
          <div className="det-fields">
            {d.kind === 'custom' && (
              <>
                <F label={t('form.metric')} error={err('metric')}>
                  {(id) => (
                    <Select id={id} value={d.metric || 'bps'} disabled={readOnly} onChange={(e) => set({ metric: e.target.value })}>
                      <option value="bps">{t('form.t.bps')}</option>
                      <option value="pps">{t('form.t.pps')}</option>
                    </Select>
                  )}
                </F>
                <F label={t('form.operator')} error={err('operator')}>
                  {(id) => (
                    <Select id={id} value={d.operator || '>'} disabled={readOnly} onChange={(e) => set({ operator: e.target.value })}>
                      <option value=">">{t('op.gt')}</option>
                      <option value="<">{t('op.lt')}</option>
                    </Select>
                  )}
                </F>
              </>
            )}
            {thresholdFields}
          </div>
          )}
          {spec.filter && (
            <F label={t('form.filter')} hint={spec.rollupOnly ? `${t('form.filter.hint')} ${t('form.filter.rollup')}` : t('form.filter.hint')} error={err('filter')}>
              {() => (
                <div className={err('filter') ? 'det-invalid' : undefined}>
                  <FilterEditor value={d.filter} readOnly={readOnly} onChange={(filter) => set({ filter })} placeholder="InIfBoundary = 'external'" />
                </div>
              )}
            </F>
          )}
          {spec.dimensions && (
            <F label={t('form.dimensions')} hint={t('form.dimensions.hint')} error={err('dimensions')}>
              {() => <Dimensions value={d.dimensions} onChange={(dimensions) => set({ dimensions })} columns={dimColumns} max={8} />}
            </F>
          )}
        </fieldset>
      </Card>

      {spec.baseline.length > 0 && (
        <Card title={t('form.baseline')}>
          <fieldset className="plain-fieldset det-fields" disabled={readOnly}>
            {spec.baseline.map(baselineField)}
          </fieldset>
        </Card>
      )}

      <Card title={t('form.event')} className={spec.baseline.length > 0 ? undefined : 'det-span'}>
        <fieldset className="plain-fieldset stack" disabled={readOnly}>
          {d.kind === 'custom' ? (
            <div className="grid-2">
              <F label={t('form.signal')} hint={t('form.signal.hint')} error={err('signal')}>
                {(id, invalid) => <Input id={id} className="mono" value={d.signal} placeholder="red.traffic.custom" spellCheck={false} aria-invalid={invalid} onChange={(e) => set({ signal: e.target.value })} />}
              </F>
              <F label={t('form.method')} error={err('method')}>
                {(id) => (
                  <Select id={id} value={d.method} disabled={readOnly} onChange={(e) => set({ method: e.target.value })}>
                    <option value="">{t('form.method.auto')}</option>
                    <option value="RED">RED</option>
                    <option value="USE">USE</option>
                    <option value="other">other</option>
                  </Select>
                )}
              </F>
            </div>
          ) : (
            <p className="muted det-signal">{t('form.signal.derived', { signal: spec.signal })}</p>
          )}
          <F label={t('form.title')} hint={t('form.title.hint')} error={err('title')}>
            {(id) => <Input id={id} value={d.title} onChange={(e) => set({ title: e.target.value })} />}
          </F>
        </fieldset>
      </Card>

      {!readOnly && (
        <div className="det-span det-foot">
          <div className="det-foot-start">
            {builtin && (
              <Button
                onClick={() => {
                  setD(toDraft(builtin))
                  setServer(null)
                  setNote(t('form.restored'))
                }}
              >
                <RotateCcw size={15} /> {t('form.restore')}
              </Button>
            )}
            {onDelete && (
              <Button variant="danger-soft" onClick={onDelete}>
                <Trash2 size={15} /> {t('delete')}
              </Button>
            )}
          </div>
          <Button onClick={onCancel}>{t('cancel')}</Button>
          <Button variant="primary" type="submit" busy={busy}>
            {t(isNew ? 'form.create' : 'form.save')}
          </Button>
        </div>
      )}
    </form>
  )
}

// kindPatch switches the kind and fills the custom kind's metric and operator.
function kindPatch(d: Draft, kind: Kind): Partial<Draft> {
  if (kind === 'custom') return { kind, metric: d.metric || 'bps', operator: d.operator || '>' }
  return { kind }
}

// F: a labelled field with its error under the control.
function F({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: (id: string, invalid: boolean) => ReactNode }) {
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children(id, !!error)}
      {error ? (
        <div className="det-field-error" role="alert">
          {error}
        </div>
      ) : (
        hint && <div className="hint">{hint}</div>
      )}
    </div>
  )
}
