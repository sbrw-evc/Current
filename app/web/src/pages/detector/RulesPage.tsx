import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Pencil, Plus, RotateCcw, Search, Trash2 } from 'lucide-react'
import { get } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Chip, Loading } from '../../ui/ui'
import { useAddDefaults, useDetectorStatus, useRules, useSaveRules } from './api'
import { Confirm, rateFormat, SeverityChip } from './common'
import { thresholdSummary, type Rule, type RulesView } from './model'
import { detStrings } from './strings'

// Detector → Rules: the list with an enable toggle per rule, links to the form, delete and
// "restore defaults". Every change PUTs the whole list (the server checks each rule).
export default function RulesPage() {
  const t = useT(detStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const nav = useNavigate()
  const edit = can('detector:edit')
  const q = useRules()
  const status = useDetectorStatus(30e3)
  const save = useSaveRules()
  const addDefaults = useAddDefaults()
  const [search, setSearch] = useState('')
  const [deleting, setDeleting] = useState<Rule | null>(null)
  const [restoring, setRestoring] = useState(false)
  const [restoreBusy, setRestoreBusy] = useState(false)
  const rules = useMemo(() => q.data?.rules ?? [], [q.data])
  const byId = useMemo(() => new Map((status.data?.rules ?? []).map((s) => [s.rule.id, s])), [status.data])
  const shown = useMemo(() => {
    const s = search.trim().toLowerCase()
    return s ? rules.filter((r) => [r.name, r.id, r.kind, t(`kind.${r.kind}`)].some((v) => v.toLowerCase().includes(s))) : rules
  }, [rules, search, t])
  const fmt = rateFormat(locale)

  const store = (next: Rule[], ok: string) =>
    save.mutateAsync(next).then(
      () => notify('ok', ok),
      (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
    )

  const toggle = (r: Rule) => void store(rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)), t('rules.saved'))

  const restore = async () => {
    setRestoreBusy(true)
    try {
      const d = await get<RulesView>('/api/detector/rules/defaults')
      await store(d.rules, t('rules.restored'))
    } catch (e) {
      notify('error', errorText(t, e).message, errorText(t, e).detail)
    } finally {
      setRestoreBusy(false)
      setRestoring(false)
    }
  }

  const fresh = q.data?.new_defaults ?? []
  const offer = (body: { ids?: string[]; dismiss?: string[] }, ok: string) =>
    addDefaults.mutateAsync(body).then(
      () => notify('ok', ok),
      (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
    )

  return (
    <Page
      id="detector-rules"
      wide
      subtitle={t('rules.sub')}
      actions={
        edit && (
          <>
            <Button onClick={() => setRestoring(true)}>
              <RotateCcw size={15} /> {t('rules.restore')}
            </Button>
            <Button variant="primary" onClick={() => nav('/detector/rules/new')}>
              <Plus size={15} /> {t('rules.new')}
            </Button>
          </>
        )
      }
    >
      {q.data?.default && <Banner kind="info" title={t('rules.default')}>{t('rules.default.text')}</Banner>}
      {edit && fresh.length > 0 && (
        <Banner kind="info" title={t('rules.newdefaults')}>
          <div className="stack" style={{ gap: 8 }}>
            <span>{t('rules.newdefaults.text', { names: fresh.map((r) => r.name || r.id).join(', ') })}</span>
            <div className="row" style={{ gap: 8 }}>
              <Button variant="primary" disabled={addDefaults.isPending} onClick={() => void offer({ ids: fresh.map((r) => r.id) }, t('rules.newdefaults.added'))}>
                <Plus size={15} /> {t('rules.newdefaults.add')}
              </Button>
              <Button disabled={addDefaults.isPending} onClick={() => void offer({ dismiss: fresh.map((r) => r.id) }, t('rules.newdefaults.dismissed'))}>
                {t('rules.newdefaults.dismiss')}
              </Button>
            </div>
          </div>
        </Banner>
      )}
      {q.error && <Banner kind="error" title={errorText(t, q.error).message}>{errorText(t, q.error).detail}</Banner>}
      <section className="card toolbar-card det-toolbar">
        <label className="search-field">
          <Search size={16} />
          <input className="input" value={search} placeholder={t('rules.search')} onChange={(e) => setSearch(e.target.value)} />
        </label>
        {q.data?.updated_at && <span className="muted">{t('rules.updated', { when: relativeTime(q.data.updated_at, locale) })}</span>}
      </section>
      <section className="card flush-card">
        {q.isPending ? (
          <div className="status-card">
            <Loading />
          </div>
        ) : shown.length === 0 ? (
          <p className="muted empty-pad">{rules.length ? t('rules.nomatch') : t('rules.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table det-table">
              <thead>
                <tr>
                  <th className="det-toggle-col">{t('col.on')}</th>
                  <th className="det-rule-col">{t('col.rule')}</th>
                  <th>{t('col.severity')}</th>
                  <th>{t('col.thresholds')}</th>
                  <th>{t('col.timing')}</th>
                  <th>{t('col.state')}</th>
                  {edit && <th aria-label="" />}
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => {
                  const st = byId.get(r.id)
                  return (
                    <tr key={r.id} className={r.enabled ? '' : 'det-rule-off'}>
                      <td className="det-toggle-col">
                        <button
                          type="button"
                          role="switch"
                          aria-checked={r.enabled}
                          aria-label={`${t('form.enabled')}: ${r.name}`}
                          disabled={!edit || save.isPending}
                          className={`switch ${r.enabled ? 'on' : ''}`}
                          onClick={() => toggle(r)}
                        >
                          <span />
                        </button>
                      </td>
                      <td className="det-rule-col">
                        <div className="cell-main">{edit ? <Link className="det-name-link" to={`/detector/rules/${encodeURIComponent(r.id)}`}>{r.name || r.id}</Link> : r.name || r.id}</div>
                        <div className="cell-sub">
                          <span>{t(`kind.${r.kind}`)}</span>
                          <span className="mono muted">{r.id}</span>
                        </div>
                      </td>
                      <td>
                        <SeverityChip severity={r.severity} />
                      </td>
                      <td className="det-cond mono">{thresholdSummary(r, fmt)}</td>
                      <td className="det-timing mono muted">{[r.window || '—', r.for || '0s', r.interval || '—'].join(' · ')}</td>
                      <td className="det-state-col">
                        <RuleState rule={r} st={st} />
                      </td>
                      {edit && (
                        <td className="actions-col">
                          <div className="row" style={{ gap: 4, flexWrap: 'nowrap' }}>
                            <Link className="icon-btn" to={`/detector/rules/${encodeURIComponent(r.id)}`} title={t('edit')} aria-label={t('edit')}>
                              <Pencil size={16} />
                            </Link>
                            <button type="button" className="icon-btn danger-icon" title={t('delete')} aria-label={t('delete')} onClick={() => setDeleting(r)}>
                              <Trash2 size={16} />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <Confirm
        open={deleting !== null}
        title={t('rules.delete.title', { name: deleting?.name ?? '' })}
        text={t('rules.delete.text')}
        action={t('delete')}
        danger
        busy={save.isPending}
        onClose={() => setDeleting(null)}
        onConfirm={() => {
          const r = deleting
          if (!r) return
          void store(
            rules.filter((x) => x.id !== r.id),
            t('rules.deleted'),
          ).finally(() => setDeleting(null))
        }}
      />
      <Confirm open={restoring} title={t('rules.restore.title')} text={t('rules.restore.text')} action={t('rules.restore')} danger busy={restoreBusy} onClose={() => setRestoring(false)} onConfirm={() => void restore()} />
    </Page>
  )
}

function RuleState({ rule, st }: { rule: Rule; st?: { last_eval?: string; error?: string; pending: number; firing: number } }) {
  const t = useT(detStrings)
  const { locale } = useLocale()
  if (!rule.enabled) return <Chip tone="off">{t('state.off')}</Chip>
  if (!st) return <span className="muted">—</span>
  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className="det-counts">
        {st.error ? <Chip tone="error">{t('state.error')}</Chip> : st.firing === 0 && st.pending === 0 ? <Chip tone="ok">{t('state.ok')}</Chip> : null}
        {st.firing > 0 && <Chip tone="error">{`${st.firing} ${t('state.firing')}`}</Chip>}
        {st.pending > 0 && <Chip tone="warn">{`${st.pending} ${t('state.pending')}`}</Chip>}
      </div>
      {st.error ? <span className="det-error-text">{st.error}</span> : st.last_eval && <span className="cell-sub">{relativeTime(st.last_eval, locale)}</span>}
    </div>
  )
}
