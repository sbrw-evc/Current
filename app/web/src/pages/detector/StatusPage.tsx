import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, BellRing, Hourglass, Inbox, LineChart, ListChecks, Send } from 'lucide-react'
import { post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { num, relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Loading, Rows, Tile, formatDate } from '../../ui/ui'
import { useDetectorStatus } from './api'
import { alertLink, alertValue, SeverityChip, StateChip } from './common'
import type { AlertState, Rule, SenderStatus } from './model'
import { detStrings } from './strings'

// Detector → Status: per-rule last run and error, active alerts (pending / firing / resolving)
// with links to Visualize, and the delivery of events to Umbrella with a test event.
export default function StatusPage() {
  const t = useT(detStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const q = useDetectorStatus(10e3)
  const s = q.data
  const rules = useMemo(() => s?.rules ?? [], [s])
  const alerts = useMemo(() => s?.alerts ?? [], [s])
  const ruleById = useMemo(() => new Map(rules.map((r) => [r.rule.id, r.rule])), [rules])
  const firing = alerts.filter((a) => a.state !== 'pending').length
  const pending = alerts.filter((a) => a.state === 'pending').length
  const errors = rules.filter((r) => r.error).length
  const active = rules.filter((r) => r.rule.enabled).length
  const now = Date.now()

  return (
    <Page id="detector-status" wide subtitle={t('status.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message}>{errorText(t, q.error).detail}</Banner>}
      {s?.remote && <Banner kind="info" title={t('status.remote')} />}
      {q.isPending ? (
        <Loading />
      ) : s ? (
        <>
          <div className="tiles tiles-5">
            <Tile label={t('tile.rules')} icon={<ListChecks size={16} />} value={num(active, locale)} sub={t('tile.rules.sub', { n: rules.length })} />
            <Tile label={t('tile.firing')} icon={<BellRing size={16} />} tone={firing ? 'error' : undefined} value={num(firing, locale)} />
            <Tile label={t('tile.pending')} icon={<Hourglass size={16} />} tone={pending ? 'warn' : undefined} value={num(pending, locale)} />
            <Tile label={t('tile.outbox')} icon={<Inbox size={16} />} tone={(s.sender?.outbox ?? 0) > 0 ? 'warn' : undefined} value={num(s.sender?.outbox ?? 0, locale)} sub={t('tile.outbox.sub')} />
            <Tile label={t('tile.errors')} icon={<AlertTriangle size={16} />} tone={errors ? 'error' : undefined} value={num(errors, locale)} />
          </div>
          <div className="det-status-grid">
            <div className="det-status-main">
              <Card title={t('status.alerts')} pad={false}>
                {alerts.length === 0 ? (
                  <p className="muted empty-pad">{t('status.noalerts')}</p>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table det-table">
                      <thead>
                        <tr>
                          <th>{t('col.state')}</th>
                          <th>{t('col.alert')}</th>
                          <th className="num">{t('col.value')}</th>
                          <th>{t('col.since')}</th>
                          {can('visualize:view') && <th aria-label="" />}
                        </tr>
                      </thead>
                      <tbody>
                        {alerts.map((a) => (
                          <AlertRow key={`${a.rule_id}/${a.key}`} a={a} rule={ruleById.get(a.rule_id)} now={now} visualize={can('visualize:view')} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
            <SenderCard sender={s.sender} queued={s.queued} />
          </div>
          <Card title={t('status.rules')} pad={false}>
            <div className="table-wrap">
              <table className="data-table det-table">
                <thead>
                  <tr>
                    <th>{t('col.rule')}</th>
                    <th>{t('col.state')}</th>
                    <th>{t('col.lasteval')}</th>
                    <th className="num">{t('col.duration')}</th>
                    <th>{t('col.next')}</th>
                    <th className="num">{t('col.groups')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.rule.id} className={r.rule.enabled ? '' : 'det-rule-off'}>
                      <td>
                        <div className="cell-main">{can('detector:edit') ? <Link className="det-name-link" to={`/detector/rules/${encodeURIComponent(r.rule.id)}`}>{r.rule.name || r.rule.id}</Link> : r.rule.name || r.rule.id}</div>
                        <div className="cell-sub">{t(`kind.${r.rule.kind}`)}</div>
                      </td>
                      <td>
                        <div className="stack" style={{ gap: 4 }}>
                          <div className="det-counts">
                            {!r.rule.enabled ? (
                              <Chip tone="off">{t('state.off')}</Chip>
                            ) : r.error ? (
                              <Chip tone="error">{t('state.error')}</Chip>
                            ) : r.firing === 0 && r.pending === 0 ? (
                              <Chip tone="ok">{t('state.ok')}</Chip>
                            ) : null}
                            {r.firing > 0 && <Chip tone="error">{`${r.firing} ${t('state.firing')}`}</Chip>}
                            {r.pending > 0 && <Chip tone="warn">{`${r.pending} ${t('state.pending')}`}</Chip>}
                          </div>
                          {r.error && <span className="det-error-text">{r.error}</span>}
                        </div>
                      </td>
                      <td>{r.last_eval ? <span title={formatDate(r.last_eval, locale)}>{relativeTime(r.last_eval, locale, now)}</span> : <span className="muted">{t('never')}</span>}</td>
                      <td className="num">{r.last_eval ? t('ms', { n: num(r.duration_ms, locale) }) : '—'}</td>
                      <td className="muted">{r.rule.enabled && r.next_eval ? <span title={formatDate(r.next_eval, locale)}>{new Date(r.next_eval).toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-GB')}</span> : '—'}</td>
                      <td className="num">{num(r.groups, locale)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      ) : null}
    </Page>
  )
}

function AlertRow({ a, rule, now, visualize }: { a: AlertState; rule?: Rule; now: number; visualize: boolean }) {
  const t = useT(detStrings)
  const { locale } = useLocale()
  const title = a.event?.title || a.group || a.key
  return (
    <tr>
      <td>
        <StateChip state={a.state} />
      </td>
      <td className="det-rule-col">
        <div className="cell-main det-alert-title">{title}</div>
        <div className="cell-sub">
          <span>{rule?.name ?? a.rule_id}</span>
          {rule && <SeverityChip severity={a.event?.severity || rule.severity} />}
        </div>
      </td>
      <td className="num">{alertValue(rule?.kind, a.value, locale)}</td>
      <td>
        <span title={formatDate(a.since, locale)}>{relativeTime(a.since, locale, now)}</span>
        {a.last_sent && <div className="cell-sub">{`${t('col.sent')}: ${relativeTime(a.last_sent, locale, now)}`}</div>}
      </td>
      {visualize && (
        <td className="actions-col">
          <Link className="btn btn-ghost btn-sm" to={alertLink(a, rule, now)}>
            <LineChart size={15} /> {t('visualize')}
          </Link>
        </td>
      )}
    </tr>
  )
}

function SenderCard({ sender, queued }: { sender?: SenderStatus; queued: number }) {
  const t = useT(detStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const test = useMutation({
    mutationFn: () => post<{ ok: boolean; error?: string }>('/api/settings/umbrella/test', { enabled: true, ingest_url: sender?.url ?? '' }),
    onSuccess: (r) => (r.ok ? notify('ok', t('sender.test.ok')) : notify('error', t('sender.test.fail'), r.error)),
    onError: (e) => notify('error', t('sender.test.fail'), errorText(t, e).detail ?? errorText(t, e).message),
  })
  const on = !!sender?.configured
  return (
    <Card title={t('sender.title')} actions={<Chip tone={on ? 'ok' : 'off'}>{t(on ? 'sender.on' : 'sender.off')}</Chip>} className="side-card">
      <div className="det-url">
        <span className="muted">{t('sender.url')}</span>
        <code>{sender?.url || '—'}</code>
      </div>
      <Rows
        align="end"
        rows={[
          [t('sender.outbox'), num(sender?.outbox ?? 0, locale)],
          [t('sender.queued'), num(queued, locale)],
          [t('sender.sent'), num(sender?.sent ?? 0, locale)],
          [t('sender.dropped'), sender?.dropped ? <Chip key="d" tone="warn">{num(sender.dropped, locale)}</Chip> : '0'],
          [t('sender.last_success'), sender?.last_success ? <span key="s" title={formatDate(sender.last_success, locale)}>{relativeTime(sender.last_success, locale)}</span> : t('sender.never')],
        ]}
      />
      {sender?.last_error && (
        <Banner kind="error" title={t('sender.last_error')}>
          {sender.last_error}
        </Banner>
      )}
      {!on && <p className="muted">{t('sender.hint')}</p>}
      {can('settings.umbrella:edit') && (
        <div className="card-actions">
          <Button variant="primary" busy={test.isPending} disabled={!sender?.url} onClick={() => test.mutate()}>
            {!test.isPending && <Send size={15} />}
            {t('sender.test')}
          </Button>
        </div>
      )}
    </Card>
  )
}
