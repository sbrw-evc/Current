import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, RotateCcw, Save, ShieldAlert, Trash2 } from 'lucide-react'
import { get, post, put } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Rows, Stepper, Switch, Textarea } from '../../ui/ui'
import { listState, parseExclude, statusFor, validateLists, validPrefix, type ThreatList, type ThreatSettings, type ThreatView } from './ThreatModel'

// Settings → Threat intelligence (docs/api.md, "Threat intelligence"): public IP blocklists that the
// enricher downloads at run time (never shipped with Current); flows to or from a listed address get
// SrcThreat / DstThreat, and the detector rule threat_contact raises sec.threat.contact.

const strings: Dict = {
  en: {
    'thr.sub': 'Public IP blocklists checked against every flow; a contact with a listed address raises sec.threat.contact in Beacon',
    'thr.lists': 'Threat lists',
    'thr.enabled': 'Check flows against threat lists',
    'thr.enabled.hint': 'Lists are downloaded by the enricher under their own terms of use; nothing is stored in Current itself.',
    'thr.col.list': 'List',
    'thr.col.state': 'State',
    'thr.col.prefixes': 'Prefixes',
    'thr.col.updated': 'Updated',
    'thr.state.ok': 'Loaded',
    'thr.state.error': 'Failed',
    'thr.state.pending': 'Waiting',
    'thr.state.disabled': 'Off',
    'thr.skipped': '{n} skipped',
    'thr.terms': 'terms',
    'thr.add': 'Add list',
    'thr.restore': 'Default lists',
    'thr.name': 'Name',
    'thr.url': 'URL',
    'thr.refresh': 'Refresh interval',
    'thr.refresh.hint': 'At least an hour: list owners ask not to poll more often.',
    'thr.minutes': 'min',
    'thr.exclude': 'Never flag',
    'thr.exclude.hint': 'Own networks, one address or prefix per line. Private, CGNAT, loopback, link-local, multicast and documentation ranges are always excluded.',
    'thr.save': 'Save',
    'thr.saved': 'Threat intelligence settings saved',
    'thr.refresh.now': 'Refresh now',
    'thr.refresh.requested': 'Refresh requested: the lists are downloaded within a minute',
    'thr.status': 'Last update',
    'thr.status.at': 'Finished',
    'thr.status.prefixes': 'Prefixes in the table',
    'thr.status.none': 'The lists have not been downloaded yet: the enricher fetches them on start and on every interval.',
    'thr.status.requested': 'Refresh requested',
    'thr.how': 'How it is used',
    'thr.how.text': 'Current columns SrcThreat and DstThreat hold the name of the list (empty when none). Filter with DstThreat != \'\'. The detector rule "Contact with a threat list address" raises sec.threat.contact (RED, severity error by default) on the internal host.',
    'thr.err.name': 'List names: letters, digits, ".", "_", "-"',
    'thr.err.dup': 'List names must be unique',
    'thr.err.url': 'A list URL must start with http:// or https://',
    'thr.err.exclude': 'Not an address or prefix: {v}',
  },
  ru: {
    'thr.sub': 'Публичные списки опасных IP-адресов, с которыми сверяется каждый поток; контакт с адресом из списка поднимает sec.threat.contact в Beacon',
    'thr.lists': 'Списки угроз',
    'thr.enabled': 'Сверять потоки со списками угроз',
    'thr.enabled.hint': 'Списки скачивает обогатитель на условиях их владельцев; в Current они не входят.',
    'thr.col.list': 'Список',
    'thr.col.state': 'Состояние',
    'thr.col.prefixes': 'Префиксов',
    'thr.col.updated': 'Обновлён',
    'thr.state.ok': 'Загружен',
    'thr.state.error': 'Ошибка',
    'thr.state.pending': 'Ожидает',
    'thr.state.disabled': 'Выключен',
    'thr.skipped': 'пропущено {n}',
    'thr.terms': 'условия',
    'thr.add': 'Добавить список',
    'thr.restore': 'Списки по умолчанию',
    'thr.name': 'Имя',
    'thr.url': 'URL',
    'thr.refresh': 'Интервал обновления',
    'thr.refresh.hint': 'Не чаще раза в час: владельцы списков просят не опрашивать чаще.',
    'thr.minutes': 'мин',
    'thr.exclude': 'Никогда не отмечать',
    'thr.exclude.hint': 'Свои сети, по одному адресу или префиксу на строку. Частные, CGNAT, loopback, link-local, multicast и документационные диапазоны исключены всегда.',
    'thr.save': 'Сохранить',
    'thr.saved': 'Настройки списков угроз сохранены',
    'thr.refresh.now': 'Обновить сейчас',
    'thr.refresh.requested': 'Обновление запрошено: списки скачаются в течение минуты',
    'thr.status': 'Последнее обновление',
    'thr.status.at': 'Завершено',
    'thr.status.prefixes': 'Префиксов в таблице',
    'thr.status.none': 'Списки ещё не скачаны: обогатитель загружает их при запуске и по интервалу.',
    'thr.status.requested': 'Запрошено обновление',
    'thr.how': 'Как это используется',
    'thr.how.text': 'Колонки SrcThreat и DstThreat содержат имя списка (пусто, если адреса нет в списках). Фильтр: DstThreat != \'\'. Правило детектора «Контакт с адресом из списка угроз» поднимает sec.threat.contact (RED, по умолчанию severity error) на внутреннем хосте.',
    'thr.err.name': 'Имена списков: буквы, цифры, «.», «_», «-»',
    'thr.err.dup': 'Имена списков должны быть уникальными',
    'thr.err.url': 'URL списка должен начинаться с http:// или https://',
    'thr.err.exclude': 'Не адрес и не префикс: {v}',
  },
}

const tones = { ok: 'ok', error: 'error', pending: 'warn', disabled: 'off' } as const

export default function ThreatPage() {
  const t = useT(strings)
  const q = useQuery({ queryKey: ['threat'], queryFn: ({ signal }) => get<ThreatView>('/api/settings/threat', signal), refetchInterval: 30_000 })
  return (
    <Page id="threat" subtitle={t('thr.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? <Loading /> : q.data ? <ThreatForm view={q.data} key={JSON.stringify(q.data.settings)} /> : null}
    </Page>
  )
}

function ThreatForm({ view }: { view: ThreatView }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const { can } = useSession()
  const qc = useQueryClient()
  const editable = can('settings.threat:edit')
  const [draft, setDraft] = useState<ThreatSettings>(view.settings)
  const [exclude, setExclude] = useState(view.settings.exclude.join('\n'))
  const excl = parseExclude(exclude)
  const badExclude = excl.filter((e) => !validPrefix(e))
  const problems = validateLists(draft.lists)
  const setList = (i: number, l: Partial<ThreatList>) => setDraft({ ...draft, lists: draft.lists.map((x, j) => (j === i ? { ...x, ...l } : x)) })

  const save = useMutation({
    mutationFn: () => put<ThreatView>('/api/settings/threat', { ...draft, exclude: excl, refresh_requested_at: undefined }),
    onSuccess: (v) => {
      qc.setQueryData(['threat'], v)
      notify('ok', t('thr.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const refresh = useMutation({
    mutationFn: () => post<{ requested_at: string }>('/api/settings/threat/refresh'),
    onSuccess: () => {
      notify('ok', t('thr.refresh.requested'))
      void qc.invalidateQueries({ queryKey: ['threat'] })
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })

  const st = view.status
  return (
    <div className="settings-grid">
      <Card
        title={t('thr.lists')}
        actions={
          editable && (
            <Button size="sm" busy={refresh.isPending} disabled={!view.settings.enabled} onClick={() => refresh.mutate()}>
              {!refresh.isPending && <RefreshCw size={14} />}
              {t('thr.refresh.now')}
            </Button>
          )
        }
      >
        <Switch checked={draft.enabled} onChange={(v) => setDraft({ ...draft, enabled: v })} label={t('thr.enabled')} hint={t('thr.enabled.hint')} disabled={!editable} />
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th />
                <th>{t('thr.col.list')}</th>
                <th>{t('thr.col.state')}</th>
                <th className="num">{t('thr.col.prefixes')}</th>
                <th>{t('thr.col.updated')}</th>
                {editable && <th />}
              </tr>
            </thead>
            <tbody>
              {draft.lists.map((l, i) => {
                const s = statusFor(st, l.name)
                const state = listState(l, s, draft.enabled)
                return (
                  <tr key={i}>
                    <td>
                      <Switch checked={l.enabled} onChange={(v) => setList(i, { enabled: v })} label="" disabled={!editable} />
                    </td>
                    <td>
                      {editable ? (
                        <div className="stack">
                          <Input aria-label={t('thr.name')} value={l.name} onChange={(e) => setList(i, { name: e.target.value.trim() })} />
                          <Input aria-label={t('thr.url')} value={l.url} onChange={(e) => setList(i, { url: e.target.value.trim() })} />
                        </div>
                      ) : (
                        <>
                          <div>{l.name}</div>
                          <div className="cell-sub muted">
                            <code>{l.url}</code>
                          </div>
                        </>
                      )}
                      {l.terms && (
                        <div className="cell-sub muted">
                          {t('thr.terms')}: {l.terms.startsWith('https://') ? <a href={l.terms.split(' ')[0]} target="_blank" rel="noreferrer">{l.terms}</a> : l.terms}
                        </div>
                      )}
                    </td>
                    <td>
                      <Chip tone={tones[state]} title={s?.error}>
                        {t(`thr.state.${state}`)}
                      </Chip>
                      {s?.error && <div className="cell-sub muted">{s.error}</div>}
                    </td>
                    <td className="num">
                      {s ? num(s.prefixes, locale) : '—'}
                      {s && s.skipped > 0 && <div className="cell-sub muted">{t('thr.skipped', { n: num(s.skipped, locale) })}</div>}
                    </td>
                    <td>{s?.updated_at ? formatDate(s.updated_at, locale) : '—'}</td>
                    {editable && (
                      <td>
                        <button type="button" className="icon-btn" aria-label="delete" onClick={() => setDraft({ ...draft, lists: draft.lists.filter((_, j) => j !== i) })}>
                          <Trash2 size={15} />
                        </button>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {editable && (
          <div className="row">
            <Button size="sm" onClick={() => setDraft({ ...draft, lists: [...draft.lists, { name: '', url: 'https://', enabled: true }] })}>
              <Plus size={14} /> {t('thr.add')}
            </Button>
            <Button size="sm" onClick={() => setDraft({ ...draft, lists: view.default_lists })}>
              <RotateCcw size={14} /> {t('thr.restore')}
            </Button>
          </div>
        )}
        <Field label={t('thr.refresh')} hint={t('thr.refresh.hint')}>
          {(id) => <Stepper id={id} value={draft.refresh_minutes} min={60} max={10080} suffix={t('thr.minutes')} onChange={(v) => setDraft({ ...draft, refresh_minutes: v })} />}
        </Field>
        <Field label={t('thr.exclude')} hint={t('thr.exclude.hint')}>
          {(id) => <Textarea id={id} rows={3} value={exclude} disabled={!editable} onChange={(e) => setExclude(e.target.value)} placeholder="203.0.113.0/24" />}
        </Field>
        {problems.map((p) => (
          <Banner key={p} kind="warn" title={t(p)} />
        ))}
        {badExclude.length > 0 && <Banner kind="warn" title={t('thr.err.exclude', { v: badExclude.join(', ') })} />}
        {editable && (
          <div className="card-actions">
            <Button variant="primary" busy={save.isPending} disabled={problems.length > 0 || badExclude.length > 0} onClick={() => save.mutate()}>
              {!save.isPending && <Save size={15} />}
              {t('thr.save')}
            </Button>
          </div>
        )}
      </Card>
      <Card title={t('thr.status')} actions={<ShieldAlert size={18} className="muted" />}>
        {st.updated_at ? (
          <Rows
            align="end"
            rows={[
              [t('thr.status.at'), formatDate(st.updated_at, locale)],
              [t('thr.status.prefixes'), num(st.prefixes, locale)],
              ...(view.settings.refresh_requested_at ? ([[t('thr.status.requested'), formatDate(view.settings.refresh_requested_at, locale)]] as [string, string][]) : []),
            ]}
          />
        ) : (
          <p className="muted">{t('thr.status.none')}</p>
        )}
        <h3>{t('thr.how')}</h3>
        <p className="hint">{t('thr.how.text')}</p>
      </Card>
    </div>
  )
}
