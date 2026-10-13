import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, Save, Search } from 'lucide-react'
import { get, put } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { formatBytes, num } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Rows, Segmented, Switch, Textarea } from '../../ui/ui'
import { AS_PROVIDERS, body, move, toDraft, toggle, validate, validRD, type BmpDraft, type BmpPolicy, type BmpRoute, type BmpView } from './BmpModel'
import { validAddress } from './SnmpModel'

// Settings → BMP (docs/api.md, "BMP"): routers stream their BGP Adj-RIB-In to Flow (TCP 10179); the
// enricher fills DstASPath, DstCommunities, DstLargeCommunities and, with the "routing" provider, the AS
// numbers of every flow from these routes.

const strings: Dict = {
  en: {
    'bmp.sub': 'BGP routes streamed by the routers over BMP: AS paths, communities and AS numbers of every flow',
    'bmp.settings': 'Receiver',
    'bmp.enabled': 'Receive BMP',
    'bmp.enabled.hint': 'Flow listens on TCP 10179 (FLOW_BMP_ADDR) while this is on. Configure the routers as BMP clients of Flow.',
    'bmp.policy': 'Routes used',
    'bmp.policy.prefer-post': 'Post-policy, else pre-policy',
    'bmp.policy.post': 'Post-policy only',
    'bmp.policy.pre': 'Pre-policy only',
    'bmp.routers': 'Allowed routers',
    'bmp.routers.hint': 'Addresses or prefixes allowed to connect, one per line; empty allows any source (restrict it in the network then).',
    'bmp.providers': 'Source of SrcAS / DstAS',
    'bmp.providers.hint': 'Tried in order until one gives an AS. "routing" is the origin AS of the BMP route.',
    'bmp.provider.routing': 'BMP route (origin AS)',
    'bmp.provider.flow': 'Exporter',
    'bmp.provider.flow-except-private': 'Exporter, except private AS',
    'bmp.provider.geoip': 'GeoIP / ASN database',
    'bmp.save': 'Save',
    'bmp.saved': 'BMP settings saved',
    'bmp.state': 'State',
    'bmp.remote': 'The receiver runs with the enricher in another process: its state is on the System status page.',
    'bmp.listen': 'Listening on',
    'bmp.on': 'Receiving',
    'bmp.off': 'Off',
    'bmp.v4': 'IPv4 prefixes',
    'bmp.v6': 'IPv6 prefixes',
    'bmp.routes': 'Routes',
    'bmp.peers': 'BGP peers',
    'bmp.vpn': 'VPN prefixes',
    'bmp.vrfs': 'VRFs (RDs)',
    'bmp.memory': 'Memory (estimate)',
    'bmp.sessions': 'Routers',
    'bmp.sessions.none': 'No router connected.',
    'bmp.col.router': 'Router',
    'bmp.col.since': 'Connected',
    'bmp.col.peersup': 'Peers up',
    'bmp.col.messages': 'Messages',
    'bmp.col.peer': 'Peer',
    'bmp.col.as': 'AS',
    'bmp.col.rib': 'RIB',
    'bmp.col.routes': 'Routes',
    'bmp.lookup': 'Route lookup',
    'bmp.lookup.address': 'Address',
    'bmp.lookup.rd': 'RD (empty: global table)',
    'bmp.lookup.table': 'Table',
    'bmp.lookup.global': 'global',
    'bmp.lookup.run': 'Look up',
    'bmp.lookup.prefix': 'Prefix',
    'bmp.lookup.path': 'AS path',
    'bmp.lookup.communities': 'Communities',
    'bmp.lookup.large': 'Large communities',
    'bmp.lookup.nexthop': 'Next hop',
    'bmp.lookup.peer': 'Learned from',
    'bmp.err.router': 'Allowed routers must be addresses or prefixes',
    'bmp.err.providers': 'Choose at least one AS source',
  },
  ru: {
    'bmp.sub': 'BGP-маршруты, которые маршрутизаторы передают по BMP: AS-пути, community и номера AS каждого потока',
    'bmp.settings': 'Приём',
    'bmp.enabled': 'Принимать BMP',
    'bmp.enabled.hint': 'Пока включено, Flow слушает TCP 10179 (FLOW_BMP_ADDR). Настройте маршрутизаторы как BMP-клиенты Flow.',
    'bmp.policy': 'Какие маршруты использовать',
    'bmp.policy.prefer-post': 'После политик, иначе до политик',
    'bmp.policy.post': 'Только после политик',
    'bmp.policy.pre': 'Только до политик',
    'bmp.routers': 'Разрешённые маршрутизаторы',
    'bmp.routers.hint': 'Адреса или префиксы, которым разрешено подключаться, по одному в строке; пусто — любой источник (тогда ограничьте доступ в сети).',
    'bmp.providers': 'Источник SrcAS / DstAS',
    'bmp.providers.hint': 'Проверяются по порядку, пока один не даст AS. «routing» — AS происхождения BMP-маршрута.',
    'bmp.provider.routing': 'BMP-маршрут (AS происхождения)',
    'bmp.provider.flow': 'Экспортёр',
    'bmp.provider.flow-except-private': 'Экспортёр, кроме частных AS',
    'bmp.provider.geoip': 'База GeoIP / ASN',
    'bmp.save': 'Сохранить',
    'bmp.saved': 'Настройки BMP сохранены',
    'bmp.state': 'Состояние',
    'bmp.remote': 'Приём работает вместе с обогатителем в другом процессе: его состояние — на странице состояния системы.',
    'bmp.listen': 'Адрес приёма',
    'bmp.on': 'Принимает',
    'bmp.off': 'Выключен',
    'bmp.v4': 'Префиксов IPv4',
    'bmp.v6': 'Префиксов IPv6',
    'bmp.routes': 'Маршрутов',
    'bmp.peers': 'BGP-соседей',
    'bmp.vpn': 'Префиксов VPN',
    'bmp.vrfs': 'VRF (RD)',
    'bmp.memory': 'Память (оценка)',
    'bmp.sessions': 'Маршрутизаторы',
    'bmp.sessions.none': 'Ни один маршрутизатор не подключён.',
    'bmp.col.router': 'Маршрутизатор',
    'bmp.col.since': 'Подключён',
    'bmp.col.peersup': 'Соседей',
    'bmp.col.messages': 'Сообщений',
    'bmp.col.peer': 'Сосед',
    'bmp.col.as': 'AS',
    'bmp.col.rib': 'RIB',
    'bmp.col.routes': 'Маршрутов',
    'bmp.lookup': 'Поиск маршрута',
    'bmp.lookup.address': 'Адрес',
    'bmp.lookup.rd': 'RD (пусто — глобальная таблица)',
    'bmp.lookup.table': 'Таблица',
    'bmp.lookup.global': 'глобальная',
    'bmp.lookup.run': 'Найти',
    'bmp.lookup.prefix': 'Префикс',
    'bmp.lookup.path': 'AS-путь',
    'bmp.lookup.communities': 'Community',
    'bmp.lookup.large': 'Large community',
    'bmp.lookup.nexthop': 'Следующий узел',
    'bmp.lookup.peer': 'Получен от',
    'bmp.err.router': 'Разрешённые маршрутизаторы — это адреса или префиксы',
    'bmp.err.providers': 'Выберите хотя бы один источник AS',
  },
}

export default function BmpPage() {
  const t = useT(strings)
  const { can } = useSession()
  const q = useQuery({ queryKey: ['bmp'], queryFn: ({ signal }) => get<BmpView>('/api/settings/bmp', signal), refetchInterval: 15000 })
  return (
    <Page id="bmp" subtitle={t('bmp.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? <Loading /> : q.data ? <BmpForm view={q.data} editable={can('settings.bmp:edit')} /> : null}
    </Page>
  )
}

function BmpForm({ view, editable }: { view: BmpView; editable: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [draft, setDraft] = useState<BmpDraft>(() => toDraft(view))
  const key = JSON.stringify([view.enabled, view.policy, view.routers, view.as_providers])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setDraft(toDraft(view)), [key])
  const problems = validate(draft)
  const save = useMutation({
    mutationFn: () => put<BmpView>('/api/settings/bmp', body(draft)),
    onSuccess: (v) => {
      qc.setQueryData(['bmp'], v)
      notify('ok', t('bmp.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  return (
    <div className="settings-grid">
      <Card title={t('bmp.settings')}>
        <fieldset className="plain-fieldset stack" disabled={!editable}>
          <Switch checked={draft.enabled} onChange={(v) => setDraft({ ...draft, enabled: v })} label={t('bmp.enabled')} hint={t('bmp.enabled.hint')} disabled={!editable} />
          <Segmented<BmpPolicy>
            label={t('bmp.policy')}
            value={draft.policy}
            options={(['prefer-post', 'post', 'pre'] as const).map((p) => ({ value: p, label: t(`bmp.policy.${p}`) }))}
            onChange={(v) => setDraft({ ...draft, policy: v })}
          />
          <Field label={t('bmp.routers')} hint={t('bmp.routers.hint')}>
            {(id) => <Textarea id={id} rows={3} value={draft.routers} placeholder="192.0.2.0/24" spellCheck={false} onChange={(e) => setDraft({ ...draft, routers: e.target.value })} />}
          </Field>
          <Field label={t('bmp.providers')} hint={t('bmp.providers.hint')}>
            {() => (
              <div className="stack">
                {[...draft.as_providers, ...AS_PROVIDERS.filter((p) => !draft.as_providers.includes(p))].map((p) => {
                  const i = draft.as_providers.indexOf(p)
                  return (
                    <div key={p} className="row">
                      <Switch checked={i >= 0} onChange={() => setDraft({ ...draft, as_providers: toggle(draft.as_providers, p) })} label={`${i >= 0 ? `${i + 1}. ` : ''}${t(`bmp.provider.${p}`)}`} disabled={!editable} />
                      {i >= 0 && editable && (
                        <>
                          <button type="button" className="icon-btn" aria-label="up" disabled={i === 0} onClick={() => setDraft({ ...draft, as_providers: move(draft.as_providers, i, -1) })}>
                            <ArrowUp size={14} />
                          </button>
                          <button type="button" className="icon-btn" aria-label="down" disabled={i === draft.as_providers.length - 1} onClick={() => setDraft({ ...draft, as_providers: move(draft.as_providers, i, 1) })}>
                            <ArrowDown size={14} />
                          </button>
                        </>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </Field>
        </fieldset>
        {problems.map((p) => (
          <Banner key={p} kind="warn" title={t(p)} />
        ))}
        {editable && (
          <div className="card-actions">
            <Button variant="primary" busy={save.isPending} disabled={problems.length > 0} onClick={() => save.mutate()}>
              {!save.isPending && <Save size={15} />}
              {t('bmp.save')}
            </Button>
          </div>
        )}
      </Card>
      <StatusCard view={view} />
      {view.status && view.status.enabled && <LookupCard />}
    </div>
  )
}

function StatusCard({ view }: { view: BmpView }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const st = view.status
  if (!st) {
    return (
      <Card title={t('bmp.state')}>
        <p className="muted">{t('bmp.remote')}</p>
      </Card>
    )
  }
  return (
    <Card title={t('bmp.state')} actions={<Chip tone={st.enabled ? (st.error ? 'error' : 'ok') : 'off'}>{t(st.enabled ? 'bmp.on' : 'bmp.off')}</Chip>}>
      {st.error && <Banner kind="error" title={st.error} />}
      <Rows align="end" rows={[[t('bmp.listen'), <code key="l">{st.listen}</code>]]} />
      <div className="stat-tiles">
        {(
          [
            ['bmp.v4', num(st.rib.prefixes_v4, locale)],
            ['bmp.v6', num(st.rib.prefixes_v6, locale)],
            ...(st.rib.vrfs
              ? ([
                  ['bmp.vpn', num(st.rib.vpn_prefixes ?? 0, locale)],
                  ['bmp.vrfs', num(st.rib.vrfs, locale)],
                ] as const)
              : []),
            ['bmp.routes', num(st.rib.routes, locale)],
            ['bmp.peers', num(st.rib.peers, locale)],
            ['bmp.memory', formatBytes(st.rib.bytes, locale)],
          ] as const
        ).map(([k, v]) => (
          <div key={k} className="stat-tile">
            <span className="stat-value">{v}</span>
            <span className="stat-label">{t(k)}</span>
          </div>
        ))}
      </div>
      <h3>{t('bmp.sessions')}</h3>
      {st.sessions.length === 0 ? (
        <p className="muted">{t('bmp.sessions.none')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('bmp.col.router')}</th>
                <th>{t('bmp.col.since')}</th>
                <th className="num">{t('bmp.col.peersup')}</th>
                <th className="num">{t('bmp.col.messages')}</th>
              </tr>
            </thead>
            <tbody>
              {st.sessions.map((s) => (
                <tr key={s.router}>
                  <td>
                    <code>{s.router}</code>
                    {s.sys_name && <div className="cell-sub muted">{s.sys_name}</div>}
                    {s.last_error && <div className="cell-sub muted">{s.last_error}</div>}
                  </td>
                  <td>{formatDate(s.since, locale)}</td>
                  <td className="num">{num(s.peers_up, locale)}</td>
                  <td className="num">{num(s.messages, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {st.peers.length > 0 && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('bmp.col.peer')}</th>
                <th className="num">{t('bmp.col.as')}</th>
                <th>{t('bmp.col.rib')}</th>
                <th className="num">{t('bmp.col.routes')}</th>
              </tr>
            </thead>
            <tbody>
              {st.peers.map((p) => (
                <tr key={`${p.router}-${p.rd ?? ''}-${p.address}-${p.post_policy}`}>
                  <td>
                    <code>{p.address}</code>
                    <div className="cell-sub muted">
                      {p.router}
                      {p.rd && ` · RD ${p.rd}`}
                    </div>
                  </td>
                  <td className="num">AS{p.as}</td>
                  <td>{p.post_policy ? 'post-policy' : 'pre-policy'}</td>
                  <td className="num">{num(p.routes, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function LookupCard() {
  const t = useT(strings)
  const [addr, setAddr] = useState('')
  const [rd, setRD] = useState('')
  const lookup = useMutation({
    mutationFn: () => {
      const q = new URLSearchParams({ address: addr.trim() })
      if (rd.trim()) q.set('rd', rd.trim())
      return get<BmpRoute>(`/api/bmp/lookup?${q}`)
    },
  })
  const r = lookup.data
  return (
    <Card title={t('bmp.lookup')}>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault()
          lookup.mutate()
        }}
      >
        <Input aria-label={t('bmp.lookup.address')} value={addr} placeholder="8.8.8.8" onChange={(e) => setAddr(e.target.value)} />
        <Input aria-label={t('bmp.lookup.rd')} title={t('bmp.lookup.rd')} value={rd} placeholder="RD 65000:1" onChange={(e) => setRD(e.target.value)} />
        <Button type="submit" busy={lookup.isPending} disabled={!validAddress(addr.trim()) || (rd.trim() !== '' && !validRD(rd))}>
          {!lookup.isPending && <Search size={15} />}
          {t('bmp.lookup.run')}
        </Button>
      </form>
      {lookup.error && <Banner kind="warn" title={errorText(t, lookup.error).message} />}
      {r && (
        <Rows
          rows={[
            [t('bmp.lookup.prefix'), <code key="p">{r.prefix}</code>],
            [t('bmp.lookup.table'), r.rd ? `RD ${r.rd}` : t('bmp.lookup.global')],
            [t('bmp.lookup.path'), r.as_path.length ? r.as_path.map((a) => `AS${a}`).join(' ') : '—'],
            [t('bmp.lookup.communities'), r.communities.join(' ') || '—'],
            [t('bmp.lookup.large'), r.large_communities.join(' ') || '—'],
            [t('bmp.lookup.nexthop'), r.next_hop || '—'],
            [t('bmp.lookup.peer'), `${r.peer.address} (AS${r.peer.as}, ${r.peer.post_policy ? 'post-policy' : 'pre-policy'}) · ${r.peer.router}`],
          ]}
        />
      )}
    </Card>
  )
}
