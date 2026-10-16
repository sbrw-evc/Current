import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Plus, Radar, Router, Search, Users, WifiOff } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { get, post } from '../../api/client'
import type { InventoryDB } from '../../api/types'
import { errorText, useLocale, useT } from '../../i18n'
import { num, relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { Banner, Button, Chip, Field, Input, Loading, Modal, Tile } from '../../ui/ui'
import { useDevices } from './api'
import { DeviceForm } from './DeviceForm'
import { deviceCounts, emptyDraft, matchDevice, statusTone, type Device, type DeviceDraft, type Found } from './model'
import { devicesStrings } from './strings'
import './devices.css'

// Network → Devices: the managed devices, their state, and adding devices (from Ledger when it
// is connected, else as local records; or from a discovery scan).

export function useInventoryConnected() {
  const { can } = useSession()
  const q = useQuery({ queryKey: ['inventory-db'], queryFn: ({ signal }) => get<InventoryDB>('/api/inventory-db', signal), enabled: can('settings.inventory:view'), staleTime: 60e3 })
  return !!(q.data?.enabled && q.data.url)
}

export function DeviceStatus({ d }: { d: Pick<Device, 'status' | 'enabled' | 'last_error'> }) {
  const t = useT(devicesStrings)
  if (!d.enabled) return <Chip tone="off">{t('status.disabled')}</Chip>
  return (
    <Chip tone={statusTone(d.status)} title={d.status !== 'up' ? d.last_error : undefined}>
      {t(`status.${d.status}`)}
    </Chip>
  )
}

export default function DevicesPage() {
  const t = useT(devicesStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const nav = useNavigate()
  const q = useDevices()
  const inventory = useInventoryConnected()
  const [search, setSearch] = useState('')
  const [adding, setAdding] = useState<Partial<DeviceDraft> | null>(null)
  const [discover, setDiscover] = useState(false)
  const list = useMemo(() => q.data?.results ?? [], [q.data])
  const shown = list.filter((d) => matchDevice(d, search))
  const c = deviceCounts(list)
  const edit = can('devices:edit')
  const now = Date.now()

  return (
    <Page
      id="devices"
      wide
      subtitle={t('dev.sub')}
      actions={
        edit && (
          <>
            <Button onClick={() => setDiscover(true)}>
              <Radar size={15} /> {t('dev.discover')}
            </Button>
            <Button variant="primary" onClick={() => setAdding({})}>
              <Plus size={15} /> {t('dev.add')}
            </Button>
          </>
        )
      }
    >
      <p className="page-guide muted">
        {t('dev.guide')} {inventory && t('dev.guide.inventory')}
      </p>
      <div className="tiles tiles-5">
        <Tile label={t('tile.total')} icon={<Router size={16} />} value={num(c.total, locale)} />
        <Tile label={t('tile.up')} icon={<CheckCircle2 size={16} />} tone="ok" value={num(c.up, locale)} />
        <Tile label={t('tile.down')} icon={<WifiOff size={16} />} tone={c.down ? 'error' : undefined} value={num(c.down, locale)} />
        <Tile label={t('tile.error')} icon={<AlertTriangle size={16} />} tone={c.error ? 'warn' : undefined} value={num(c.error, locale)} />
        <Tile label={t('tile.clients')} icon={<Users size={16} />} value={num(c.clients, locale)} to="/clients" />
      </div>
      <section className="card toolbar-card">
        <label className="search-field">
          <Search size={16} />
          <input className="input" value={search} placeholder={t('dev.search')} onChange={(e) => setSearch(e.target.value)} />
        </label>
      </section>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      <section className="card flush-card">
        {q.isPending ? (
          <div className="status-card">
            <Loading />
          </div>
        ) : shown.length === 0 ? (
          <p className="muted empty-pad">{list.length ? t('dev.nomatch') : t('dev.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table m-cards">
              <thead>
                <tr>
                  <th>{t('col.device')}</th>
                  <th>{t('col.platform')}</th>
                  <th>{t('col.site')}</th>
                  <th>{t('col.status')}</th>
                  <th>{t('col.polled')}</th>
                  <th className="num">{t('col.ifaces')}</th>
                  <th className="num">{t('col.clients')}</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((d) => (
                  <tr key={d.id} className="clickable" onClick={() => nav(`/devices/${d.id}`)}>
                    <td className="m-name">
                      <div className="cell-main">{d.name}</div>
                      <div className="cell-sub">
                        <span className="mono">{d.host}</span>
                        {d.bound ? <Chip tone={d.inventory_missing ? 'warn' : 'ok'} title={t('bound.hint')}>{d.inventory_missing ? t('bound.missing') : t('bound')}</Chip> : <Chip tone="low">{t('standalone')}</Chip>}
                        {d.tags.map((x) => (
                          <span key={x} className="pill">
                            {x}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td data-label={t('col.platform')}>
                      <div>{d.platform_title}</div>
                      <div className="cell-sub">{[d.facts.model, d.transport.toUpperCase()].filter(Boolean).join(' · ')}</div>
                    </td>
                    <td data-label={t('col.site')}>
                      <div>{d.site || '—'}</div>
                      {d.role && <div className="cell-sub">{t(`role.${d.role}`) === `role.${d.role}` ? d.role : t(`role.${d.role}`)}</div>}
                    </td>
                    <td data-label={t('col.status')}>
                      <DeviceStatus d={d} />
                    </td>
                    <td data-label={t('col.polled')}>{d.last_poll_at ? relativeTime(d.last_poll_at, locale, now) : '—'}</td>
                    <td className="num" data-label={t('col.ifaces')}>
                      {d.counts.interfaces ? `${d.counts.interfaces_up}/${d.counts.interfaces}` : '—'}
                    </td>
                    <td className="num" data-label={t('col.clients')}>{num(d.counts.endpoints, locale)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {adding && <DeviceForm open onClose={() => setAdding(null)} inventory={inventory} prefill={adding} onSaved={(d) => nav(`/devices/${d.id}`)} />}
      {discover && (
        <DiscoverDialog
          onClose={() => setDiscover(false)}
          onUse={(f) => {
            setDiscover(false)
            setAdding({ ...emptyDraft(f.platforms[0] ?? ''), host: f.host, name: f.name })
          }}
        />
      )}
    </Page>
  )
}

function DiscoverDialog({ onClose, onUse }: { onClose: () => void; onUse: (f: Found) => void }) {
  const t = useT(devicesStrings)
  const nav = useNavigate()
  const [target, setTarget] = useState('')
  const [community, setCommunity] = useState('public')
  const scan = useMutation({ mutationFn: () => post<{ results: Found[] }>('/api/devices/discover', { target: target.trim(), community }) })
  return (
    <Modal
      open
      onClose={onClose}
      title={t('disc.title')}
      footer={
        <Button variant="primary" busy={scan.isPending} disabled={!target.trim()} onClick={() => scan.mutate()}>
          {!scan.isPending && <Radar size={15} />} {t('disc.run')}
        </Button>
      }
    >
      <div className="row wrap">
        <Field label={t('disc.target')}>{(id) => <Input id={id} value={target} placeholder="192.0.2.0/24" spellCheck={false} onChange={(e) => setTarget(e.target.value)} />}</Field>
        <Field label={t('disc.community')}>{(id) => <Input id={id} value={community} style={{ width: 140 }} onChange={(e) => setCommunity(e.target.value)} />}</Field>
      </div>
      {scan.error && <Banner kind="error" title={errorText(t, scan.error).message}>{errorText(t, scan.error).detail}</Banner>}
      {scan.data &&
        (scan.data.results.length === 0 ? (
          <p className="muted">{t('disc.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table compact">
              <thead>
                <tr>
                  <th>{t('disc.col.host')}</th>
                  <th>{t('disc.col.found')}</th>
                  <th>{t('disc.col.guess')}</th>
                  <th aria-label="" />
                </tr>
              </thead>
              <tbody>
                {scan.data.results.map((f) => (
                  <tr key={f.host}>
                    <td>
                      <div className="mono">{f.host}</div>
                      {f.name && <div className="cell-sub">{f.name}</div>}
                    </td>
                    <td className="cell-sub">{f.evidence.slice(0, 3).join(', ') || f.ports.join(', ')}</td>
                    <td>{f.platforms[0] ?? '—'}</td>
                    <td className="actions-col">
                      {f.known ? (
                        <Button size="sm" variant="ghost" onClick={() => nav(`/devices/${f.device_id}`)}>
                          {t('disc.known')}
                        </Button>
                      ) : (
                        <Button size="sm" onClick={() => onUse(f)}>
                          <Plus size={14} /> {t('disc.use')}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </Modal>
  )
}
