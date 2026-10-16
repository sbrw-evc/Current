import { useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Download, KeyRound, Pencil, Play, RefreshCw, Trash2 } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { del, post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { formatBps, num, relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Rows, Segmented, Select, Switch, Textarea } from '../../ui/ui'
import { useDevice, usePlatforms } from './api'
import { DeviceForm } from './DeviceForm'
import { DeviceStatus, useInventoryConnected } from './DevicesPage'
import { ClientsTable } from './ClientsPage'
import { uptimeText, visibleActions, type ActionResult, type DeviceDetail, type Iface } from './model'
import { devicesStrings } from './strings'
import './devices.css'

// Network → Devices → a device: what it reported (overview, interfaces with load, neighbours,
// clients, devices behind a controller) and the settings Current can apply on it.

type Tab = 'overview' | 'interfaces' | 'neighbors' | 'clients' | 'children' | 'actions'

export default function DevicePage() {
  const t = useT(devicesStrings)
  const { id = '0' } = useParams()
  const q = useDevice(Number(id))
  const [tab, setTab] = useState<Tab>('overview')
  const [editing, setEditing] = useState(false)
  const inventory = useInventoryConnected()
  const d = q.data
  const back = (
    <Link to="/devices" className="btn btn-ghost btn-sm">
      <ArrowLeft size={15} /> {t('detail.back')}
    </Link>
  )
  if (!d)
    return (
      <Page id="devices" actions={back}>
        {q.error ? <Banner kind="error" title={errorText(t, q.error).message} /> : <Loading />}
      </Page>
    )
  const tabs: { value: Tab; label: ReactNode }[] = [
    { value: 'overview', label: t('tab.overview') },
    { value: 'interfaces', label: `${t('tab.interfaces')} ${d.interfaces.length || ''}` },
    { value: 'neighbors', label: `${t('tab.neighbors')} ${d.neighbors.length || ''}` },
    { value: 'clients', label: `${t('tab.clients')} ${d.endpoints.length || ''}` },
  ]
  if (d.kind === 'controller' || d.children.length) tabs.push({ value: 'children', label: `${t('tab.children')} ${d.children.length || ''}` })
  tabs.push({ value: 'actions', label: t('tab.actions') })
  return (
    <Page
      id="devices"
      title={d.name}
      wide
      subtitle={
        <span className="row wrap">
          <DeviceStatus d={d} />
          <span className="mono">{d.host}</span>
          <span>{d.platform_title}</span>
          {d.bound ? <Chip tone={d.inventory_missing ? 'warn' : 'ok'} title={t('bound.hint')}>{d.inventory_missing ? t('bound.missing') : t('bound')}</Chip> : <Chip tone="low">{t('standalone')}</Chip>}
          {d.alerted && <Chip tone="error">{t('ov.alerted')}</Chip>}
        </span>
      }
      actions={<HeadActions d={d} onEdit={() => setEditing(true)} back={back} />}
    >
      {d.status !== 'up' && d.last_error && <Banner kind={d.status === 'down' ? 'error' : 'warn'} title={t(`status.${d.status}`)}>{d.last_error}</Banner>}
      <div className="device-tabs">
        <Segmented label={d.name} value={tab} options={tabs} onChange={setTab} />
      </div>
      {tab === 'overview' && <Overview d={d} />}
      {tab === 'interfaces' && <Interfaces list={d.interfaces} />}
      {tab === 'neighbors' && <Neighbors d={d} />}
      {tab === 'clients' && (
        <section className="card flush-card">
          {d.endpoints.length ? <ClientsTable list={d.endpoints} hideDevice /> : <p className="muted empty-pad">{t('none.clients')}</p>}
        </section>
      )}
      {tab === 'children' && <Children d={d} />}
      {tab === 'actions' && <Actions d={d} />}
      {editing && <DeviceForm open device={d} inventory={inventory} onClose={() => setEditing(false)} />}
    </Page>
  )
}

function HeadActions({ d, onEdit, back }: { d: DeviceDetail; onEdit: () => void; back: ReactNode }) {
  const t = useT(devicesStrings)
  const { can } = useSession()
  const qc = useQueryClient()
  const nav = useNavigate()
  const fail = (e: unknown) => notify('error', errorText(t, e).message, errorText(t, e).detail)
  const poll = useMutation({
    mutationFn: () => post<{ ok: boolean; error: string }>(`/api/devices/${d.id}/poll`),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      notify(r.ok ? 'ok' : 'warn', t('act.polled'), r.error || undefined)
    },
    onError: fail,
  })
  const remove = useMutation({
    mutationFn: () => del(`/api/devices/${d.id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      notify('ok', t('act.deleted'))
      nav('/devices')
    },
    onError: fail,
  })
  return (
    <>
      {back}
      {(can('devices:operate') || can('devices:admin')) && (
        <Button busy={poll.isPending} onClick={() => poll.mutate()}>
          {!poll.isPending && <RefreshCw size={15} />} {t('act.poll')}
        </Button>
      )}
      {can('devices:edit') && (
        <>
          <Button onClick={onEdit}>
            <Pencil size={15} /> {t('act.edit')}
          </Button>
          <Button variant="ghost" onClick={() => window.confirm(t('act.delete.confirm', { name: d.name })) && remove.mutate()} aria-label={t('act.delete')} title={t('act.delete')}>
            <Trash2 size={15} />
          </Button>
        </>
      )}
    </>
  )
}

function pct(v: number | null | undefined, locale: 'en' | 'ru') {
  return v == null ? '—' : `${num(v, locale, 1)} %`
}

function Overview({ d }: { d: DeviceDetail }) {
  const t = useT(devicesStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const qc = useQueryClient()
  const reset = useMutation({
    mutationFn: () => post(`/api/devices/${d.id}/reset-host-key`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      notify('ok', t('act.resetkey.done'))
    },
  })
  const f = d.facts
  const set = Object.entries(d.credentials.set).filter(([, v]) => v).map(([k]) => t(`field.${k}`))
  return (
    <div className="settings-grid">
      <Card title={t('ov.identity')}>
        <Rows
          rows={[
            [t('ov.hostname'), f.hostname || '—'],
            [t('ov.model'), [f.vendor || d.vendor, f.model].filter(Boolean).join(' ') || '—'],
            [t('ov.os'), [f.os, f.version].filter(Boolean).join(' ') || '—'],
            [t('ov.serial'), f.serial ? <span className="mono">{f.serial}</span> : '—'],
            [t('ov.mac'), f.mac ? <span className="mono">{f.mac}</span> : '—'],
            [t('form.site'), d.site || '—'],
            [t('form.role'), d.role || '—'],
            [t('ov.inventory'), d.bound ? <span className="mono">{d.source_ref}</span> : t('standalone')],
          ]}
        />
      </Card>
      <Card title={t('ov.health')}>
        <Rows
          rows={[
            [t('col.status'), <DeviceStatus key="s" d={d} />],
            [t('ov.uptime'), uptimeText(f.uptime_seconds, locale)],
            [t('ov.cpu'), pct(f.cpu_percent, locale)],
            [t('ov.memory'), pct(f.memory_percent, locale)],
            [t('ov.lastok'), d.last_ok_at ? `${formatDate(d.last_ok_at, locale)} (${relativeTime(d.last_ok_at, locale)})` : '—'],
            [t('col.ifaces'), `${d.counts.interfaces_up}/${d.counts.interfaces}`],
            [t('col.clients'), num(d.counts.endpoints, locale)],
          ]}
        />
      </Card>
      <Card title={t('ov.management')}>
        <Rows
          rows={[
            [t('ov.transport'), `${d.transport.toUpperCase()}${d.port ? `:${d.port}` : ''}`],
            [t('ov.poll'), d.enabled ? `${d.poll_seconds} ${t('form.sec')}` : t('status.disabled')],
            [t('ov.creds'), set.length ? set.join(', ') : '—'],
            ...(d.snmp_profile ? [[t('ov.snmp'), d.snmp_profile.name] as [string, string]] : []),
            [
              t('ov.hostkey'),
              d.ssh_host_key ? (
                <span className="row wrap" key="k">
                  <span className="mono">{d.ssh_host_key}</span>
                  {can('devices:edit') && (
                    <Button size="sm" variant="ghost" busy={reset.isPending} onClick={() => reset.mutate()}>
                      <KeyRound size={14} /> {t('act.resetkey')}
                    </Button>
                  )}
                </span>
              ) : (
                <span className="muted">{t('ov.hostkey.none')}</span>
              ),
            ],
          ]}
        />
        {d.note && <p className="hint">{d.note}</p>}
      </Card>
      <Card title={t('ov.flow')}>
        <Rows
          rows={[
            [t('ov.exporter'), d.exporter_ips.length ? <span className="mono">{d.exporter_ips.slice(0, 6).join(', ')}</span> : '—'],
            [t('p.collector'), d.collector.ip ? <span className="mono">{`${d.collector.ip}:${d.collector.netflow_port}`}</span> : <span className="muted">{t('p.collector.unknown')}</span>],
          ]}
        />
        {can('exporters:view') && (
          <Link className="btn btn-ghost btn-sm" to="/exporters">
            {t('ov.exporter.link')}
          </Link>
        )}
      </Card>
    </div>
  )
}

export function Load({ i }: { i: Iface }) {
  const { locale } = useLocale()
  const u = i.utilization ?? 0
  const tone = u >= 85 ? 'error' : u >= 60 ? 'warn' : 'ok'
  if (i.utilization == null) return <span className="muted">—</span>
  return (
    <div className="util">
      <span className="util-value">{num(u, locale, 1)} %</span>
      <span className={`util-bar tone-${tone}`}>
        <span style={{ width: `${Math.min(100, u)}%` }} />
      </span>
    </div>
  )
}

function Interfaces({ list }: { list: Iface[] }) {
  const t = useT(devicesStrings)
  const { locale } = useLocale()
  if (!list.length) return <p className="muted card empty-pad">{t('none.interfaces')}</p>
  return (
    <section className="card flush-card">
      <div className="table-wrap">
        <table className="data-table compact m-cards">
          <thead>
            <tr>
              <th>{t('if.name')}</th>
              <th>{t('if.state')}</th>
              <th className="num">{t('if.speed')}</th>
              <th className="num">{t('if.rx')}</th>
              <th className="num">{t('if.tx')}</th>
              <th>{t('if.load')}</th>
              <th>{t('if.addresses')}</th>
            </tr>
          </thead>
          <tbody>
            {list.map((i) => (
              <tr key={i.name}>
                <td className="m-name">
                  <div className="mono">{i.name}</div>
                  {i.description && <div className="cell-sub">{i.description}</div>}
                </td>
                <td data-label={t('if.state')}>
                  {i.admin_up === false ? <Chip tone="off">{t('if.admindown')}</Chip> : i.oper_up ? <Chip tone="ok">{t('if.up')}</Chip> : i.oper_up === false ? <Chip tone="error">{t('if.down')}</Chip> : '—'}
                </td>
                <td className="num" data-label={t('if.speed')}>{i.speed_mbps ? formatBps(i.speed_mbps * 1e6, locale) : '—'}</td>
                <td className="num" data-label={t('if.rx')}>{i.rx_bps != null ? formatBps(i.rx_bps, locale) : '—'}</td>
                <td className="num" data-label={t('if.tx')}>{i.tx_bps != null ? formatBps(i.tx_bps, locale) : '—'}</td>
                <td data-label={t('if.load')}>
                  <Load i={i} />
                </td>
                <td className="mono cell-sub" data-label={t('if.addresses')}>{(i.addresses ?? []).join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Neighbors({ d }: { d: DeviceDetail }) {
  const t = useT(devicesStrings)
  if (!d.neighbors.length) return <p className="muted card empty-pad">{t('none.neighbors')}</p>
  return (
    <section className="card flush-card">
      <div className="table-wrap">
        <table className="data-table compact m-cards">
          <thead>
            <tr>
              <th>{t('nb.local')}</th>
              <th>{t('nb.remote')}</th>
              <th>{t('nb.port')}</th>
              <th>{t('nb.platform')}</th>
              <th>{t('nb.protocol')}</th>
            </tr>
          </thead>
          <tbody>
            {d.neighbors.map((n, i) => (
              <tr key={i}>
                <td className="mono">{n.local_interface}</td>
                <td className="m-name">
                  <div className="cell-main">{n.remote_name || n.remote_ip || n.remote_mac}</div>
                  <div className="cell-sub mono">{[n.remote_ip, n.remote_mac].filter(Boolean).join(' · ')}</div>
                </td>
                <td className="mono" data-label={t('nb.port')}>{n.remote_interface || '—'}</td>
                <td data-label={t('nb.platform')}>{n.remote_platform || '—'}</td>
                <td data-label={t('nb.protocol')}>
                  <Chip tone="info" dot={false}>
                    {n.protocol.toUpperCase()}
                  </Chip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Children({ d }: { d: DeviceDetail }) {
  const t = useT(devicesStrings)
  if (!d.children.length) return <p className="muted card empty-pad">{t('none.children')}</p>
  return (
    <section className="card flush-card">
      <div className="table-wrap">
        <table className="data-table compact m-cards">
          <thead>
            <tr>
              <th>{t('ch.name')}</th>
              <th>{t('ch.kind')}</th>
              <th>{t('col.status')}</th>
              <th>{t('ch.uplink')}</th>
              <th className="num">{t('ch.clients')}</th>
            </tr>
          </thead>
          <tbody>
            {d.children.map((c) => (
              <tr key={c.mac}>
                <td className="m-name">
                  <div className="cell-main">{c.name || c.mac}</div>
                  <div className="cell-sub mono">{[c.ip, c.mac, c.model].filter(Boolean).join(' · ')}</div>
                </td>
                <td data-label={t('ch.kind')}>{c.kind}</td>
                <td data-label={t('col.status')}>
                  <Chip tone={c.online ? 'ok' : 'error'}>{t(c.online ? 'status.online' : 'status.offline')}</Chip>
                </td>
                <td className="mono" data-label={t('ch.uplink')}>{[c.uplink_mac, c.uplink_port].filter(Boolean).join(' · ') || '—'}</td>
                <td className="num" data-label={t('ch.clients')}>{c.clients ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

const csv = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

function Actions({ d }: { d: DeviceDetail }) {
  const t = useT(devicesStrings)
  const { can } = useSession()
  const platforms = usePlatforms()
  const admin = platforms.data?.admin_actions ?? ['reboot', 'command', 'backup']
  const list = visibleActions(d.capabilities, admin, { operate: can('devices:operate'), admin: can('devices:admin') })
  const backup = d.capabilities.includes('backup') && can('devices:admin')
  if (!list.length && !backup) return <p className="muted card empty-pad">{t('err.unsupported_action')}</p>
  return (
    <div className="settings-grid">
      {list.map((a) => (
        <ActionCard key={a} d={d} action={a} admin={admin.includes(a)} protocols={platforms.data?.flow_protocols ?? ['netflow9', 'ipfix', 'sflow']} />
      ))}
      {backup && (
        <Card title={t('act.backup')} actions={<Chip tone="purple" dot={false}>{t('act.admin')}</Chip>}>
          <a className="btn btn-secondary" href={`/api/devices/${d.id}/backup`} download>
            <Download size={15} /> {t('act.backup')}
          </a>
        </Card>
      )}
    </div>
  )
}

function ActionCard({ d, action, admin, protocols }: { d: DeviceDetail; action: string; admin: boolean; protocols: string[] }) {
  const t = useT(devicesStrings)
  const qc = useQueryClient()
  const [p, setP] = useState({ name: '', enabled: true, description: '', servers: '', protocol: protocols.includes('ipfix') ? 'ipfix' : protocols[0], command: '' })
  const set = (x: Partial<typeof p>) => setP({ ...p, ...x })
  const params = () => {
    switch (action) {
      case 'hostname':
        return { name: p.name.trim() }
      case 'interface':
        return { name: p.name.trim(), enabled: p.enabled, ...(p.description ? { description: p.description } : {}) }
      case 'dns':
      case 'ntp':
        return { servers: csv(p.servers) }
      case 'flow_export':
        return { enabled: p.enabled, protocol: p.protocol }
      case 'command':
        return { command: p.command }
      default:
        return {}
    }
  }
  const run = useMutation({
    mutationFn: () => post<ActionResult>(`/api/devices/${d.id}/actions`, { action, params: params() }),
    onSuccess: () => {
      notify('ok', t('act.done'))
      qc.invalidateQueries({ queryKey: ['devices'] })
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const go = () => (action !== 'reboot' || window.confirm(t('act.reboot.confirm', { name: d.name }))) && run.mutate()
  return (
    <Card title={t(`act.${action}`)} actions={admin ? <Chip tone="purple" dot={false}>{t('act.admin')}</Chip> : undefined}>
      <div className="stack">
        {(action === 'hostname' || action === 'interface') && (
          <Field label={action === 'hostname' ? t('p.name') : t('p.iface')}>
            {(id) =>
              action === 'interface' && d.interfaces.length ? (
                <Select id={id} value={p.name} onChange={(e) => set({ name: e.target.value })}>
                  <option value="">—</option>
                  {d.interfaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                    </option>
                  ))}
                </Select>
              ) : (
                <Input id={id} value={p.name} onChange={(e) => set({ name: e.target.value })} />
              )
            }
          </Field>
        )}
        {action === 'interface' && (
          <>
            <Switch checked={p.enabled} onChange={(v) => set({ enabled: v })} label={t('p.enabled')} />
            <Field label={t('p.description')}>{(id) => <Input id={id} value={p.description} onChange={(e) => set({ description: e.target.value })} />}</Field>
          </>
        )}
        {(action === 'dns' || action === 'ntp') && (
          <Field label={t('p.servers')} hint={t('p.servers.hint')}>
            {(id) => <Input id={id} value={p.servers} placeholder={action === 'dns' ? '1.1.1.1, 8.8.8.8' : 'pool.ntp.org'} onChange={(e) => set({ servers: e.target.value })} />}
          </Field>
        )}
        {action === 'flow_export' && (
          <>
            <p className="hint">{d.collector.ip ? t('p.collector.auto', { ip: d.collector.ip, port: p.protocol === 'sflow' ? d.collector.sflow_port : d.collector.netflow_port }) : t('p.collector.unknown')}</p>
            <Segmented label={t('p.protocol')} value={p.protocol} options={protocols.map((x) => ({ value: x, label: x === 'ipfix' ? 'IPFIX' : x === 'sflow' ? 'sFlow' : x.replace('netflow', 'NetFlow v') }))} onChange={(v) => set({ protocol: v })} />
            <Switch checked={p.enabled} onChange={(v) => set({ enabled: v })} label={t('p.enabled')} />
          </>
        )}
        {action === 'command' && <Field label={t('p.command')}>{(id) => <Textarea id={id} rows={2} className="mono" value={p.command} spellCheck={false} onChange={(e) => set({ command: e.target.value })} />}</Field>}
        <div className="card-actions">
          <Button variant={action === 'reboot' ? 'danger' : 'primary'} busy={run.isPending} disabled={action === 'flow_export' && !d.collector.ip} onClick={go}>
            {!run.isPending && <Play size={14} />} {action === 'reboot' ? t('act.reboot') : t('act.run')}
          </Button>
        </div>
        {run.data?.output && (
          <details open={action === 'command'}>
            <summary>{t('act.output')}</summary>
            <pre className="action-output">{run.data.output}</pre>
          </details>
        )}
      </div>
    </Card>
  )
}
