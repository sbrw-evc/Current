import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Ban, Pencil, Search, Trash2, Undo2, Wifi } from 'lucide-react'
import { Link } from 'react-router-dom'
import { del, patch, post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { num, relativeTime } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Chip, Field, Input, Loading, Modal, Segmented, Textarea } from '../../ui/ui'
import { useClients } from './api'
import { matchClient, statusTone, type Client } from './model'
import { devicesStrings } from './strings'
import './devices.css'

// Network → Clients: the hosts the managed devices see, merged by MAC.

type Filter = 'all' | 'online' | 'offline'

export default function ClientsPage() {
  const t = useT(devicesStrings)
  const { locale } = useLocale()
  const q = useClients()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const list = useMemo(() => q.data?.results ?? [], [q.data])
  const shown = list.filter((c) => matchClient(c, search) && (filter === 'all' || c.online === (filter === 'online')))
  const online = list.filter((c) => c.online).length
  return (
    <Page id="clients" wide subtitle={t('cl.sub')}>
      <section className="card toolbar-card row wrap">
        <label className="search-field">
          <Search size={16} />
          <input className="input" value={search} placeholder={t('cl.search')} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <Segmented
          label={t('cl.all')}
          value={filter}
          options={[
            { value: 'all', label: `${t('cl.all')} ${num(list.length, locale)}` },
            { value: 'online', label: `${t('cl.online')} ${num(online, locale)}` },
            { value: 'offline', label: `${t('cl.offline')} ${num(list.length - online, locale)}` },
          ]}
          onChange={setFilter}
        />
      </section>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      <section className="card flush-card">
        {q.isPending ? (
          <div className="status-card">
            <Loading />
          </div>
        ) : shown.length === 0 ? (
          <p className="muted empty-pad">{list.length ? t('dev.nomatch') : t('cl.empty')}</p>
        ) : (
          <ClientsTable list={shown} />
        )}
      </section>
    </Page>
  )
}

export function ClientsTable({ list, hideDevice }: { list: Client[]; hideDevice?: boolean }) {
  const t = useT(devicesStrings)
  const { locale } = useLocale()
  const { can } = useSession()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<Client | null>(null)
  const fail = (e: unknown) => notify('error', errorText(t, e).message, errorText(t, e).detail)
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['endpoints'] })
    qc.invalidateQueries({ queryKey: ['devices'] })
  }
  const block = useMutation({
    mutationFn: (c: Client) => post<{ device_name: string }>(`/api/endpoints/${c.mac}/block`, { blocked: !c.blocked }).then((r) => ({ r, c })),
    onSuccess: ({ r, c }) => {
      notify('ok', t(c.blocked ? 'cl.unblocked.done' : 'cl.blocked.done', { device: r.device_name }))
      refresh()
    },
    onError: fail,
  })
  const forget = useMutation({ mutationFn: (c: Client) => del(`/api/endpoints/${c.mac}`), onSuccess: refresh, onError: fail })
  const edit = can('devices:edit')
  const operate = can('devices:operate') || can('devices:admin')
  const now = Date.now()
  return (
    <div className="table-wrap">
      <table className="data-table m-cards">
        <thead>
          <tr>
            <th>{t('cl.col.client')}</th>
            <th>{t('cl.col.address')}</th>
            <th>{t('cl.col.where')}</th>
            <th>{t('cl.col.vendor')}</th>
            <th>{t('cl.col.seen')}</th>
            {(edit || operate) && <th aria-label="" />}
          </tr>
        </thead>
        <tbody>
          {list.map((c) => (
            <tr key={c.mac}>
              <td className="m-name">
                <div className="cell-main">
                  {c.name || <span className="muted">{c.mac}</span>} {c.blocked && <Chip tone="error">{t('cl.blocked')}</Chip>}
                </div>
                <div className="cell-sub">
                  <span className="mono">{c.mac}</span>
                  {c.note && <span>{c.note}</span>}
                </div>
              </td>
              <td className="mono" data-label={t('cl.col.address')}>{c.ip || '—'}</td>
              <td data-label={t('cl.col.where')}>
                {!hideDevice && c.device_id ? <Link to={`/devices/${c.device_id}`}>{c.device_name}</Link> : null}
                <div className="cell-sub">
                  <Chip tone="info" dot={false}>
                    {t(`src.${c.source}`)}
                  </Chip>
                  {c.ssid && (
                    <span>
                      <Wifi size={12} /> {c.ssid}
                      {c.signal != null && ` ${c.signal} dBm`}
                    </span>
                  )}
                  {(c.port || c.interface) && <span className="mono">{c.port || c.interface}</span>}
                  {c.vlan != null && <span>VLAN {c.vlan}</span>}
                </div>
              </td>
              <td data-label={t('cl.col.vendor')}>{c.vendor || '—'}</td>
              <td data-label={t('cl.col.seen')}>
                <Chip tone={statusTone(c.online ? 'online' : 'offline')}>{c.online ? t('status.online') : relativeTime(c.last_seen, locale, now)}</Chip>
              </td>
              {(edit || operate) && (
                <td className="actions-col">
                  {edit && (
                    <button type="button" className="icon-btn" title={t('cl.edit')} aria-label={t('cl.edit')} onClick={() => setEditing(c)}>
                      <Pencil size={15} />
                    </button>
                  )}
                  {operate && (
                    <button type="button" className="icon-btn" title={t(c.blocked ? 'cl.unblock' : 'cl.block')} aria-label={t(c.blocked ? 'cl.unblock' : 'cl.block')} onClick={() => block.mutate(c)}>
                      {c.blocked ? <Undo2 size={15} /> : <Ban size={15} />}
                    </button>
                  )}
                  {edit && (
                    <button type="button" className="icon-btn" title={t('cl.forget')} aria-label={t('cl.forget')} onClick={() => window.confirm(t('cl.forget.confirm', { name: c.name || c.mac })) && forget.mutate(c)}>
                      <Trash2 size={15} />
                    </button>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {editing && <RenameDialog c={editing} onClose={() => setEditing(null)} onSaved={refresh} />}
    </div>
  )
}

function RenameDialog({ c, onClose, onSaved }: { c: Client; onClose: () => void; onSaved: () => void }) {
  const t = useT(devicesStrings)
  const [alias, setAlias] = useState(c.alias)
  const [note, setNote] = useState(c.note)
  const save = useMutation({
    mutationFn: () => patch(`/api/endpoints/${c.mac}`, { alias, note }),
    onSuccess: () => {
      onSaved()
      onClose()
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  return (
    <Modal
      open
      onClose={onClose}
      title={c.name || c.mac}
      footer={
        <Button variant="primary" busy={save.isPending} onClick={() => save.mutate()}>
          {t('form.save')}
        </Button>
      }
    >
      <Field label={t('cl.alias')}>{(id) => <Input id={id} value={alias} placeholder={c.hostname} onChange={(e) => setAlias(e.target.value)} />}</Field>
      <Field label={t('cl.note')}>{(id) => <Textarea id={id} rows={2} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
    </Modal>
  )
}
