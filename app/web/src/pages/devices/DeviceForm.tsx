import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, PlugZap, Search, XCircle } from 'lucide-react'
import { patch, post } from '../../api/client'
import { errorText, useT } from '../../i18n'
import { notify } from '../../ui/notify'
import { SecretField } from '../../ui/SecretField'
import { Banner, Button, Chip, Field, Input, Modal, Segmented, Select, Stepper, Switch, Textarea } from '../../ui/ui'
import { useCandidates, usePlatforms } from './api'
import { credentialFields, draftOf, emptyDraft, fromCandidate, inputOf, validateDraft, type Device, type DeviceDraft, type TestResult } from './model'
import { devicesStrings } from './strings'

// DeviceForm adds or edits a device. With Inventory DB connected a new device is picked from the
// Inventory DB devices not managed yet, and a bound device's name, site and role are read-only.
export function DeviceForm({ open, onClose, device, inventory, prefill, onSaved }: { open: boolean; onClose: () => void; device?: Device; inventory: boolean; prefill?: Partial<DeviceDraft>; onSaved?: (d: Device) => void }) {
  const t = useT(devicesStrings)
  const qc = useQueryClient()
  const creating = !device
  const platforms = usePlatforms()
  const list = useMemo(() => platforms.data?.platforms ?? [], [platforms.data])
  const [draft, setDraft] = useState<DeviceDraft>(() => (device ? draftOf(device) : { ...emptyDraft(), ...prefill }))
  const set = (p: Partial<DeviceDraft>) => setDraft((d) => ({ ...d, ...p }))
  const platform = list.find((p) => p.key === draft.platform)
  const transport = draft.transport || platform?.transports[0]?.name || ''
  const bound = device ? device.bound : !!draft.inventory_id
  const problems = validateDraft(draft, { inventory, creating, platform })
  const fields = credentialFields(platform, transport, draft.snmp_source)
  const hasSnmp = platform?.credentials.some((f) => f.startsWith('snmp_')) ?? false

  const save = useMutation({
    mutationFn: () => {
      const body = inputOf({ ...draft, transport }, { bound, creating })
      return creating ? post<Device>('/api/devices', body) : patch<Device>(`/api/devices/${device.id}`, body)
    },
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      notify('ok', t(creating ? 'form.created' : 'form.saved'))
      onSaved?.(d)
      onClose()
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const test = useMutation({
    mutationFn: () => post<TestResult>('/api/devices/test', { ...inputOf({ ...draft, transport }, { bound: true, creating: true }), ...(device ? { id: device.id } : {}) }),
  })

  const port = platform?.transports.find((x) => x.name === transport)?.port
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t(creating ? 'form.title.add' : 'form.title.edit')}
      footer={
        <>
          <Button busy={test.isPending} disabled={problems.some((p) => p !== 'form.err.inventory')} onClick={() => test.mutate()}>
            {!test.isPending && <PlugZap size={15} />}
            {t('form.test')}
          </Button>
          <Button variant="primary" busy={save.isPending} disabled={problems.length > 0} onClick={() => save.mutate()}>
            {t(creating ? 'form.create' : 'form.save')}
          </Button>
        </>
      }
    >
      {creating && inventory && <CandidatePicker selected={draft.inventory_id} onPick={(c) => setDraft((d) => ({ ...fromCandidate(c, list), secrets: d.secrets, plain: d.plain }))} />}
      <div className="row wrap">
        <Field label={t('form.platform')}>
          {(id) => (
            <Select id={id} value={draft.platform} onChange={(e) => set({ platform: e.target.value, transport: '' })}>
              <option value="">{t('form.platform.pick')}</option>
              {list.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {platform && platform.transports.length > 1 && (
          <Segmented label={t('form.transport')} value={transport} options={platform.transports.map((x) => ({ value: x.name, label: x.name.toUpperCase() }))} onChange={(v) => set({ transport: v })} />
        )}
      </div>
      {platform?.hint && <p className="hint">{platform.hint}</p>}
      <div className="row wrap">
        <Field label={t('form.host')}>{(id) => <Input id={id} value={draft.host} placeholder="192.0.2.1" spellCheck={false} onChange={(e) => set({ host: e.target.value })} />}</Field>
        <Field label={t('form.port')} hint={port ? t('form.port.hint', { port }) : undefined}>
          {(id) => <Input id={id} value={draft.port} inputMode="numeric" style={{ width: 110 }} onChange={(e) => set({ port: e.target.value })} />}
        </Field>
      </div>
      {(transport === 'https' || transport === 'api') && <Switch checked={draft.verify_tls} onChange={(v) => set({ verify_tls: v })} label={t('form.verify_tls')} />}
      {platform?.kind === 'controller' && <Field label={t('form.site_ctl')}>{(id) => <Input id={id} value={draft.controller_site} onChange={(e) => set({ controller_site: e.target.value })} />}</Field>}
      {bound ? (
        <div className="row wrap">
          <Chip tone="ok" title={t('bound.hint')}>
            {t('bound')}
          </Chip>
          <span>{draft.name}</span>
          {draft.site && <span className="muted">{draft.site}</span>}
          {draft.role && <span className="muted">{draft.role}</span>}
        </div>
      ) : (
        !inventory && (
          <div className="row wrap">
            <Field label={t('form.name')} hint={t('form.name.hint')}>
              {(id) => <Input id={id} value={draft.name} onChange={(e) => set({ name: e.target.value })} />}
            </Field>
            <Field label={t('form.site')}>{(id) => <Input id={id} value={draft.site} onChange={(e) => set({ site: e.target.value })} />}</Field>
            <Field label={t('form.role')}>
              {(id) => (
                <Select id={id} value={draft.role} onChange={(e) => set({ role: e.target.value })}>
                  <option value="">—</option>
                  {(platforms.data?.roles ?? []).map((r) => (
                    <option key={r} value={r}>
                      {t(`role.${r}`)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
        )
      )}

      {platform && (fields.length > 0 || hasSnmp) && (
        <fieldset className="plain-fieldset stack">
          <legend className="field-label">{t('form.creds')}</legend>
          <p className="hint">{t('form.creds.hint')}</p>
          {hasSnmp && transport === 'snmp' && (
            <Segmented
              label={t('form.snmp_source')}
              value={draft.snmp_source}
              options={[
                { value: 'own', label: t('form.snmp_source.own') },
                { value: 'profile', label: t('form.snmp_source.profile'), title: t('form.snmp_source.hint') },
              ]}
              onChange={(v) => set({ snmp_source: v })}
            />
          )}
          {draft.snmp_source === 'profile' && transport === 'snmp' && <p className="hint">{t('form.snmp_source.hint')}</p>}
          <div className="form-grid-2">
            {fields.map((f) =>
              platforms.data?.secret_fields.includes(f) ? (
                <div key={f} className="stack-tight">
                  {f === 'private_key' ? (
                    <Field label={t(`field.${f}`)}>{(id) => <Textarea id={id} rows={3} spellCheck={false} value={draft.secrets[f] ?? ''} placeholder={device?.credentials.set[f] ? '••••••••' : ''} onChange={(e) => set({ secrets: { ...draft.secrets, [f]: e.target.value } })} />}</Field>
                  ) : (
                    <SecretField label={t(`field.${f}`)} value={draft.secrets[f] ?? ''} isSet={!!device?.credentials.set[f] && !draft.clear.includes(f)} onChange={(v) => set({ secrets: { ...draft.secrets, [f]: v } })} />
                  )}
                  {device?.credentials.set[f] && (
                    <label className="check-inline">
                      <input type="checkbox" checked={draft.clear.includes(f)} onChange={(e) => set({ clear: e.target.checked ? [...draft.clear, f] : draft.clear.filter((x) => x !== f) })} /> {draft.clear.includes(f) ? t('form.cleared') : t('form.clear')}
                    </label>
                  )}
                </div>
              ) : f === 'snmp_version' ? (
                <Segmented key={f} label={t(`field.${f}`)} value={draft.plain[f] || '2c'} options={['1', '2c', '3'].map((v) => ({ value: v, label: `v${v}` }))} onChange={(v) => set({ plain: { ...draft.plain, [f]: v } })} />
              ) : f === 'snmp_auth_protocol' || f === 'snmp_priv_protocol' ? (
                <Field key={f} label={t(`field.${f}`)}>
                  {(id) => (
                    <Select id={id} value={draft.plain[f] ?? ''} onChange={(e) => set({ plain: { ...draft.plain, [f]: e.target.value } })}>
                      <option value="">—</option>
                      {(f === 'snmp_auth_protocol' ? platforms.data?.snmp_auth_protocols : platforms.data?.snmp_priv_protocols)?.map((x) => (
                        <option key={x} value={x}>
                          {x.toUpperCase()}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
              ) : (
                <Field key={f} label={t(`field.${f}`)}>{(id) => <Input id={id} value={draft.plain[f] ?? ''} autoComplete="off" onChange={(e) => set({ plain: { ...draft.plain, [f]: e.target.value } })} />}</Field>
              ),
            )}
          </div>
        </fieldset>
      )}

      <div className="row wrap">
        <Field label={t('form.poll')}>{(id) => <Stepper id={id} value={draft.poll_seconds} min={60} max={86400} suffix={t('form.sec')} onChange={(v) => set({ poll_seconds: v })} />}</Field>
        <Field label={t('form.exporter')} hint={t('form.exporter.hint')}>
          {(id) => <Input id={id} value={draft.flow_exporter_ip} spellCheck={false} onChange={(e) => set({ flow_exporter_ip: e.target.value })} />}
        </Field>
      </div>
      <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })} label={t('form.enabled')} />
      <div className="row wrap">
        <Field label={t('form.tags')} hint={t('form.tags.hint')}>{(id) => <Input id={id} value={draft.tags} onChange={(e) => set({ tags: e.target.value })} />}</Field>
      </div>
      <Field label={t('form.note')}>{(id) => <Textarea id={id} rows={2} value={draft.note} onChange={(e) => set({ note: e.target.value })} />}</Field>

      {problems.filter((p) => draft.platform || p === 'form.err.platform').slice(0, 2).map((p) => (
        <Banner key={p} kind="warn" title={t(p)} />
      ))}
      {test.data && (
        <div className="test-result good">
          <CheckCircle2 size={16} />
          <span>
            {t('form.test.ok', { model: [test.data.facts.vendor, test.data.facts.model].filter(Boolean).join(' ') || test.data.facts.hostname || draft.host, ifaces: test.data.interfaces, clients: test.data.endpoints })}
            {test.data.host_key && <span className="muted"> · {t('form.test.key', { key: test.data.host_key })}</span>}
          </span>
        </div>
      )}
      {test.error && (
        <div className="test-result bad">
          <XCircle size={16} />
          <span>
            {errorText(t, test.error).message} {errorText(t, test.error).detail}
          </span>
        </div>
      )}
    </Modal>
  )
}

function CandidatePicker({ selected, onPick }: { selected: number | null; onPick: (c: NonNullable<ReturnType<typeof useCandidates>['data']>['devices'][number]) => void }) {
  const t = useT(devicesStrings)
  const q = useCandidates(true)
  const [search, setSearch] = useState('')
  const all = q.data?.devices ?? []
  const s = search.trim().toLowerCase()
  const shown = (s ? all.filter((c) => [c.name, c.host, c.site, c.model, c.manufacturer].some((v) => v.toLowerCase().includes(s))) : all).slice(0, 50)
  return (
    <div className="stack-tight">
      <span className="field-label">{t('form.inventory')}</span>
      <p className="hint">{t('form.inventory.hint')}</p>
      <label className="search-field">
        <Search size={16} />
        <input className="input" value={search} placeholder={t('form.inventory.search')} onChange={(e) => setSearch(e.target.value)} />
      </label>
      {q.data && !q.data.loaded ? (
        <p className="muted">{t('form.inventory.loading')}</p>
      ) : shown.length === 0 ? (
        <p className="muted">{t('form.inventory.none')}</p>
      ) : (
        <div className="pick-list" role="listbox" aria-label={t('form.inventory')}>
          {shown.map((c) => (
            <button key={c.id} type="button" role="option" aria-selected={selected === c.id} className={`pick-item ${selected === c.id ? 'active' : ''}`} onClick={() => onPick(c)}>
              <span className="cell-main">{c.name}</span>
              <span className="cell-sub">
                {c.host && <span className="mono">{c.host}</span>}
                {c.site && <span>{c.site}</span>}
                {(c.manufacturer || c.model) && <span>{[c.manufacturer, c.model].filter(Boolean).join(' ')}</span>}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
