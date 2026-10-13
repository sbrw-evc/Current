import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, KeyRound, LockKeyhole, Plus, PlugZap, Save, Trash2, XCircle } from 'lucide-react'
import { get, post, put } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { SecretField } from '../../ui/SecretField'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Select, Stepper, Switch, Textarea } from '../../ui/ui'
import { gnmiBody, gnmiProfileBody, newGnmiProfile, toGnmiDraft, validateGnmi, type GnmiDraft, type GnmiEncoding, type GnmiProfileDraft, type GnmiView } from './GnmiModel'
import { validAddress } from './SnmpModel'

// Settings → gNMI (docs/api.md, "gNMI"): interface names, descriptions and speeds read over gNMI
// (OpenConfig) for exporters Inventory DB does not describe. Passwords and CA certificates go to
// OpenBao and are never shown again.

const strings: Dict = {
  en: {
    'gnmi.sub': 'Interface names and speeds over gNMI (OpenConfig) for devices that Inventory DB does not describe',
    'gnmi.polling': 'Polling',
    'gnmi.enabled': 'Poll devices over gNMI',
    'gnmi.enabled.hint': 'Used after Inventory DB and the interface data the exporters send, and before SNMP: when both answer, gNMI wins and SNMP fills what it lacks.',
    'gnmi.exporters': 'Poll the exporters seen in flows',
    'gnmi.exporters.hint': 'Only exporters inside the prefixes of a credential profile are polled.',
    'gnmi.devices': 'Additional devices',
    'gnmi.devices.hint': 'Addresses polled even before they send flows, one per line.',
    'gnmi.interval': 'Refresh every',
    'gnmi.ttl': 'Keep data of a silent device for',
    'gnmi.timeout': 'Request timeout',
    'gnmi.concurrency': 'Parallel polls',
    'gnmi.min': 'min',
    'gnmi.sec': 's',
    'gnmi.profiles': 'Credential profiles',
    'gnmi.profiles.hint': 'A device uses the first profile whose prefixes contain its address; a profile without prefixes matches every device.',
    'gnmi.add': 'Add profile',
    'gnmi.name': 'Name',
    'gnmi.port': 'Port',
    'gnmi.encoding': 'Encoding',
    'gnmi.encoding.hint': 'A device rejecting JSON_IETF is asked again with JSON.',
    'gnmi.prefixes': 'Devices (prefixes)',
    'gnmi.user': 'User name',
    'gnmi.user.hint': 'Sent in the username / password metadata of each request; empty = no authentication.',
    'gnmi.password': 'Password',
    'gnmi.tls': 'TLS',
    'gnmi.tls.hint': 'Without TLS the password travels in clear text.',
    'gnmi.skip': 'Do not verify the device certificate',
    'gnmi.servername': 'Certificate name',
    'gnmi.servername.hint': 'Expected name in the device certificate; empty = its address.',
    'gnmi.ca': 'CA certificate (PEM)',
    'gnmi.ca.hint': 'Empty = the system trust store. Saved to OpenBao and never shown again.',
    'gnmi.ca.set': 'set · kept in OpenBao',
    'gnmi.ca.replace': 'Replace',
    'gnmi.ca.remove': 'Remove',
    'gnmi.ca.keep': 'Keep the saved one',
    'gnmi.ca.removed': 'The saved CA certificate is removed on save.',
    'gnmi.optional': 'optional',
    'gnmi.test': 'Poll a device',
    'gnmi.test.address': 'Device address',
    'gnmi.test.run': 'Poll',
    'gnmi.test.ok': '{n} interfaces',
    'gnmi.test.fail': 'Poll failed',
    'gnmi.save': 'Save',
    'gnmi.saved': 'gNMI settings saved',
    'gnmi.status': 'Polled devices',
    'gnmi.status.none': 'No device polled yet.',
    'gnmi.status.remote': 'The poller runs with the enricher in another process: its state is on the System status page.',
    'gnmi.col.device': 'Device',
    'gnmi.col.profile': 'Profile',
    'gnmi.col.ifaces': 'Interfaces',
    'gnmi.col.polled': 'Polled',
    'gnmi.col.idx': 'ifindex',
    'gnmi.col.name': 'Name',
    'gnmi.col.descr': 'Description',
    'gnmi.col.speed': 'Speed',
    'gnmi.err.device': 'Additional devices must be IP addresses',
    'gnmi.err.ttl': 'The keep time must not be shorter than the refresh period',
    'gnmi.err.name': 'Every profile needs a name',
    'gnmi.err.dup': 'Profile names must be unique',
    'gnmi.err.prefix': 'Profile devices must be addresses or prefixes',
    'gnmi.err.port': 'The port must be between 1 and 65535',
    'gnmi.err.password': 'A profile with a user name needs its password',
    'gnmi.err.ca': 'The CA certificate must be a PEM certificate',
  },
  ru: {
    'gnmi.sub': 'Имена и скорости интерфейсов по gNMI (OpenConfig) для устройств, которых нет в Inventory DB',
    'gnmi.polling': 'Опрос',
    'gnmi.enabled': 'Опрашивать устройства по gNMI',
    'gnmi.enabled.hint': 'Используется после Inventory DB и данных об интерфейсах от экспортёров и перед SNMP: если отвечают оба, приоритет у gNMI, а SNMP дополняет недостающее.',
    'gnmi.exporters': 'Опрашивать экспортёры из потоков',
    'gnmi.exporters.hint': 'Опрашиваются только экспортёры внутри префиксов профиля учётных данных.',
    'gnmi.devices': 'Дополнительные устройства',
    'gnmi.devices.hint': 'Адреса, которые опрашиваются ещё до прихода потоков, по одному в строке.',
    'gnmi.interval': 'Обновлять каждые',
    'gnmi.ttl': 'Хранить данные молчащего устройства',
    'gnmi.timeout': 'Тайм-аут запроса',
    'gnmi.concurrency': 'Одновременных опросов',
    'gnmi.min': 'мин',
    'gnmi.sec': 'с',
    'gnmi.profiles': 'Профили учётных данных',
    'gnmi.profiles.hint': 'Устройство опрашивается первым профилем, в префиксы которого входит его адрес; профиль без префиксов подходит любому устройству.',
    'gnmi.add': 'Добавить профиль',
    'gnmi.name': 'Название',
    'gnmi.port': 'Порт',
    'gnmi.encoding': 'Кодировка',
    'gnmi.encoding.hint': 'Если устройство не принимает JSON_IETF, запрос повторяется в JSON.',
    'gnmi.prefixes': 'Устройства (префиксы)',
    'gnmi.user': 'Пользователь',
    'gnmi.user.hint': 'Передаётся в метаданных username / password каждого запроса; пусто — без аутентификации.',
    'gnmi.password': 'Пароль',
    'gnmi.tls': 'TLS',
    'gnmi.tls.hint': 'Без TLS пароль передаётся открытым текстом.',
    'gnmi.skip': 'Не проверять сертификат устройства',
    'gnmi.servername': 'Имя в сертификате',
    'gnmi.servername.hint': 'Ожидаемое имя в сертификате устройства; пусто — его адрес.',
    'gnmi.ca': 'Сертификат УЦ (PEM)',
    'gnmi.ca.hint': 'Пусто — системное хранилище доверенных сертификатов. Сохраняется в OpenBao и больше не показывается.',
    'gnmi.ca.set': 'задан · хранится в OpenBao',
    'gnmi.ca.replace': 'Заменить',
    'gnmi.ca.remove': 'Удалить',
    'gnmi.ca.keep': 'Оставить сохранённый',
    'gnmi.ca.removed': 'Сохранённый сертификат УЦ будет удалён при сохранении.',
    'gnmi.optional': 'необязательно',
    'gnmi.test': 'Проверочный опрос',
    'gnmi.test.address': 'Адрес устройства',
    'gnmi.test.run': 'Опросить',
    'gnmi.test.ok': 'Интерфейсов: {n}',
    'gnmi.test.fail': 'Опрос не удался',
    'gnmi.save': 'Сохранить',
    'gnmi.saved': 'Настройки gNMI сохранены',
    'gnmi.status': 'Опрошенные устройства',
    'gnmi.status.none': 'Устройства ещё не опрашивались.',
    'gnmi.status.remote': 'Опрос работает вместе с обогатителем в другом процессе: его состояние — на странице состояния системы.',
    'gnmi.col.device': 'Устройство',
    'gnmi.col.profile': 'Профиль',
    'gnmi.col.ifaces': 'Интерфейсы',
    'gnmi.col.polled': 'Опрошено',
    'gnmi.col.idx': 'ifindex',
    'gnmi.col.name': 'Имя',
    'gnmi.col.descr': 'Описание',
    'gnmi.col.speed': 'Скорость',
    'gnmi.err.device': 'Дополнительные устройства — это IP-адреса',
    'gnmi.err.ttl': 'Срок хранения не может быть короче периода обновления',
    'gnmi.err.name': 'У каждого профиля должно быть название',
    'gnmi.err.dup': 'Названия профилей должны различаться',
    'gnmi.err.prefix': 'Устройства профиля — это адреса или префиксы',
    'gnmi.err.port': 'Порт — от 1 до 65535',
    'gnmi.err.password': 'Профилю с пользователем нужен пароль',
    'gnmi.err.ca': 'Сертификат УЦ должен быть в формате PEM',
  },
}

type TestResult = { ok: boolean; error?: string; details?: { interfaces: number; sample: { index: number; name: string; descr: string; speed: number }[] } }

function speedText(bps: number) {
  if (!bps) return '—'
  if (bps >= 1e9) return `${bps / 1e9} Gb/s`
  if (bps >= 1e6) return `${bps / 1e6} Mb/s`
  return `${bps} b/s`
}

export default function GnmiPage() {
  const t = useT(strings)
  const { can } = useSession()
  const q = useQuery({ queryKey: ['gnmi'], queryFn: ({ signal }) => get<GnmiView>('/api/settings/gnmi', signal) })
  return (
    <Page id="gnmi" subtitle={t('gnmi.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? <Loading /> : q.data ? <GnmiForm view={q.data} editable={can('settings.gnmi:edit')} /> : null}
    </Page>
  )
}

// CaField: a write-only multi-line PEM (a password input would drop its line breaks).
function CaField({ p, onChange }: { p: GnmiProfileDraft; onChange: (v: Partial<GnmiProfileDraft>) => void }) {
  const t = useT(strings)
  const [replacing, setReplacing] = useState(false)
  const editing = !p.ca_set || replacing || p.ca_pem !== ''
  return (
    <Field label={t('gnmi.ca')} optional={t('gnmi.optional')} hint={p.ca_remove ? t('gnmi.ca.removed') : t('gnmi.ca.hint')}>
      {(id) =>
        editing ? (
          <div className="stack">
            <Textarea id={id} rows={4} value={p.ca_pem} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => onChange({ ca_pem: e.target.value, ca_remove: false })} />
            {p.ca_set && (
              <button
                type="button"
                className="link-button"
                onClick={() => {
                  onChange({ ca_pem: '' })
                  setReplacing(false)
                }}
              >
                {t('gnmi.ca.keep')}
              </button>
            )}
          </div>
        ) : (
          <div className="secret-set">
            {!p.ca_remove && (
              <Chip tone="ok">
                <LockKeyhole size={12} /> {t('gnmi.ca.set')}
              </Chip>
            )}
            <button id={id} type="button" className="btn btn-secondary btn-sm" onClick={() => setReplacing(true)}>
              <KeyRound size={14} /> {t('gnmi.ca.replace')}
            </button>
            <button type="button" className="link-button" onClick={() => onChange({ ca_remove: !p.ca_remove })}>
              {p.ca_remove ? t('gnmi.ca.keep') : t('gnmi.ca.remove')}
            </button>
          </div>
        )
      }
    </Field>
  )
}

function GnmiForm({ view, editable }: { view: GnmiView; editable: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const [draft, setDraft] = useState<GnmiDraft>(() => toGnmiDraft(view))
  useEffect(() => setDraft(toGnmiDraft(view)), [view])
  const problems = validateGnmi(draft)
  const set = (p: Partial<GnmiDraft>) => setDraft({ ...draft, ...p })
  const setProfile = (i: number, p: Partial<GnmiProfileDraft>) => set({ profiles: draft.profiles.map((x, j) => (j === i ? { ...x, ...p } : x)) })

  const save = useMutation({
    mutationFn: () => put<GnmiView>('/api/settings/gnmi', gnmiBody(draft)),
    onSuccess: (v) => {
      qc.setQueryData(['gnmi'], v)
      notify('ok', t('gnmi.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })

  const [testAddr, setTestAddr] = useState('')
  const [testProfile, setTestProfile] = useState(0)
  const test = useMutation({
    mutationFn: () => post<TestResult>('/api/settings/gnmi/test', { address: testAddr.trim(), profile: gnmiProfileBody(draft.profiles[testProfile]) }),
  })

  const st = view.status
  return (
    <div className="settings-grid">
      <Card title={t('gnmi.polling')}>
        <fieldset className="plain-fieldset stack" disabled={!editable}>
          <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })} label={t('gnmi.enabled')} hint={t('gnmi.enabled.hint')} disabled={!editable} />
          <Switch checked={draft.poll_exporters} onChange={(v) => set({ poll_exporters: v })} label={t('gnmi.exporters')} hint={t('gnmi.exporters.hint')} disabled={!editable} />
          <Field label={t('gnmi.devices')} hint={t('gnmi.devices.hint')}>
            {(id) => <Textarea id={id} rows={3} value={draft.devices} onChange={(e) => set({ devices: e.target.value })} placeholder="192.0.2.1" spellCheck={false} />}
          </Field>
          <div className="row wrap">
            <Field label={t('gnmi.interval')}>{(id) => <Stepper id={id} value={draft.interval_minutes} min={1} max={1440} suffix={t('gnmi.min')} onChange={(v) => set({ interval_minutes: v })} />}</Field>
            <Field label={t('gnmi.ttl')}>{(id) => <Stepper id={id} value={draft.ttl_minutes} min={1} max={10080} suffix={t('gnmi.min')} onChange={(v) => set({ ttl_minutes: v })} />}</Field>
          </div>
          <div className="row wrap">
            <Field label={t('gnmi.timeout')}>{(id) => <Stepper id={id} value={draft.timeout_seconds} min={1} max={60} suffix={t('gnmi.sec')} onChange={(v) => set({ timeout_seconds: v })} />}</Field>
            <Field label={t('gnmi.concurrency')}>{(id) => <Stepper id={id} value={draft.concurrency} min={1} max={64} onChange={(v) => set({ concurrency: v })} />}</Field>
          </div>
        </fieldset>
      </Card>

      <Card title={t('gnmi.profiles')}>
        <p className="hint">{t('gnmi.profiles.hint')}</p>
        <fieldset className="plain-fieldset stack" disabled={!editable}>
          {draft.profiles.map((p, i) => (
            <div key={p.key} className="card stack" style={{ padding: 12 }}>
              <div className="row wrap">
                <Field label={t('gnmi.name')}>{(id) => <Input id={id} value={p.name} onChange={(e) => setProfile(i, { name: e.target.value })} />}</Field>
                <Field label={t('gnmi.port')}>{(id) => <Stepper id={id} value={p.port} min={1} max={65535} onChange={(v) => setProfile(i, { port: v })} />}</Field>
                <Field label={t('gnmi.encoding')} hint={t('gnmi.encoding.hint')}>
                  {(id) => (
                    <Select id={id} value={p.encoding} onChange={(e) => setProfile(i, { encoding: e.target.value as GnmiEncoding })}>
                      {view.encodings.map((e) => (
                        <option key={e} value={e}>
                          {e.toUpperCase()}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                {editable && (
                  <button type="button" className="icon-btn" aria-label="delete" onClick={() => set({ profiles: draft.profiles.filter((_, j) => j !== i) })}>
                    <Trash2 size={15} />
                  </button>
                )}
              </div>
              <Field label={t('gnmi.prefixes')}>
                {(id) => <Textarea id={id} rows={2} value={p.prefixes} onChange={(e) => setProfile(i, { prefixes: e.target.value })} placeholder="10.0.0.0/8" spellCheck={false} />}
              </Field>
              <div className="row wrap">
                <Field label={t('gnmi.user')} optional={t('gnmi.optional')} hint={t('gnmi.user.hint')}>
                  {(id) => <Input id={id} value={p.username} autoComplete="off" onChange={(e) => setProfile(i, { username: e.target.value })} />}
                </Field>
                {p.username.trim() !== '' && <SecretField label={t('gnmi.password')} value={p.password} onChange={(v) => setProfile(i, { password: v })} isSet={p.password_set} />}
              </div>
              <Switch checked={p.tls} onChange={(v) => setProfile(i, { tls: v })} label={t('gnmi.tls')} hint={p.tls ? undefined : t('gnmi.tls.hint')} disabled={!editable} />
              {p.tls && (
                <>
                  <Switch checked={p.skip_verify} onChange={(v) => setProfile(i, { skip_verify: v })} label={t('gnmi.skip')} disabled={!editable} />
                  {!p.skip_verify && (
                    <>
                      <Field label={t('gnmi.servername')} optional={t('gnmi.optional')} hint={t('gnmi.servername.hint')}>
                        {(id) => <Input id={id} value={p.server_name} placeholder="router.example.net" onChange={(e) => setProfile(i, { server_name: e.target.value })} />}
                      </Field>
                      <CaField p={p} onChange={(v) => setProfile(i, v)} />
                    </>
                  )}
                </>
              )}
            </div>
          ))}
        </fieldset>
        {editable && (
          <div className="row">
            <Button size="sm" onClick={() => set({ profiles: [...draft.profiles, newGnmiProfile()] })}>
              <Plus size={14} /> {t('gnmi.add')}
            </Button>
          </div>
        )}
        {problems.map((p) => (
          <Banner key={p} kind="warn" title={t(p)} />
        ))}
        {editable && (
          <div className="card-actions">
            <Button variant="primary" busy={save.isPending} disabled={problems.length > 0} onClick={() => save.mutate()}>
              {!save.isPending && <Save size={15} />}
              {t('gnmi.save')}
            </Button>
          </div>
        )}
      </Card>

      {editable && draft.profiles.length > 0 && (
        <Card title={t('gnmi.test')}>
          <div className="row wrap">
            <Field label={t('gnmi.test.address')}>{(id) => <Input id={id} value={testAddr} placeholder="192.0.2.1" onChange={(e) => setTestAddr(e.target.value)} />}</Field>
            <Field label={t('gnmi.col.profile')}>
              {(id) => (
                <Select id={id} value={String(testProfile)} onChange={(e) => setTestProfile(Number(e.target.value))}>
                  {draft.profiles.map((p, i) => (
                    <option key={p.key} value={i}>
                      {p.name || `#${i + 1}`}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          {test.data && (
            <div className={`test-result ${test.data.ok ? 'good' : 'bad'}`}>
              {test.data.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
              <span>{test.data.ok ? t('gnmi.test.ok', { n: test.data.details?.interfaces ?? 0 }) : `${t('gnmi.test.fail')}: ${test.data.error ?? ''}`}</span>
            </div>
          )}
          {test.error && <Banner kind="error" title={errorText(t, test.error).message} />}
          {test.data?.ok && test.data.details && (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="num">{t('gnmi.col.idx')}</th>
                    <th>{t('gnmi.col.name')}</th>
                    <th>{t('gnmi.col.descr')}</th>
                    <th className="num">{t('gnmi.col.speed')}</th>
                  </tr>
                </thead>
                <tbody>
                  {test.data.details.sample.map((r) => (
                    <tr key={r.index}>
                      <td className="num">{r.index}</td>
                      <td>{r.name}</td>
                      <td>{r.descr}</td>
                      <td className="num">{speedText(r.speed)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="card-actions">
            <Button busy={test.isPending} disabled={!validAddress(testAddr.trim()) || !draft.profiles[testProfile]} onClick={() => test.mutate()}>
              {!test.isPending && <PlugZap size={15} />}
              {t('gnmi.test.run')}
            </Button>
          </div>
        </Card>
      )}

      <Card title={t('gnmi.status')}>
        {!st ? (
          <p className="muted">{t('gnmi.status.remote')}</p>
        ) : st.devices.length === 0 ? (
          <p className="muted">{t('gnmi.status.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('gnmi.col.device')}</th>
                  <th>{t('gnmi.col.profile')}</th>
                  <th className="num">{t('gnmi.col.ifaces')}</th>
                  <th>{t('gnmi.col.polled')}</th>
                </tr>
              </thead>
              <tbody>
                {st.devices.map((d) => (
                  <tr key={d.address}>
                    <td>
                      <code>{d.address}</code>
                      {d.error && <div className="cell-sub muted">{d.error}</div>}
                    </td>
                    <td>{d.profile ?? '—'}</td>
                    <td className="num">{num(d.interfaces, locale)}</td>
                    <td>{d.error ? <Chip tone="error">{t('gnmi.test.fail')}</Chip> : d.polled ? formatDate(d.polled, locale) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
