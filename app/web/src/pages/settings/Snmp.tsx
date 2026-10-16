import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Plus, PlugZap, Save, Trash2, XCircle } from 'lucide-react'
import { get, post, put } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { SecretField } from '../../ui/SecretField'
import { Banner, Button, Card, Chip, Field, formatDate, Input, Loading, Segmented, Select, Stepper, Switch, Textarea } from '../../ui/ui'
import { body, newProfile, profileBody, toDraft, validAddress, validate, type ProfileDraft, type SecurityLevel, type SnmpDraft, type SnmpView } from './SnmpModel'

// Settings → SNMP (docs/api.md, "SNMP"): interface names, descriptions and speeds polled over SNMP
// for exporters Ledger does not describe. Credentials go to OpenBao and are never shown again.

const strings: Dict = {
  en: {
    'snmp.sub': 'Interface names and speeds over SNMP for devices that Ledger does not describe',
    'snmp.polling': 'Polling',
    'snmp.enabled': 'Poll devices over SNMP',
    'snmp.enabled.hint': 'Used after Ledger and the interface data the exporters send (option templates, sFlow counters).',
    'snmp.exporters': 'Poll the exporters seen in flows',
    'snmp.exporters.hint': 'Only exporters inside the prefixes of a credential profile are polled.',
    'snmp.devices': 'Additional devices',
    'snmp.devices.hint': 'Addresses polled even before they send flows, one per line.',
    'snmp.interval': 'Refresh every',
    'snmp.ttl': 'Keep data of a silent device for',
    'snmp.timeout': 'Request timeout',
    'snmp.retries': 'Retries',
    'snmp.concurrency': 'Parallel polls',
    'snmp.min': 'min',
    'snmp.sec': 's',
    'snmp.profiles': 'Credential profiles',
    'snmp.profiles.hint': 'A device uses the first profile whose prefixes contain its address; a profile without prefixes matches every device.',
    'snmp.add': 'Add profile',
    'snmp.name': 'Name',
    'snmp.version': 'Version',
    'snmp.port': 'Port',
    'snmp.prefixes': 'Devices (prefixes)',
    'snmp.community': 'Community',
    'snmp.user': 'User name',
    'snmp.level': 'Security level',
    'snmp.authproto': 'Authentication',
    'snmp.auth': 'Authentication password',
    'snmp.privproto': 'Privacy',
    'snmp.priv': 'Privacy password',
    'snmp.context': 'Context',
    'snmp.test': 'Poll a device',
    'snmp.test.address': 'Device address',
    'snmp.test.run': 'Poll',
    'snmp.test.ok': '{n} interfaces',
    'snmp.test.fail': 'Poll failed',
    'snmp.save': 'Save',
    'snmp.saved': 'SNMP settings saved',
    'snmp.status': 'Polled devices',
    'snmp.status.none': 'No device polled yet.',
    'snmp.status.remote': 'The poller runs with the enricher in another process: its state is on the System status page.',
    'snmp.col.device': 'Device',
    'snmp.col.profile': 'Profile',
    'snmp.col.ifaces': 'Interfaces',
    'snmp.col.polled': 'Polled',
    'snmp.col.idx': 'ifIndex',
    'snmp.col.name': 'Name',
    'snmp.col.descr': 'Description',
    'snmp.col.speed': 'Speed',
    'snmp.err.device': 'Additional devices must be IP addresses',
    'snmp.err.ttl': 'The keep time must not be shorter than the refresh period',
    'snmp.err.name': 'Every profile needs a name',
    'snmp.err.dup': 'Profile names must be unique',
    'snmp.err.prefix': 'Profile devices must be addresses or prefixes',
    'snmp.err.port': 'The port must be between 1 and 65535',
    'snmp.err.community': 'An SNMPv2c profile needs a community',
    'snmp.err.user': 'An SNMPv3 profile needs a user name',
    'snmp.err.auth': 'An SNMPv3 profile with authentication needs its password',
    'snmp.err.priv': 'An SNMPv3 profile with privacy needs its password',
  },
  ru: {
    'snmp.sub': 'Имена и скорости интерфейсов по SNMP для устройств, которых нет в Ledger',
    'snmp.polling': 'Опрос',
    'snmp.enabled': 'Опрашивать устройства по SNMP',
    'snmp.enabled.hint': 'Используется после Ledger и данных об интерфейсах от экспортёров (option templates, счётчики sFlow).',
    'snmp.exporters': 'Опрашивать экспортёры из потоков',
    'snmp.exporters.hint': 'Опрашиваются только экспортёры внутри префиксов профиля учётных данных.',
    'snmp.devices': 'Дополнительные устройства',
    'snmp.devices.hint': 'Адреса, которые опрашиваются ещё до прихода потоков, по одному в строке.',
    'snmp.interval': 'Обновлять каждые',
    'snmp.ttl': 'Хранить данные молчащего устройства',
    'snmp.timeout': 'Тайм-аут запроса',
    'snmp.retries': 'Повторы',
    'snmp.concurrency': 'Одновременных опросов',
    'snmp.min': 'мин',
    'snmp.sec': 'с',
    'snmp.profiles': 'Профили учётных данных',
    'snmp.profiles.hint': 'Устройство опрашивается первым профилем, в префиксы которого входит его адрес; профиль без префиксов подходит любому устройству.',
    'snmp.add': 'Добавить профиль',
    'snmp.name': 'Название',
    'snmp.version': 'Версия',
    'snmp.port': 'Порт',
    'snmp.prefixes': 'Устройства (префиксы)',
    'snmp.community': 'Community',
    'snmp.user': 'Пользователь',
    'snmp.level': 'Уровень безопасности',
    'snmp.authproto': 'Аутентификация',
    'snmp.auth': 'Пароль аутентификации',
    'snmp.privproto': 'Шифрование',
    'snmp.priv': 'Пароль шифрования',
    'snmp.context': 'Контекст',
    'snmp.test': 'Проверочный опрос',
    'snmp.test.address': 'Адрес устройства',
    'snmp.test.run': 'Опросить',
    'snmp.test.ok': 'Интерфейсов: {n}',
    'snmp.test.fail': 'Опрос не удался',
    'snmp.save': 'Сохранить',
    'snmp.saved': 'Настройки SNMP сохранены',
    'snmp.status': 'Опрошенные устройства',
    'snmp.status.none': 'Устройства ещё не опрашивались.',
    'snmp.status.remote': 'Опрос работает вместе с обогатителем в другом процессе: его состояние — на странице состояния системы.',
    'snmp.col.device': 'Устройство',
    'snmp.col.profile': 'Профиль',
    'snmp.col.ifaces': 'Интерфейсы',
    'snmp.col.polled': 'Опрошено',
    'snmp.col.idx': 'ifIndex',
    'snmp.col.name': 'Имя',
    'snmp.col.descr': 'Описание',
    'snmp.col.speed': 'Скорость',
    'snmp.err.device': 'Дополнительные устройства — это IP-адреса',
    'snmp.err.ttl': 'Срок хранения не может быть короче периода обновления',
    'snmp.err.name': 'У каждого профиля должно быть название',
    'snmp.err.dup': 'Названия профилей должны различаться',
    'snmp.err.prefix': 'Устройства профиля — это адреса или префиксы',
    'snmp.err.port': 'Порт — от 1 до 65535',
    'snmp.err.community': 'Профилю SNMPv2c нужна community',
    'snmp.err.user': 'Профилю SNMPv3 нужно имя пользователя',
    'snmp.err.auth': 'Профилю SNMPv3 с аутентификацией нужен пароль',
    'snmp.err.priv': 'Профилю SNMPv3 с шифрованием нужен пароль шифрования',
  },
}

type TestResult = { ok: boolean; error?: string; details?: { interfaces: number; sample: { index: number; name: string; descr: string; speed: number }[] } }

function speedText(bps: number) {
  if (!bps) return '—'
  if (bps >= 1e9) return `${bps / 1e9} Gb/s`
  if (bps >= 1e6) return `${bps / 1e6} Mb/s`
  return `${bps} b/s`
}

export default function SnmpPage() {
  const t = useT(strings)
  const { can } = useSession()
  const q = useQuery({ queryKey: ['snmp'], queryFn: ({ signal }) => get<SnmpView>('/api/settings/snmp', signal) })
  return (
    <Page id="snmp" subtitle={t('snmp.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.isPending ? <Loading /> : q.data ? <SnmpForm view={q.data} editable={can('settings.snmp:edit')} /> : null}
    </Page>
  )
}

function SnmpForm({ view, editable }: { view: SnmpView; editable: boolean }) {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const [draft, setDraft] = useState<SnmpDraft>(() => toDraft(view))
  useEffect(() => setDraft(toDraft(view)), [view])
  const problems = validate(draft)
  const set = (p: Partial<SnmpDraft>) => setDraft({ ...draft, ...p })
  const setProfile = (i: number, p: Partial<ProfileDraft>) => set({ profiles: draft.profiles.map((x, j) => (j === i ? { ...x, ...p } : x)) })

  const save = useMutation({
    mutationFn: () => put<SnmpView>('/api/settings/snmp', body(draft)),
    onSuccess: (v) => {
      qc.setQueryData(['snmp'], v)
      notify('ok', t('snmp.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })

  const [testAddr, setTestAddr] = useState('')
  const [testProfile, setTestProfile] = useState(0)
  const test = useMutation({
    mutationFn: () => post<TestResult>('/api/settings/snmp/test', { address: testAddr.trim(), profile: profileBody(draft.profiles[testProfile]) }),
  })

  const st = view.status
  return (
    <div className="settings-grid">
      <Card title={t('snmp.polling')}>
        <fieldset className="plain-fieldset stack" disabled={!editable}>
          <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })} label={t('snmp.enabled')} hint={t('snmp.enabled.hint')} disabled={!editable} />
          <Switch checked={draft.poll_exporters} onChange={(v) => set({ poll_exporters: v })} label={t('snmp.exporters')} hint={t('snmp.exporters.hint')} disabled={!editable} />
          <Field label={t('snmp.devices')} hint={t('snmp.devices.hint')}>
            {(id) => <Textarea id={id} rows={3} value={draft.devices} onChange={(e) => set({ devices: e.target.value })} placeholder="192.0.2.1" spellCheck={false} />}
          </Field>
          <div className="row wrap">
            <Field label={t('snmp.interval')}>{(id) => <Stepper id={id} value={draft.interval_minutes} min={1} max={1440} suffix={t('snmp.min')} onChange={(v) => set({ interval_minutes: v })} />}</Field>
            <Field label={t('snmp.ttl')}>{(id) => <Stepper id={id} value={draft.ttl_minutes} min={1} max={10080} suffix={t('snmp.min')} onChange={(v) => set({ ttl_minutes: v })} />}</Field>
          </div>
          <div className="row wrap">
            <Field label={t('snmp.timeout')}>{(id) => <Stepper id={id} value={draft.timeout_seconds} min={1} max={60} suffix={t('snmp.sec')} onChange={(v) => set({ timeout_seconds: v })} />}</Field>
            <Field label={t('snmp.retries')}>{(id) => <Stepper id={id} value={draft.retries} min={0} max={5} onChange={(v) => set({ retries: v })} />}</Field>
            <Field label={t('snmp.concurrency')}>{(id) => <Stepper id={id} value={draft.concurrency} min={1} max={64} onChange={(v) => set({ concurrency: v })} />}</Field>
          </div>
        </fieldset>
      </Card>

      <Card title={t('snmp.profiles')}>
        <p className="hint">{t('snmp.profiles.hint')}</p>
        <fieldset className="plain-fieldset stack" disabled={!editable}>
          {draft.profiles.map((p, i) => (
            <div key={p.key} className="card stack" style={{ padding: 12 }}>
              <div className="row wrap">
                <Field label={t('snmp.name')}>{(id) => <Input id={id} value={p.name} onChange={(e) => setProfile(i, { name: e.target.value })} />}</Field>
                <Segmented label={t('snmp.version')} value={p.version} options={[{ value: '2c', label: 'v2c' }, { value: '3', label: 'v3' }]} onChange={(v) => setProfile(i, { version: v })} />
                <Field label={t('snmp.port')}>{(id) => <Stepper id={id} value={p.port} min={1} max={65535} onChange={(v) => setProfile(i, { port: v })} />}</Field>
                {editable && (
                  <button type="button" className="icon-btn" aria-label="delete" onClick={() => set({ profiles: draft.profiles.filter((_, j) => j !== i) })}>
                    <Trash2 size={15} />
                  </button>
                )}
              </div>
              <Field label={t('snmp.prefixes')}>
                {(id) => <Textarea id={id} rows={2} value={p.prefixes} onChange={(e) => setProfile(i, { prefixes: e.target.value })} placeholder="10.0.0.0/8" spellCheck={false} />}
              </Field>
              {p.version === '2c' ? (
                <SecretField label={t('snmp.community')} value={p.community} onChange={(v) => setProfile(i, { community: v })} isSet={p.community_set} />
              ) : (
                <>
                  <div className="row wrap">
                    <Field label={t('snmp.user')}>{(id) => <Input id={id} value={p.username} autoComplete="off" onChange={(e) => setProfile(i, { username: e.target.value })} />}</Field>
                    <Field label={t('snmp.level')}>
                      {(id) => (
                        <Select id={id} value={p.security_level} onChange={(e) => setProfile(i, { security_level: e.target.value as SecurityLevel })}>
                          {(['noAuthNoPriv', 'authNoPriv', 'authPriv'] as const).map((l) => (
                            <option key={l} value={l}>
                              {l}
                            </option>
                          ))}
                        </Select>
                      )}
                    </Field>
                    <Field label={t('snmp.context')}>{(id) => <Input id={id} value={p.context_name} onChange={(e) => setProfile(i, { context_name: e.target.value })} />}</Field>
                  </div>
                  {p.security_level !== 'noAuthNoPriv' && (
                    <div className="row wrap">
                      <Field label={t('snmp.authproto')}>
                        {(id) => (
                          <Select id={id} value={p.auth_protocol} onChange={(e) => setProfile(i, { auth_protocol: e.target.value })}>
                            {view.auth_protocols.map((a) => (
                              <option key={a} value={a}>
                                {a}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                      <SecretField label={t('snmp.auth')} value={p.auth_password} onChange={(v) => setProfile(i, { auth_password: v })} isSet={p.auth_password_set} />
                    </div>
                  )}
                  {p.security_level === 'authPriv' && (
                    <div className="row wrap">
                      <Field label={t('snmp.privproto')}>
                        {(id) => (
                          <Select id={id} value={p.priv_protocol} onChange={(e) => setProfile(i, { priv_protocol: e.target.value })}>
                            {view.priv_protocols.map((a) => (
                              <option key={a} value={a}>
                                {a}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                      <SecretField label={t('snmp.priv')} value={p.priv_password} onChange={(v) => setProfile(i, { priv_password: v })} isSet={p.priv_password_set} />
                    </div>
                  )}
                </>
              )}
            </div>
          ))}
        </fieldset>
        {editable && (
          <div className="row">
            <Button size="sm" onClick={() => set({ profiles: [...draft.profiles, newProfile()] })}>
              <Plus size={14} /> {t('snmp.add')}
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
              {t('snmp.save')}
            </Button>
          </div>
        )}
      </Card>

      {editable && draft.profiles.length > 0 && (
        <Card title={t('snmp.test')}>
          <div className="row wrap">
            <Field label={t('snmp.test.address')}>{(id) => <Input id={id} value={testAddr} placeholder="192.0.2.1" onChange={(e) => setTestAddr(e.target.value)} />}</Field>
            <Field label={t('snmp.col.profile')}>
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
              <span>{test.data.ok ? t('snmp.test.ok', { n: test.data.details?.interfaces ?? 0 }) : `${t('snmp.test.fail')}: ${test.data.error ?? ''}`}</span>
            </div>
          )}
          {test.error && <Banner kind="error" title={errorText(t, test.error).message} />}
          {test.data?.ok && test.data.details && (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="num">{t('snmp.col.idx')}</th>
                    <th>{t('snmp.col.name')}</th>
                    <th>{t('snmp.col.descr')}</th>
                    <th className="num">{t('snmp.col.speed')}</th>
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
            <Button busy={test.isPending} disabled={!validAddress(testAddr.trim())} onClick={() => test.mutate()}>
              {!test.isPending && <PlugZap size={15} />}
              {t('snmp.test.run')}
            </Button>
          </div>
        </Card>
      )}

      <Card title={t('snmp.status')}>
        {!st ? (
          <p className="muted">{t('snmp.status.remote')}</p>
        ) : st.devices.length === 0 ? (
          <p className="muted">{t('snmp.status.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('snmp.col.device')}</th>
                  <th>{t('snmp.col.profile')}</th>
                  <th className="num">{t('snmp.col.ifaces')}</th>
                  <th>{t('snmp.col.polled')}</th>
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
                    <td>{d.error ? <Chip tone="error">{t('snmp.test.fail')}</Chip> : d.polled ? formatDate(d.polled, locale) : '—'}</td>
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
