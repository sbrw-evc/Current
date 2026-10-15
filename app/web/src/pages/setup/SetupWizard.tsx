import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Check, Plus, Trash2 } from 'lucide-react'
import { AnimatePresence, motion, MotionConfig, type Variants } from 'motion/react'
import { useNavigate } from 'react-router-dom'
import { ApiError, post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { browserTimezone, timezones, zoneLabel } from '../../lib/timezones'
import { originOf } from '../../lib/fx'
import { useTheme } from '../../theme'
import { Choice, Choices, Pop } from '../../ui/Choice'
import { SecretField } from '../../ui/SecretField'
import { Banner, Brand, Button, Chip, Field, Input, Password, Preferences, Rows, Select, spring, Stepper, Switch, type Tone } from '../../ui/ui'
import { DEFAULT_POLICY, failed, publicURLOk, USERNAME } from './policy'
import { PolicyChecklist, PolicyEditor } from '../identity/components'
import { setupStrings } from './strings'
import type { Admin, ClickHouse, Collector, GeoIP, Inventory, Nats, OpenBao, PasswordPolicy, Postgres, Retention, SetupBody, SetupDefaults, SetupTheme, TestResult, TestStep, Umbrella } from './types'

// The first-run wizard in Umbrella's look (Umbrella app/web/src/setup/SetupApp.tsx): a step list,
// animated step transitions, connection forms with a "Check" button and result chips, a summary.

export type StepId = 'code' | 'general' | 'openbao' | 'postgres' | 'clickhouse' | 'nats' | 'collector' | 'inventory' | 'umbrella' | 'geoip' | 'admin' | 'review'
export const STEPS: StepId[] = ['code', 'general', 'openbao', 'postgres', 'clickhouse', 'nats', 'collector', 'inventory', 'umbrella', 'geoip', 'admin', 'review']
const OPTIONAL: StepId[] = ['inventory', 'umbrella', 'geoip']

const stepVariants: Variants = {
  enter: (dir: 'fwd' | 'back') => ({ opacity: 0, x: dir === 'fwd' ? 36 : -36 }),
  center: { opacity: 1, x: 0 },
  exit: (dir: 'fwd' | 'back') => ({ opacity: 0, x: dir === 'fwd' ? -36 : 36 }),
}

const SSL_MODES = ['disable', 'prefer', 'require', 'verify-ca', 'verify-full']
const INTERVALS = ['5m', '15m', '30m', '1h', '6h', '24h']

type CheckState = { key: string; result: TestResult } | undefined

const detailStrings = {
  en: { 'det.version': 'Version', 'det.has_state': 'Flow data found', 'det.saved_at': 'Saved', 'det.devices': 'Devices', 'det.mount': 'Mount', 'det.policies': 'Policies', 'det.token_ttl': 'Token TTL', 'det.server': 'Server', 'det.jetstream': 'JetStream', 'det.files': 'Files', 'det.build': 'Build', 'det.event': 'Test event', 'det.connector': 'Connector', 'det.tables': 'Tables', 'det.prefixes': 'Prefixes', 'det.circuits': 'Circuits' },
  ru: { 'det.version': 'Версия', 'det.has_state': 'Найдены данные Flow', 'det.saved_at': 'Сохранены', 'det.devices': 'Устройств', 'det.mount': 'Хранилище', 'det.policies': 'Политики', 'det.token_ttl': 'Срок токена', 'det.server': 'Сервер', 'det.jetstream': 'JetStream', 'det.files': 'Файлов', 'det.build': 'Сборка', 'det.event': 'Тестовое событие', 'det.connector': 'Коннектор', 'det.tables': 'Таблицы', 'det.prefixes': 'Префиксов', 'det.circuits': 'Каналов' },
}
const dict = { en: { ...setupStrings.en, ...detailStrings.en }, ru: { ...setupStrings.ru, ...detailStrings.ru } }

const nonEmpty = (v: string) => (v ? v : undefined)

export default function SetupWizard({ defaults }: { defaults: SetupDefaults }) {
  const t = useT(dict)
  const { locale, setLocale } = useLocale()
  const { setTheme } = useTheme()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const d = defaults

  const [step, setStepRaw] = useState<StepId>('code')
  const [dir, setDir] = useState<'fwd' | 'back'>('fwd')
  const [reached, setReached] = useState(0)
  const [code, setCode] = useState('')
  const [codeOk, setCodeOk] = useState(false)
  const [general, setGeneral] = useState<{ language: 'ru' | 'en'; theme: SetupTheme; timezone: string; public_url: string }>(() => {
    const tz = d.timezone || browserTimezone()
    return { language: d.language ?? locale, theme: d.theme ?? 'system', timezone: timezones().some((z) => z.id === tz) ? tz : 'UTC', public_url: d.public_url || window.location.origin }
  })
  const [ob, setOb] = useState<OpenBao>({ addr: d.openbao?.addr ?? '', mount: d.openbao?.mount ?? 'flow', auth: d.openbao?.auth ?? 'approle', token: '', role_id: d.openbao?.role_id ?? '', secret_id: '' })
  const [pg, setPg] = useState<Postgres>({
    host: d.postgres?.host ?? '',
    port: d.postgres?.port ?? 5432,
    database: d.postgres?.database ?? 'flow',
    username: d.postgres?.username ?? 'flow',
    password: '',
    sslmode: d.postgres?.sslmode ?? 'prefer',
    attach_existing: false,
  })
  const [ch, setCh] = useState<ClickHouse>({ addr: d.clickhouse?.addr ?? '', database: d.clickhouse?.database ?? 'flow', username: d.clickhouse?.username ?? 'default', password: '', secure: d.clickhouse?.secure ?? false })
  const [ret, setRet] = useState<Retention>({ raw_days: 15, d1m: 30, d5m: 90, d1h: 730, ...(d.clickhouse?.retention ?? {}) })
  const [nats, setNats] = useState<Nats>({ url: d.nats?.url ?? '' })
  const [col, setCol] = useState<Collector>({ netflow_addr: ':2055', sflow_addr: ':6343', default_sampling_rate: 1, ...(d.collector ?? {}) })
  const [inv, setInv] = useState<Inventory>({ enabled: true, url: '', token: '', interval: '15m' })
  const [um, setUm] = useState<Umbrella>({ enabled: true, ingest_url: '', token: '' })
  const [geo, setGeo] = useState<GeoIP & { enabled: boolean }>({ enabled: true, databases: ['/geoip/GeoLite2-City.mmdb', '/geoip/GeoLite2-ASN.mmdb'] })
  const [admin, setAdmin] = useState<Admin & { confirm: string }>({ username: 'admin', name: '', email: '', password: '', confirm: '' })
  const [policy, setPolicy] = useState<PasswordPolicy>(DEFAULT_POLICY)
  const [policyOpen, setPolicyOpen] = useState(false)
  const [checks, setChecks] = useState<Partial<Record<TestStep, CheckState>>>({})
  const [testing, setTesting] = useState<TestStep | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ message: string; detail?: string } | null>(null)
  const [done, setDone] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)

  const set = {
    obToken: !!d.openbao?.token_set,
    obRole: !!d.openbao?.role_id_set,
    obSecret: !!d.openbao?.secret_id_set,
    pg: !!d.postgres?.password_set,
    ch: !!d.clickhouse?.password_set,
  }

  // The bodies of the checks; a check is valid while its body is unchanged.
  const bodies: Record<TestStep, Record<string, unknown>> = {
    openbao: { addr: ob.addr.trim(), mount: ob.mount.trim(), auth: ob.auth, ...(ob.auth === 'token' ? { token: nonEmpty(ob.token) } : { role_id: ob.role_id.trim(), secret_id: nonEmpty(ob.secret_id) }) },
    postgres: { host: pg.host.trim(), port: pg.port, database: pg.database.trim(), username: pg.username.trim(), password: nonEmpty(pg.password), sslmode: pg.sslmode },
    clickhouse: { addr: ch.addr.trim(), database: ch.database.trim(), username: ch.username.trim(), password: nonEmpty(ch.password), secure: ch.secure },
    nats: { url: nats.url.trim() },
    inventory: { url: inv.url.trim(), token: nonEmpty(inv.token), interval: inv.interval },
    umbrella: { ingest_url: um.ingest_url.trim(), token: nonEmpty(um.token) },
    geoip: { databases: geo.databases.map((x) => x.trim()).filter(Boolean) },
  }
  const keyOf = (s: TestStep) => JSON.stringify(bodies[s])
  const passed = (s: TestStep) => {
    const c = checks[s]
    return !!c && c.key === keyOf(s) && c.result.ok
  }
  const hasState = passed('postgres') && checks.postgres?.result.details?.has_state === true
  const attach = hasState && pg.attach_existing

  const policyFails = failed(admin.password, admin.username.trim(), policy)
  const adminEmpty = admin.password === '' && admin.confirm === ''
  const adminValid = USERNAME.test(admin.username.trim()) && policyFails.length === 0 && admin.password === admin.confirm && (admin.email.trim() === '' || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(admin.email.trim()))
  const publicValid = publicURLOk(general.public_url)

  const canNext: Record<StepId, boolean> = {
    code: codeOk,
    general: publicValid,
    openbao: passed('openbao'),
    postgres: passed('postgres') && (!hasState || pg.attach_existing),
    clickhouse: passed('clickhouse') && ret.raw_days > 0,
    nats: nats.url.trim() === '' || passed('nats'),
    collector: col.netflow_addr.trim() !== '' || col.sflow_addr.trim() !== '',
    inventory: !inv.enabled || passed('inventory'),
    umbrella: !um.enabled || passed('umbrella'),
    geoip: !geo.enabled || geo.databases.filter((x) => x.trim()).length === 0 || passed('geoip'),
    admin: adminValid || (attach && adminEmpty),
    review: false,
  }

  useEffect(() => {
    heading.current?.focus()
    setError(null)
  }, [step])

  const setStep = (s: StepId) => {
    setDir(STEPS.indexOf(s) >= STEPS.indexOf(step) ? 'fwd' : 'back')
    setStepRaw(s)
  }
  const go = (s: StepId) => {
    setReached((r) => Math.max(r, STEPS.indexOf(s)))
    setStep(s)
  }
  const next = () => {
    const i = STEPS.indexOf(step)
    if (canNext[step] && i < STEPS.length - 1) go(STEPS[i + 1])
  }
  const back = () => {
    const i = STEPS.indexOf(step)
    if (i > 0) setStep(STEPS[i - 1])
  }
  const skip = () => {
    if (step === 'inventory') setInv({ ...inv, enabled: false })
    if (step === 'umbrella') setUm({ ...um, enabled: false })
    if (step === 'geoip') setGeo({ ...geo, enabled: false })
    go(STEPS[STEPS.indexOf(step) + 1])
  }

  const fail = (e: unknown) => {
    setError(errorText(t, e))
    if (e instanceof ApiError && e.code === 'setup_code_invalid') setCodeOk(false)
  }

  const verifyCode = async () => {
    setBusy(true)
    setError(null)
    try {
      await post('/api/setup/check-code', { setup_code: code.trim() })
      setCodeOk(true)
      go('general')
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  const test = async (s: TestStep) => {
    const key = keyOf(s)
    setTesting(s)
    setError(null)
    try {
      const result = await post<TestResult>(`/api/setup/test/${s}`, { ...bodies[s], setup_code: code.trim() })
      setChecks((c) => ({ ...c, [s]: { key, result } }))
    } catch (e) {
      fail(e)
    } finally {
      setTesting(null)
    }
  }

  const finish = async () => {
    setBusy(true)
    setError(null)
    const body: SetupBody = {
      setup_code: code.trim(),
      language: general.language,
      theme: general.theme,
      timezone: general.timezone,
      public_url: general.public_url.trim().replace(/\/+$/, ''),
      openbao: bodies.openbao as Partial<OpenBao>,
      postgres: { ...(bodies.postgres as Partial<Postgres>), attach_existing: attach },
      clickhouse: bodies.clickhouse as Partial<ClickHouse>,
      retention: ret,
      nats: { url: nats.url.trim() },
      collector: { ...col, netflow_addr: col.netflow_addr.trim(), sflow_addr: col.sflow_addr.trim() },
      inventory: inv.enabled ? { enabled: true, ...(bodies.inventory as Partial<Inventory>) } : { enabled: false },
      umbrella: um.enabled ? { enabled: true, ...(bodies.umbrella as Partial<Umbrella>) } : { enabled: false },
      geoip: { databases: geo.enabled ? (bodies.geoip.databases as string[]) : [] },
      admin: attach && adminEmpty ? { username: '', name: '', email: '', password: '' } : { username: admin.username.trim(), name: admin.name.trim(), email: admin.email.trim(), password: admin.password },
      password_policy: policy,
    }
    try {
      await post('/api/setup', body)
      setDone(true)
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  const current = STEPS.indexOf(step)
  const errorBanner = error && (
    <Banner kind="error" title={error.message}>
      {error.detail}
    </Banner>
  )

  if (done) {
    return (
      <div className="center-page">
        <motion.div className="card panel done-card" initial={{ opacity: 0, scale: 0.9, y: 12 }} animate={{ opacity: 1, scale: 1, y: 0 }} transition={{ type: 'spring', stiffness: 260, damping: 22 }}>
          <svg className="done-mark" viewBox="0 0 52 52" width={56} height={56} aria-hidden>
            <motion.circle cx="26" cy="26" r="24" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.6, delay: 0.15 }} />
            <motion.path d="M15 27l7 7 15-15" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.4, delay: 0.65 }} />
          </svg>
          <h1>{t('done.title')}</h1>
          <p className="muted">{t('done.text', { user: admin.username.trim() || 'admin' })}</p>
          <Button
            variant="primary"
            onClick={() => {
              qc.setQueryData(['setup'], { required: false })
              navigate('/login', { replace: true })
            }}
          >
            {t('done.signin')}
          </Button>
        </motion.div>
      </div>
    )
  }

  const footer = (opts: { test?: TestStep; testDisabled?: boolean; optional?: boolean; submitLabel?: string }) => (
    <div className="panel-foot">
      <Button variant="ghost" onClick={back} disabled={current === 0}>
        {t('back')}
      </Button>
      <div className="row foot-actions">
        {opts.optional && (
          <Button variant="ghost" onClick={skip}>
            {t('skip')}
          </Button>
        )}
        {opts.test && (
          <Button onClick={() => void test(opts.test!)} busy={testing === opts.test} disabled={opts.testDisabled}>
            {testing === opts.test ? t('checking') : t('check')}
          </Button>
        )}
        <Button variant="primary" onClick={next} disabled={!canNext[step]}>
          {t('next')}
        </Button>
      </div>
    </div>
  )

  const chipFor = (s: StepId): { tone: Tone; label: string } | null => {
    if (OPTIONAL.includes(s)) {
      const off = (s === 'inventory' && !inv.enabled) || (s === 'umbrella' && !um.enabled) || (s === 'geoip' && (!geo.enabled || geo.databases.every((x) => !x.trim())))
      if (off) return { tone: 'off', label: t('chip.skipped') }
    }
    if (s === 'nats' && nats.url.trim() === '') return { tone: 'info', label: t('chip.builtin') }
    if (!['openbao', 'postgres', 'clickhouse', 'nats', 'inventory', 'umbrella', 'geoip'].includes(s)) return null
    const c = checks[s as TestStep]
    if (!c) return { tone: 'warn', label: t('chip.none') }
    if (c.key !== keyOf(s as TestStep)) return { tone: 'warn', label: t('chip.changed') }
    return c.result.ok ? { tone: 'ok', label: t('chip.ok') } : { tone: 'error', label: t('chip.fail') }
  }

  const checkView = (s: TestStep, extra?: ReactNode) => <CheckView check={checks[s]} currentKey={keyOf(s)} t={t} extra={extra} />

  return (
    <MotionConfig reducedMotion="user">
      <div className="wizard">
        <header className="wizard-top">
          <div className="brand">
            <Brand />
            <span className="brand-sub wizard-sub">{t('title')}</span>
          </div>
          <Preferences />
        </header>
        <div className="wizard-body">
          <nav aria-label={t('title')}>
            <ol className="steps" data-native-scroll>
              {STEPS.map((s, i) => {
                const isDone = i < current || (i <= reached && canNext[s] && s !== step)
                return (
                  <li key={s}>
                    <button type="button" className={`step ${s === step ? 'current' : ''} ${isDone ? 'done' : ''}`} disabled={i > reached || (!codeOk && s !== 'code')} aria-current={s === step ? 'step' : undefined} onClick={() => setStep(s)}>
                      {s === step && <motion.span layoutId="step-current" className="step-highlight" transition={spring} />}
                      <span className="num">
                        {isDone ? (
                          <Pop>
                            <Check size={14} />
                          </Pop>
                        ) : (
                          i + 1
                        )}
                      </span>
                      <span className="step-label">
                        <span>{t(`step.${s}`)}</span>
                        <small>{t(`step.${s}.sub`)}</small>
                      </span>
                    </button>
                  </li>
                )
              })}
            </ol>
          </nav>
          <main className="card panel">
            <div className="progress" role="progressbar" aria-valuemin={1} aria-valuemax={STEPS.length} aria-valuenow={current + 1}>
              <motion.span initial={false} animate={{ width: `${((current + 1) / STEPS.length) * 100}%` }} transition={{ type: 'spring', stiffness: 140, damping: 22 }} />
            </div>
            <AnimatePresence mode="wait" custom={dir} initial={false}>
              <motion.div key={step} className="step-view" custom={dir} variants={stepVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.26, ease: [0.22, 1, 0.36, 1] }}>
                {step === 'code' && (
                  <form
                    className="stack"
                    noValidate
                    onSubmit={(e) => {
                      e.preventDefault()
                      void verifyCode()
                    }}
                  >
                    <Head refEl={heading} title={t('code.title')} text={t('code.text')} />
                    <div className="section">
                      <div className="section-title">{t('code.where')}</div>
                      <Rows
                        rows={[
                          [t('code.logs'), <code key="l">docker compose logs flow | grep setup_code</code>],
                          [t('code.file'), <code key="f">$FLOW_DATA_DIR/setup-token</code>],
                          [t('code.env'), <code key="e">FLOW_SETUP_TOKEN</code>],
                        ]}
                      />
                    </div>
                    <Field label={t('code.label')}>{(id) => <Input id={id} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" spellCheck={false} autoFocus />}</Field>
                    {errorBanner}
                    <div className="panel-foot">
                      <span />
                      <Button variant="primary" type="submit" busy={busy} disabled={!code.trim()}>
                        {t('code.verify')}
                      </Button>
                    </div>
                  </form>
                )}

                {step === 'general' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('general.title')} text={t('general.text')} />
                    <Field label={t('general.language')}>
                      {() => (
                        <Choices
                          label={t('general.language')}
                          value={general.language}
                          onChange={(l) => {
                            setGeneral({ ...general, language: l })
                            setLocale(l)
                          }}
                          options={[
                            { value: 'ru', title: t('lang.ru') },
                            { value: 'en', title: t('lang.en') },
                          ]}
                        />
                      )}
                    </Field>
                    <Field label={t('general.theme')}>
                      {() => (
                        <div className="choices choices-3" role="radiogroup" aria-label={t('general.theme')}>
                          {(['light', 'dark', 'system'] as SetupTheme[]).map((v) => (
                            <Choice
                              key={v}
                              aria-checked={general.theme === v}
                              onClick={(e) => {
                                setGeneral({ ...general, theme: v })
                                const real = v === 'system' ? (window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : v
                                setTheme(real, originOf(e))
                              }}
                            >
                              <span className={`swatch swatch-${v}`} aria-hidden />
                              <span>
                                <span className="choice-title">{t(v === 'system' ? 'theme.system' : `theme.${v}`)}</span>
                                <br />
                                <span className="hint">{t(`theme.${v}.desc`)}</span>
                              </span>
                            </Choice>
                          ))}
                        </div>
                      )}
                    </Field>
                    <Field label={t('general.timezone')} hint={t('general.timezone.hint')}>
                      {(id) => <TimezoneSelect id={id} value={general.timezone} onChange={(timezone) => setGeneral({ ...general, timezone })} />}
                    </Field>
                    <Field label={t('general.public')} hint={publicValid ? t('general.public.hint') : t('general.public.bad')}>
                      {(id) => <Input id={id} value={general.public_url} spellCheck={false} placeholder="https://flow.example.com" aria-invalid={!publicValid || undefined} onChange={(e) => setGeneral({ ...general, public_url: e.target.value })} />}
                    </Field>
                    {footer({})}
                  </div>
                )}

                {step === 'openbao' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('ob.title')} text={t('ob.text')} />
                    <div className="grid-3">
                      <Field label={t('ob.addr')} hint={t('ob.addr.hint')}>{(id) => <Input id={id} value={ob.addr} placeholder="http://openbao:8200" spellCheck={false} onChange={(e) => setOb({ ...ob, addr: e.target.value })} />}</Field>
                      <Field label={t('ob.mount')} hint={t('ob.mount.hint')}>{(id) => <Input id={id} value={ob.mount} spellCheck={false} onChange={(e) => setOb({ ...ob, mount: e.target.value })} />}</Field>
                    </div>
                    <Field label={t('ob.auth')}>
                      {() => (
                        <Choices
                          label={t('ob.auth')}
                          value={ob.auth}
                          onChange={(auth) => setOb({ ...ob, auth })}
                          options={(['approle', 'token'] as const).map((a) => ({ value: a, title: t(`ob.auth.${a}`), hint: t(`ob.auth.${a}.hint`) }))}
                        />
                      )}
                    </Field>
                    {ob.auth === 'token' ? (
                      <SecretField label={t('ob.token')} value={ob.token} onChange={(token) => setOb({ ...ob, token })} isSet={set.obToken} />
                    ) : (
                      <div className="grid-2">
                        <SecretField label={t('ob.roleId')} value={ob.role_id} onChange={(role_id) => setOb({ ...ob, role_id })} isSet={set.obRole} />
                        <SecretField label={t('ob.secretId')} value={ob.secret_id} onChange={(secret_id) => setOb({ ...ob, secret_id })} isSet={set.obSecret} />
                      </div>
                    )}
                    {checkView('openbao')}
                    {errorBanner}
                    {footer({ test: 'openbao', testDisabled: !ob.addr.trim() || (ob.auth === 'token' ? !ob.token && !set.obToken : (!ob.role_id.trim() && !set.obRole) || (!ob.secret_id && !set.obSecret)) })}
                  </div>
                )}

                {step === 'postgres' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('pg.title')} text={t('pg.text')} />
                    <div className="grid-3">
                      <Field label={t('pg.host')}>{(id) => <Input id={id} value={pg.host} placeholder="postgres" spellCheck={false} onChange={(e) => setPg({ ...pg, host: e.target.value })} />}</Field>
                      <Field label={t('pg.port')}>{(id) => <Input id={id} value={String(pg.port)} inputMode="numeric" onChange={(e) => setPg({ ...pg, port: Number(e.target.value.replace(/\D/g, '')) || 0 })} />}</Field>
                    </div>
                    <div className="grid-2">
                      <Field label={t('pg.database')}>{(id) => <Input id={id} value={pg.database} spellCheck={false} onChange={(e) => setPg({ ...pg, database: e.target.value })} />}</Field>
                      <Field label={t('pg.sslmode')}>
                        {(id) => (
                          <Select id={id} value={pg.sslmode} onChange={(e) => setPg({ ...pg, sslmode: e.target.value })}>
                            {SSL_MODES.map((m) => (
                              <option key={m} value={m}>
                                {m}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                      <Field label={t('pg.user')}>{(id) => <Input id={id} value={pg.username} spellCheck={false} autoComplete="off" onChange={(e) => setPg({ ...pg, username: e.target.value })} />}</Field>
                      <SecretField label={t('pg.password')} value={pg.password} onChange={(password) => setPg({ ...pg, password })} isSet={set.pg} />
                    </div>
                    {checkView(
                      'postgres',
                      hasState && (
                        <Banner kind="warn" title={t('pg.state')}>
                          <p>{t('pg.state.text')}</p>
                          <div style={{ marginTop: 10 }}>
                            <Switch checked={pg.attach_existing} onChange={(v) => setPg({ ...pg, attach_existing: v })} label={t('pg.attach')} />
                          </div>
                        </Banner>
                      ),
                    )}
                    {errorBanner}
                    {footer({ test: 'postgres', testDisabled: !pg.host.trim() || !pg.database.trim() || !pg.username.trim() || (!pg.password && !set.pg) })}
                  </div>
                )}

                {step === 'clickhouse' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('ch.title')} text={t('ch.text')} />
                    <div className="grid-2">
                      <Field label={t('ch.addr')} hint={t('ch.addr.hint')}>{(id) => <Input id={id} value={ch.addr} placeholder="clickhouse:9000" spellCheck={false} onChange={(e) => setCh({ ...ch, addr: e.target.value })} />}</Field>
                      <Field label={t('ch.database')}>{(id) => <Input id={id} value={ch.database} spellCheck={false} onChange={(e) => setCh({ ...ch, database: e.target.value })} />}</Field>
                      <Field label={t('ch.user')}>{(id) => <Input id={id} value={ch.username} spellCheck={false} autoComplete="off" onChange={(e) => setCh({ ...ch, username: e.target.value })} />}</Field>
                      <SecretField label={t('ch.password')} value={ch.password} onChange={(password) => setCh({ ...ch, password })} isSet={set.ch} />
                    </div>
                    <Switch checked={ch.secure} onChange={(secure) => setCh({ ...ch, secure })} label={t('ch.secure')} hint={t('ch.secure.hint')} />
                    <section className="section">
                      <div className="section-title">{t('ch.retention')}</div>
                      <p className="hint">{t('ch.retention.text')}</p>
                      <div className="retention-grid">
                        {(['raw_days', 'd1m', 'd5m', 'd1h'] as const).map((k) => (
                          <div key={k} className="field">
                            <label>{t(`ret.${k}`)}</label>
                            <Stepper value={ret[k]} min={1} max={3650} suffix={t('days')} onChange={(v) => setRet({ ...ret, [k]: v })} label={t(`ret.${k}`)} />
                          </div>
                        ))}
                      </div>
                    </section>
                    {checkView('clickhouse')}
                    {errorBanner}
                    {footer({ test: 'clickhouse', testDisabled: !ch.addr.trim() || !ch.database.trim() })}
                  </div>
                )}

                {step === 'nats' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('nats.title')} text={t('nats.text')} />
                    <Field label={t('nats.url')} hint={t('nats.url.hint')} optional={t('optional')}>
                      {(id) => <Input id={id} value={nats.url} placeholder="nats://nats:4222" spellCheck={false} onChange={(e) => setNats({ url: e.target.value })} />}
                    </Field>
                    {nats.url.trim() === '' ? <Banner kind="info" title={t('nats.builtin')} /> : checkView('nats')}
                    {errorBanner}
                    {footer({ test: nats.url.trim() ? 'nats' : undefined })}
                  </div>
                )}

                {step === 'collector' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('col.title')} text={t('col.text')} />
                    <div className="grid-2">
                      <Field label={t('col.netflow')} hint={t('col.netflow.hint')}>{(id) => <Input id={id} value={col.netflow_addr} spellCheck={false} onChange={(e) => setCol({ ...col, netflow_addr: e.target.value })} />}</Field>
                      <Field label={t('col.sflow')} hint={t('col.sflow.hint')}>{(id) => <Input id={id} value={col.sflow_addr} spellCheck={false} onChange={(e) => setCol({ ...col, sflow_addr: e.target.value })} />}</Field>
                    </div>
                    <Field label={t('col.sampling')} hint={t('col.sampling.hint')}>
                      {() => (
                        <div className="nb-stepper">
                          <Stepper value={col.default_sampling_rate} min={1} max={65535} onChange={(v) => setCol({ ...col, default_sampling_rate: v })} label={t('col.sampling')} />
                        </div>
                      )}
                    </Field>
                    <RouterHints collector={col} publicURL={general.public_url} t={t} />
                    {footer({})}
                  </div>
                )}

                {step === 'inventory' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('inv.title')} text={t('inv.text')} />
                    <Switch checked={inv.enabled} onChange={(enabled) => setInv({ ...inv, enabled })} label={t('inv.enable')} />
                    <Reveal on={inv.enabled} off={<Banner kind="info" title={t('inv.off')} />}>
                      <Field label={t('inv.url')}>{(id) => <Input id={id} value={inv.url} placeholder="https://inventory.example.net" spellCheck={false} onChange={(e) => setInv({ ...inv, url: e.target.value })} />}</Field>
                      <SecretField label={t('inv.token')} value={inv.token} onChange={(token) => setInv({ ...inv, token })} isSet={false} hint={t('inv.token.hint')} />
                      <Field label={t('inv.interval')}>
                        {(id) => (
                          <Select id={id} value={inv.interval} onChange={(e) => setInv({ ...inv, interval: e.target.value })}>
                            {INTERVALS.map((i) => (
                              <option key={i} value={i}>
                                {i}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Field>
                      {checkView('inventory')}
                    </Reveal>
                    {errorBanner}
                    {footer({ optional: true, test: inv.enabled ? 'inventory' : undefined, testDisabled: !/^https?:\/\/\S+/.test(inv.url.trim()) || !inv.token })}
                  </div>
                )}

                {step === 'umbrella' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('um.title')} text={t('um.text')} />
                    <Switch checked={um.enabled} onChange={(enabled) => setUm({ ...um, enabled })} label={t('um.enable')} />
                    <Reveal on={um.enabled} off={<Banner kind="info" title={t('um.off')} />}>
                      <div className="section">
                        <div className="section-title">{t('um.where')}</div>
                        <p>{t('um.where.text')}</p>
                      </div>
                      <Field label={t('um.url')} hint={t('um.url.hint')}>{(id) => <Input id={id} value={um.ingest_url} placeholder="https://umbrella.example.com/api/ingest/umbrella-flow" spellCheck={false} onChange={(e) => setUm({ ...um, ingest_url: e.target.value })} />}</Field>
                      <SecretField label={t('um.token')} value={um.token} onChange={(token) => setUm({ ...um, token })} isSet={false} hint={t('um.check.hint')} />
                      {checkView('umbrella')}
                    </Reveal>
                    {errorBanner}
                    {footer({ optional: true, test: um.enabled ? 'umbrella' : undefined, testDisabled: !/^https?:\/\/\S+/.test(um.ingest_url.trim()) || !um.token })}
                  </div>
                )}

                {step === 'geoip' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('geo.title')} text={t('geo.text')} />
                    <Switch checked={geo.enabled} onChange={(enabled) => setGeo({ ...geo, enabled })} label={t('geo.files')} />
                    <Reveal on={geo.enabled} off={<Banner kind="info" title={t('geo.off')} />}>
                      <div className="stack geo-list">
                        {geo.databases.map((p, i) => (
                          <div key={i} className="geo-row">
                            <Input value={p} spellCheck={false} placeholder="/geoip/GeoLite2-City.mmdb" onChange={(e) => setGeo({ ...geo, databases: geo.databases.map((x, j) => (j === i ? e.target.value : x)) })} aria-label={t('geo.files')} />
                            <button type="button" className="icon-btn danger-icon" onClick={() => setGeo({ ...geo, databases: geo.databases.filter((_, j) => j !== i) })} aria-label={t('geo.remove')}>
                              <Trash2 size={15} />
                            </button>
                          </div>
                        ))}
                        <div>
                          <Button variant="ghost" onClick={() => setGeo({ ...geo, databases: [...geo.databases, ''] })}>
                            <Plus size={15} /> {t('geo.add')}
                          </Button>
                        </div>
                      </div>
                      {checkView('geoip')}
                    </Reveal>
                    {errorBanner}
                    {footer({ optional: true, test: geo.enabled ? 'geoip' : undefined, testDisabled: geo.databases.every((x) => !x.trim()) })}
                  </div>
                )}

                {step === 'admin' && (
                  <form
                    className="stack"
                    noValidate
                    onSubmit={(e) => {
                      e.preventDefault()
                      next()
                    }}
                  >
                    <Head refEl={heading} title={t('ad.title')} text={t('ad.text')} />
                    {attach && <Banner kind="info" title={t('ad.skipped')} />}
                    <div className="grid-2">
                      <Field label={t('ad.username')} hint={admin.username && !USERNAME.test(admin.username.trim()) ? t('ad.username.bad') : undefined}>
                        {(id) => <Input id={id} value={admin.username} autoComplete="username" spellCheck={false} onChange={(e) => setAdmin({ ...admin, username: e.target.value })} />}
                      </Field>
                      <Field label={t('ad.name')} optional={t('optional')}>{(id) => <Input id={id} value={admin.name} autoComplete="name" onChange={(e) => setAdmin({ ...admin, name: e.target.value })} />}</Field>
                    </div>
                    <Field label={t('ad.email')} optional={t('optional')}>{(id) => <Input id={id} type="email" value={admin.email} autoComplete="email" onChange={(e) => setAdmin({ ...admin, email: e.target.value })} />}</Field>
                    <div className="grid-2">
                      <Field label={t('ad.password')}>{(id) => <Password id={id} value={admin.password} autoComplete="new-password" onChange={(e) => setAdmin({ ...admin, password: e.target.value })} />}</Field>
                      <Field label={t('ad.confirm')}>{(id) => <Password id={id} value={admin.confirm} autoComplete="new-password" onChange={(e) => setAdmin({ ...admin, confirm: e.target.value })} />}</Field>
                    </div>
                    <PolicyChecklist policy={policy} password={admin.password} username={admin.username.trim()} confirm={admin.confirm} />
                    <section className="section">
                      <header className="section-head">
                        <h3>{t(JSON.stringify(policy) === JSON.stringify(DEFAULT_POLICY) ? 'pol.default' : 'pol.custom')}</h3>
                        <Button variant="ghost" aria-expanded={policyOpen} onClick={() => setPolicyOpen((o) => !o)}>
                          {t(policyOpen ? 'pol.collapse' : 'pol.change')}
                        </Button>
                      </header>
                      <p className="hint">{t('pol.later')}</p>
                      <AnimatePresence initial={false}>
                        {policyOpen && (
                          <motion.div key="policy" className="reveal-box" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.3 }}>
                            <PolicyEditor value={policy} onChange={setPolicy} />
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </section>
                    {footer({})}
                  </form>
                )}

                {step === 'review' && (
                  <div className="stack">
                    <Head refEl={heading} title={t('rv.title')} text={t('rv.text')} />
                    <div className="summary">
                      <Summary title={t('step.general')} edit={() => setStep('general')} t={t} rows={[[t('rv.language'), t(`lang.${general.language}`)], [t('rv.theme'), t(general.theme === 'system' ? 'theme.system' : `theme.${general.theme}`)], [t('rv.timezone'), zoneLabel(general.timezone)], [t('rv.public'), <code key="p">{general.public_url.trim() || '—'}</code>]]} />
                      <Summary title="OpenBao" chip={chipFor('openbao')} edit={() => setStep('openbao')} t={t} rows={[[t('rv.address'), <code key="a">{ob.addr}</code>], [t('ob.mount'), ob.mount], [t('rv.auth'), t(`ob.auth.${ob.auth}`)]]} />
                      <Summary
                        title="PostgreSQL"
                        chip={chipFor('postgres')}
                        edit={() => setStep('postgres')}
                        t={t}
                        rows={[[t('rv.database'), <code key="d">{`${pg.username}@${pg.host}:${pg.port}/${pg.database}`}</code>], [t('pg.sslmode'), pg.sslmode], [t('rv.secret'), t(pg.password ? 'rv.secret.new' : 'rv.secret.set')], ...(hasState ? ([[t('rv.state'), t(pg.attach_existing ? 'rv.attach' : 'no')]] as [string, string][]) : [])]}
                      />
                      <Summary title="ClickHouse" chip={chipFor('clickhouse')} edit={() => setStep('clickhouse')} t={t} rows={[[t('rv.database'), <code key="c">{`${ch.username}@${ch.addr}/${ch.database}${ch.secure ? ' (TLS)' : ''}`}</code>], [t('rv.retention'), `${ret.raw_days} / ${ret.d1m} / ${ret.d5m} / ${ret.d1h}`]]} />
                      <Summary title={t('step.nats')} chip={chipFor('nats')} edit={() => setStep('nats')} t={t} rows={[[t('rv.queue'), nats.url.trim() ? <code key="n">{nats.url.trim()}</code> : t('chip.builtin')]]} />
                      <Summary title={t('step.collector')} edit={() => setStep('collector')} t={t} rows={[[t('rv.ports'), <code key="p">{`NetFlow/IPFIX ${col.netflow_addr || '—'} · sFlow ${col.sflow_addr || '—'}`}</code>], [t('col.sampling'), `1:${col.default_sampling_rate}`]]} />
                      <Summary title="Inventory DB" chip={chipFor('inventory')} edit={() => setStep('inventory')} t={t} rows={inv.enabled ? [[t('rv.address'), <code key="i">{inv.url}</code>], [t('inv.interval'), inv.interval]] : [[t('step.inventory'), t('rv.off')]]} />
                      <Summary title="Umbrella" chip={chipFor('umbrella')} edit={() => setStep('umbrella')} t={t} rows={um.enabled ? [[t('rv.address'), <code key="u">{um.ingest_url}</code>]] : [[t('step.umbrella'), t('rv.off')]]} />
                      <Summary title="GeoIP" chip={chipFor('geoip')} edit={() => setStep('geoip')} t={t} rows={geo.enabled && geo.databases.some((x) => x.trim()) ? [[t('rv.files'), geo.databases.filter((x) => x.trim()).join(', ')]] : [[t('step.geoip'), t('rv.off')]]} />
                      <Summary title={t('step.admin')} edit={() => setStep('admin')} t={t} rows={[[t('rv.user'), attach && adminEmpty ? t('ad.skipped') : [admin.username.trim(), admin.name.trim(), admin.email.trim()].filter(Boolean).join(' · ')], [t('pol.min'), String(policy.min_length)]]} />
                    </div>
                    {error && (
                      <Banner kind="error" title={`${t('rv.failed')}: ${error.message}`}>
                        {error.detail}
                      </Banner>
                    )}
                    <div className="panel-foot">
                      <Button variant="ghost" onClick={back}>
                        {t('back')}
                      </Button>
                      <Button variant="primary" onClick={() => void finish()} busy={busy} disabled={!STEPS.slice(0, -1).every((s) => canNext[s])}>
                        {busy ? t('rv.finishing') : t('rv.finish')}
                      </Button>
                    </div>
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </main>
        </div>
      </div>
    </MotionConfig>
  )
}

function Head({ title, text, refEl }: { title: string; text: string; refEl: React.RefObject<HTMLHeadingElement | null> }) {
  return (
    <div className="panel-head">
      <h1 ref={refEl} tabIndex={-1} style={{ outline: 'none' }}>
        {title}
      </h1>
      <p className="muted">{text}</p>
    </div>
  )
}

function Reveal({ on, off, children }: { on: boolean; off: ReactNode; children: ReactNode }) {
  return (
    <AnimatePresence initial={false} mode="wait">
      {on ? (
        <motion.div key="on" className="reveal-box" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}>
          <div className="stack">{children}</div>
        </motion.div>
      ) : (
        <motion.div key="off" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>
          {off}
        </motion.div>
      )}
    </AnimatePresence>
  )
}

type T = (k: string, v?: Record<string, string | number>) => string

function CheckView({ check, currentKey, t, extra }: { check: CheckState; currentKey: string; t: T; extra?: ReactNode }) {
  if (!check) return null
  if (check.key !== currentKey) return <Banner kind="info" title={t('check.changed')} />
  const r = check.result
  const rows = Object.entries(r.details ?? {})
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => [t(`det.${k}`).startsWith('det.') ? k : t(`det.${k}`), typeof v === 'boolean' ? t(v ? 'yes' : 'no') : Array.isArray(v) ? v.join(', ') : String(v)] as [string, string])
  return (
    <>
      <Banner kind={r.ok ? 'ok' : 'error'} title={r.ok ? t('check.ok') : t('check.fail')}>
        {r.error && <div>{r.error}</div>}
        {rows.length > 0 && <Rows rows={rows} />}
      </Banner>
      {r.ok && extra}
    </>
  )
}

function Summary({ title, rows, edit, t, chip }: { title: string; rows: [ReactNode, ReactNode][]; edit: () => void; t: T; chip?: { tone: Tone; label: string } | null }) {
  return (
    <section className="section">
      <header className="section-head">
        <h3>
          {title}
          {chip && <Chip tone={chip.tone}>{chip.label}</Chip>}
        </h3>
        <Button variant="ghost" size="sm" onClick={edit}>
          {t('rv.edit')}
        </Button>
      </header>
      <Rows rows={rows} />
    </section>
  )
}

function TimezoneSelect({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const zones = useMemo(timezones, [])
  return (
    <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
      {zones.map((z) => (
        <option key={z.id} value={z.id}>
          {z.label}
        </option>
      ))}
    </Select>
  )
}

function portOf(addr: string, fallback: string) {
  const m = /:(\d+)$/.exec(addr.trim())
  return m ? m[1] : fallback
}

function RouterHints({ collector, publicURL, t }: { collector: Collector; publicURL: string; t: T }) {
  let host = window.location.hostname
  try {
    host = new URL(publicURL).hostname || host
  } catch {
    // The browser's host then.
  }
  const nf = portOf(collector.netflow_addr, '2055')
  const sf = portOf(collector.sflow_addr, '6343')
  const blocks: [string, string][] = [
    ['Cisco IOS XE (IPFIX)', `flow exporter UMBRELLA-FLOW\n destination ${host}\n transport udp ${nf}\n export-protocol ipfix\n template data timeout 60`],
    ['Juniper (IPFIX)', `set forwarding-options sampling instance FLOW family inet output flow-server ${host} port ${nf}\nset forwarding-options sampling instance FLOW family inet output flow-server ${host} version-ipfix template ipv4`],
    ['Arista / Huawei (sFlow)', `sflow destination ${host} ${sf}\nsflow sample 1000\nsflow run`],
  ]
  return (
    <section className="section">
      <div className="section-title">{t('col.routers')}</div>
      <p className="hint">{t('col.routers.text', { host })}</p>
      <div className="row router-targets">
        <Chip tone="info">NetFlow / IPFIX → {host}:{nf}/udp</Chip>
        <Chip tone="purple">sFlow → {host}:{sf}/udp</Chip>
      </div>
      <div className="router-snippets">
        {blocks.map(([name, text]) => (
          <div key={name}>
            <div className="snippet-title">{name}</div>
            <pre className="code-block">{text}</pre>
          </div>
        ))}
      </div>
    </section>
  )
}
