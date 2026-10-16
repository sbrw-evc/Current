import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BellRing, CheckCircle2, ChevronRight, Circle, Database, Router, ServerCrash, X } from 'lucide-react'
import { Link } from 'react-router-dom'
import { get, type ApiError } from '../../api/client'
import { useExporters } from '../../api/queries'
import type { UmbrellaAPI, UmbrellaIngest } from '../../api/beacon'
import { useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { useSession } from '../../shell/session'
import { useDetectorStatus, useRules } from '../detector/api'
import { useDevices } from '../devices/api'
import type { BmpView } from '../settings/BmpModel'
import { useInventoryIntegration } from '../settings/LedgerIntegration'
import { attention, steps, stepsDone, type Attention, type Step } from './model'

const strings: Dict = {
  en: {
    'att.title': 'Needs attention',
    'att.ok': 'All is well',
    'att.ok.title': 'No active alerts, every exporter is sending flows',
    'att.alerts': 'Active detector alerts: {n}',
    'att.alerts.sub': 'Traffic anomalies the detector is reporting now',
    'att.silent': 'Exporters without flows for over 5 minutes: {n}',
    'att.silent.sub': 'Check the device, its flow export or the path to the collector',
    'att.devicesdown': 'Unreachable network devices: {n}',
    'att.devicesdown.sub': 'Two polls in a row failed; an incident is open in Beacon when it is connected',
    'att.noinventory': 'Exporters missing from Ledger: {n}',
    'att.noinventory.sub': 'Their flows get no site, role or interface names',
    'att.open': 'Open',
    'ob.title': 'First steps',
    'ob.lead': 'What is left so Current shows named, enriched traffic and reports incidents to Beacon.',
    'ob.progress': '{done} of {total}',
    'ob.done': 'Done',
    'ob.optional': 'optional',
    'ob.hide': 'Hide',
    'ob.step.exporters': 'Send flows to the collector',
    'ob.step.exporters.text': 'Point NetFlow, IPFIX or sFlow of the routers at Current; each device appears among the exporters with its first flow.',
    'ob.step.exporters.go': 'Exporters',
    'ob.step.detector': 'Turn on the detector rules',
    'ob.step.detector.text': 'DDoS, overload and anomaly rules watch the traffic and raise alerts.',
    'ob.step.detector.go': 'Rules',
    'ob.step.inventory': 'Connect Ledger',
    'ob.step.inventory.text': 'Device names, sites and interface roles for every flow.',
    'ob.step.inventory.go': 'Connect',
    'ob.step.umbrella': 'Connect Beacon',
    'ob.step.umbrella.text': 'Detector alerts become incidents, and discovered dependencies go to the CMDB.',
    'ob.step.umbrella.go': 'Connect',
    'ob.step.devices': 'Add network devices',
    'ob.step.devices.text': 'Current polls them: interface load, neighbours, clients, and an incident in Beacon when one goes down.',
    'ob.step.devices.go': 'Devices',
    'ob.step.bmp': 'Receive BGP routes over BMP',
    'ob.step.bmp.text': 'AS paths and communities for each flow.',
    'ob.step.bmp.go': 'Set up',
  },
  ru: {
    'att.title': 'Требует внимания',
    'att.ok': 'Всё в порядке',
    'att.ok.title': 'Активных оповещений нет, все экспортёры присылают потоки',
    'att.alerts': 'Активные оповещения детектора: {n}',
    'att.alerts.sub': 'Аномалии трафика, о которых детектор сообщает сейчас',
    'att.silent': 'Экспортёры без потоков дольше 5 минут: {n}',
    'att.silent.sub': 'Проверьте устройство, экспорт потоков или путь до коллектора',
    'att.devicesdown': 'Недоступные сетевые устройства: {n}',
    'att.devicesdown.sub': 'Два опроса подряд не удались; если Beacon подключён, в нём открыт инцидент',
    'att.noinventory': 'Экспортёры, которых нет в Ledger: {n}',
    'att.noinventory.sub': 'Их потоки остаются без площадки, роли и имён интерфейсов',
    'att.open': 'Открыть',
    'ob.title': 'Первые шаги',
    'ob.lead': 'Что осталось, чтобы Current показывал трафик с именами и обогащением и передавал инциденты в Beacon.',
    'ob.progress': '{done} из {total}',
    'ob.done': 'Готово',
    'ob.optional': 'по желанию',
    'ob.hide': 'Скрыть',
    'ob.step.exporters': 'Направьте потоки на коллектор',
    'ob.step.exporters.text': 'Настройте NetFlow, IPFIX или sFlow на маршрутизаторах; устройство появится среди экспортёров с первым потоком.',
    'ob.step.exporters.go': 'Экспортёры',
    'ob.step.detector': 'Включите правила детектора',
    'ob.step.detector.text': 'Правила DDoS, перегрузки и аномалий следят за трафиком и создают оповещения.',
    'ob.step.detector.go': 'Правила',
    'ob.step.inventory': 'Подключите Ledger',
    'ob.step.inventory.text': 'Имена устройств, площадки и роли интерфейсов для каждого потока.',
    'ob.step.inventory.go': 'Подключить',
    'ob.step.umbrella': 'Подключите Beacon',
    'ob.step.umbrella.text': 'Оповещения детектора станут инцидентами, а найденные зависимости попадут в CMDB.',
    'ob.step.umbrella.go': 'Подключить',
    'ob.step.devices': 'Добавьте сетевые устройства',
    'ob.step.devices.text': 'Current будет их опрашивать: загрузка интерфейсов, соседи, клиенты и инцидент в Beacon, если устройство упадёт.',
    'ob.step.devices.go': 'Устройства',
    'ob.step.bmp': 'Принимайте BGP-маршруты по BMP',
    'ob.step.bmp.text': 'AS-пути и community для каждого потока.',
    'ob.step.bmp.go': 'Настроить',
  },
}

const ICONS = { alerts: BellRing, devicesdown: ServerCrash, silent: Router, noinventory: Database }

// useAttention reads the alerts and exporters the role may see.
function useAttention() {
  const { can } = useSession()
  const seeAlerts = can('detector:view')
  const seeExporters = can('exporters:view')
  const seeDevices = can('devices:view')
  const det = useDetectorStatus(30e3, seeAlerts)
  const exp = useExporters(seeExporters)
  const devs = useDevices(seeDevices)
  const alerts = seeAlerts ? det.data?.alerts : []
  const exporters = seeExporters ? exp.data?.results : []
  const ready = (!seeAlerts || det.data !== undefined || det.isError) && (!seeExporters || exp.data !== undefined || exp.isError)
  return { items: attention(alerts, exporters, Date.now(), seeDevices ? devs.data?.results : undefined), ready, any: seeAlerts || seeExporters }
}

// HealthChip is the Overview's one-line verdict: «All is well» or how many things need a look.
export function HealthChip() {
  const t = useT(strings)
  const { items, ready, any } = useAttention()
  if (!any || !ready) return null
  if (items.length === 0)
    return (
      <span className="pill chip-soft tone-ok" title={t('att.ok.title')}>
        <span className="chip-dot" aria-hidden />
        {t('att.ok')}
      </span>
    )
  return null
}

// AttentionCard lists what needs a look now; nothing when all is well.
export function AttentionCard() {
  const t = useT(strings)
  const { locale } = useLocale()
  const { items } = useAttention()
  if (items.length === 0) return null
  return (
    <section className="card att-card" aria-labelledby="att-title">
      <h2 id="att-title" className="card-title">
        {t('att.title')}
      </h2>
      <ul className="att-list">
        {items.map((a) => (
          <AttentionRow key={a.id} item={a} text={t(`att.${a.id}`, { n: num(a.count, locale) })} sub={t(`att.${a.id}.sub`)} open={t('att.open')} />
        ))}
      </ul>
    </section>
  )
}

function AttentionRow({ item, text, sub, open }: { item: Attention; text: string; sub: string; open: string }) {
  const Icon = ICONS[item.id]
  return (
    <li>
      <Link to={item.path} className={`att-row att-${item.tone}`}>
        <span className="att-icon">
          <Icon size={17} aria-hidden />
        </span>
        <span className="att-text">
          <span className="att-name">{text}</span>
          <span className="muted">{sub}</span>
        </span>
        <span className="att-go">
          {open}
          <ChevronRight size={15} aria-hidden />
        </span>
      </Link>
    </li>
  )
}

const HIDDEN = 'flow.home.steps.hidden'

function readHidden() {
  try {
    return localStorage.getItem(HIDDEN) === '1'
  } catch {
    return false
  }
}

// FirstSteps is Beacon's «first steps» checklist: shown until every required step is done or the
// user hides it.
export function FirstSteps() {
  const t = useT(strings)
  const { can } = useSession()
  const [hidden, setHidden] = useState(readHidden)
  const exp = useExporters(can('exporters:view') && !hidden)
  const rules = useRules(can('detector:view') && !hidden)
  const inv = useInventoryIntegration(can('settings.inventory:view') && !hidden)
  const opt = { retry: false, staleTime: 60e3 } as const
  const ingest = useQuery({ queryKey: ['settings', 'umbrella'], queryFn: ({ signal }) => get<UmbrellaIngest>('/api/settings/umbrella', signal), enabled: can('settings.umbrella:view') && !hidden, ...opt })
  const api = useQuery({ queryKey: ['settings', 'umbrella', 'api'], queryFn: ({ signal }) => get<UmbrellaAPI>('/api/settings/umbrella/api', signal), enabled: can('settings.umbrella:view') && !hidden, ...opt })
  const devs = useDevices(can('devices:view') && !hidden)
  const bmp = useQuery<BmpView, ApiError>({ queryKey: ['bmp'], queryFn: ({ signal }) => get<BmpView>('/api/settings/bmp', signal), enabled: can('settings.bmp:view') && !hidden, ...opt })
  if (hidden) return null
  const list = steps({
    exporters: can('exporters:view') ? exp.data?.results : undefined,
    rules: can('detector:view') ? rules.data : undefined,
    inventory: can('settings.inventory:view') ? inv.data : undefined,
    umbrella: { ingest: ingest.data, api: api.data },
    bmp: bmp.data,
    devices: can('devices:view') ? devs.data?.results : undefined,
  })
  if (list.length === 0 || stepsDone(list)) return null
  const required = list.filter((s) => !s.optional)
  const done = required.filter((s) => s.done).length
  const hide = () => {
    try {
      localStorage.setItem(HIDDEN, '1')
    } catch {
      // Hidden until reload.
    }
    setHidden(true)
  }
  return (
    <section className="card ob-card" aria-labelledby="ob-title">
      <header className="ob-head">
        <div>
          <h2 id="ob-title">{t('ob.title')}</h2>
          <p className="muted">{t('ob.lead')}</p>
        </div>
        <div className="row ob-head-actions">
          <span className="pill chip-soft tone-warn ob-count">{t('ob.progress', { done, total: required.length })}</span>
          <button type="button" className="icon-btn" onClick={hide} aria-label={t('ob.hide')} title={t('ob.hide')}>
            <X size={16} />
          </button>
        </div>
      </header>
      <div className="ob-bar" role="progressbar" aria-valuemin={0} aria-valuemax={required.length} aria-valuenow={done} aria-label={t('ob.title')}>
        <span style={{ width: `${(done / Math.max(required.length, 1)) * 100}%` }} />
      </div>
      <ol className="ob-steps">
        {list.map((s) => (
          <StepRow key={s.id} step={s} />
        ))}
      </ol>
    </section>
  )
}

function StepRow({ step: s }: { step: Step }) {
  const t = useT(strings)
  return (
    <li className={`ob-step ${s.done ? 'ob-step-done' : ''}`}>
      {s.done ? <CheckCircle2 size={20} className="ob-icon ob-icon-done" aria-hidden /> : <Circle size={20} className="ob-icon" aria-hidden />}
      <div className="ob-text">
        <div className="ob-name">
          {t(`ob.step.${s.id}`)}
          {s.optional && <span className="pill tone-off ob-opt">{t('ob.optional')}</span>}
        </div>
        {!s.done && <div className="muted">{t(`ob.step.${s.id}.text`)}</div>}
      </div>
      <div className="ob-action">
        {s.done ? (
          <span className="pill chip-soft tone-ok">{t('ob.done')}</span>
        ) : (
          <Link to={s.path} className="btn btn-secondary btn-sm">
            {t(`ob.step.${s.id}.go`)}
            <ChevronRight size={15} aria-hidden />
          </Link>
        )}
      </div>
    </li>
  )
}
