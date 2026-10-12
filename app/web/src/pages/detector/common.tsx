import type { ReactNode } from 'react'
import { Button, Chip, Modal, type Tone } from '../../ui/ui'
import { useT } from '../../i18n'
import { formatBps, formatPps, num } from '../../lib/format'
import type { Locale } from '../../api/types'
import { DEFAULT_STATE, visualizeLink } from '../visualize/state'
import type { AlertState, Kind, Rule } from './model'
import { detStrings } from './strings'
import './detector.css'

export const severityTone: Record<string, Tone> = { critical: 'error', error: 'orange', warning: 'warn', low: 'info', info: 'low' }
export const stateTone: Record<string, Tone> = { pending: 'warn', firing: 'error', resolving: 'info' }

export function SeverityChip({ severity }: { severity: string }) {
  const t = useT(detStrings)
  return <Chip tone={severityTone[severity] ?? 'off'}>{t(`sev.${severity || 'warning'}`)}</Chip>
}

export function StateChip({ state }: { state: string }) {
  const t = useT(detStrings)
  return <Chip tone={stateTone[state] ?? 'off'}>{t(`state.${state}`)}</Chip>
}

export function Confirm({ open, title, text, action, danger, busy, onConfirm, onClose }: { open: boolean; title: string; text: ReactNode; action: string; danger?: boolean; busy?: boolean; onConfirm: () => void; onClose: () => void }) {
  const t = useT(detStrings)
  return (
    <Modal
      open={open}
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{t('cancel')}</Button>
          <Button variant={danger ? 'danger' : 'primary'} busy={busy} onClick={onConfirm}>
            {action}
          </Button>
        </>
      }
    >
      <p className="muted">{text}</p>
    </Modal>
  )
}

export const rateFormat = (locale: Locale) => ({
  bps: (n: number) => formatBps(n, locale),
  pps: (n: number) => formatPps(n, locale),
  pct: (n: number) => `${num(n, locale, 1)} %`,
})

// alertValue formats the last value of an alert in the unit of its rule.
export function alertValue(kind: Kind | undefined, v: number, locale: Locale): string {
  const f = rateFormat(locale)
  switch (kind) {
    case 'link_utilization':
    case 'link_commit':
      return f.pct(v)
    case 'ddos_syn':
      return f.pps(v)
    case 'exporter_silent':
      return v >= 3600 ? `${num(v / 3600, locale, 1)} h` : `${num(Math.round(v / 60), locale, 0)} min`
    default:
      return f.bps(v)
  }
}

function quote(v: string) {
  return `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
}

// alertLink opens Visualize on the traffic of an alert: the event's own link when the detector
// built one (public URL set), else the rule's filter narrowed to the alert's address or group,
// from 15 minutes before the alert started until now.
export function alertLink(a: AlertState, rule: Rule | undefined, now = Date.now()): string {
  const flow = a.event?.links?.flow
  if (flow) {
    try {
      const u = new URL(flow)
      if (u.pathname === '/visualize' || u.pathname === '/go/incident') return u.pathname + u.search
    } catch {
      // not a URL: build one
    }
  }
  const parts: string[] = []
  if (rule?.filter) parts.push(`(${rule.filter})`)
  const labels = a.event?.labels ?? {}
  const ip = a.event?.ip || labels.dst_ip
  let dims = rule?.dimensions?.length ? rule.dimensions : ['SrcAS', 'DstAS']
  if (ip) {
    parts.push(`DstAddr = ${ip}`)
    dims = ['SrcAS', 'SrcAddr', 'Proto']
  } else if (labels.exporter_address || labels.exporter) {
    parts.push(labels.exporter_address ? `ExporterAddress = ${labels.exporter_address}` : `ExporterName = ${quote(labels.exporter)}`)
    if (labels.interface) parts.push(`(InIfName = ${quote(labels.interface)} OR OutIfName = ${quote(labels.interface)})`)
    dims = labels.interface ? ['SrcAS', 'DstAS'] : ['InIfName']
  } else if (rule?.dimensions?.length) {
    for (const d of rule.dimensions) if (labels[d] !== undefined) parts.push(`${d} = ${quote(labels[d])}`)
  }
  const since = Date.parse(a.since)
  const start = new Date((Number.isFinite(since) ? since : now - 3600e3) - 15 * 60e3)
  const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')
  return visualizeLink({ ...DEFAULT_STATE, range: { start: iso(start), end: iso(new Date(now)) }, filter: parts.join(' AND '), dimensions: dims, bidirectional: false })
}
