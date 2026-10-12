import type { Locale, Units } from '../api/types'

// Human formatting of traffic values: SI prefixes (1000), as network engineers read them.

const BPS: Record<Locale, string[]> = {
  en: ['bps', 'kbps', 'Mbps', 'Gbps', 'Tbps', 'Pbps'],
  ru: ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с', 'Пбит/с'],
}
const PPS: Record<Locale, string[]> = {
  en: ['pps', 'kpps', 'Mpps', 'Gpps', 'Tpps', 'Ppps'],
  ru: ['пак/с', 'Кпак/с', 'Мпак/с', 'Гпак/с', 'Тпак/с', 'Ппак/с'],
}
const BYTES: Record<Locale, string[]> = {
  en: ['B', 'kB', 'MB', 'GB', 'TB', 'PB'],
  ru: ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'],
}
const PLAIN: Record<Locale, string[]> = {
  en: ['', 'k', 'M', 'G', 'T', 'P'],
  ru: ['', 'тыс.', 'млн', 'млрд', 'трлн', 'квадр.'],
}

function tag(locale: Locale) {
  return locale === 'ru' ? 'ru-RU' : 'en-US'
}

// num formats a number with up to `digits` significant fraction digits, in the locale.
export function num(v: number, locale: Locale, maxFrac = 2) {
  return new Intl.NumberFormat(tag(locale), { maximumFractionDigits: maxFrac }).format(v)
}

function scaled(v: number, units: string[], locale: Locale, sep = ' ') {
  if (!Number.isFinite(v)) return '—'
  const neg = v < 0
  let a = Math.abs(v)
  let i = 0
  while (a >= 1000 && i < units.length - 1) {
    a /= 1000
    i++
  }
  const frac = a >= 100 ? 0 : a >= 10 ? 1 : 2
  const s = num(a, locale, i === 0 ? Math.min(frac, 1) : frac)
  const u = units[i]
  return `${neg ? '−' : ''}${s}${u ? sep + u : ''}`
}

export function formatBps(v: number, locale: Locale) {
  return scaled(v, BPS[locale], locale)
}

export function formatPps(v: number, locale: Locale) {
  return scaled(v, PPS[locale], locale)
}

export function formatBytes(v: number, locale: Locale) {
  return scaled(v, BYTES[locale], locale)
}

export function formatCount(v: number, locale: Locale) {
  return scaled(v, PLAIN[locale], locale)
}

export function formatPercent(v: number, locale: Locale) {
  if (!Number.isFinite(v)) return '—'
  return `${num(v, locale, v >= 10 ? 1 : 2)} %`
}

export function formatUnits(v: number, units: Units, locale: Locale) {
  switch (units) {
    case 'l3bps':
    case 'l2bps':
      return formatBps(v, locale)
    case 'pps':
      return formatPps(v, locale)
    default:
      return formatPercent(v, locale)
  }
}

// A short axis label: same as formatUnits but without needless digits.
export function axisLabel(v: number, units: Units, locale: Locale) {
  return formatUnits(Math.abs(v), units, locale)
}

export function relativeTime(iso: string, locale: Locale, now = Date.now()) {
  const d = new Date(iso).getTime()
  if (!Number.isFinite(d)) return '—'
  const s = Math.round((d - now) / 1000)
  const rtf = new Intl.RelativeTimeFormat(tag(locale), { numeric: 'auto' })
  const a = Math.abs(s)
  if (a < 60) return rtf.format(s, 'second')
  if (a < 3600) return rtf.format(Math.round(s / 60), 'minute')
  if (a < 86400) return rtf.format(Math.round(s / 3600), 'hour')
  return rtf.format(Math.round(s / 86400), 'day')
}
