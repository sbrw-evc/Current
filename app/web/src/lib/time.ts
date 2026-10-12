// Time ranges of the console: a preset relative to now, or fixed start/end.

export const PRESETS = ['15m', '1h', '6h', '24h', '7d', '30d'] as const
export type Preset = (typeof PRESETS)[number]
export type Range = { preset: Preset } | { start: string; end: string }

const MS: Record<Preset, number> = {
  '15m': 15 * 60e3,
  '1h': 3600e3,
  '6h': 6 * 3600e3,
  '24h': 24 * 3600e3,
  '7d': 7 * 86400e3,
  '30d': 30 * 86400e3,
}

export function isPreset(v: unknown): v is Preset {
  return typeof v === 'string' && (PRESETS as readonly string[]).includes(v)
}

// resolve gives the start and end of a range as RFC 3339 UTC strings, rounded to the minute.
export function resolve(r: Range, now = Date.now()): { start: string; end: string } {
  if ('preset' in r) {
    const end = Math.floor(now / 60e3) * 60e3
    return { start: new Date(end - MS[r.preset]).toISOString().replace('.000Z', 'Z'), end: new Date(end).toISOString().replace('.000Z', 'Z') }
  }
  return { start: r.start, end: r.end }
}

// toLocalInput / fromLocalInput convert between ISO strings and <input type=datetime-local>.
export function toLocalInput(iso: string) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

export function fromLocalInput(v: string) {
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().replace('.000Z', 'Z')
}
