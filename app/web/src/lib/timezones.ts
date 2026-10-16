// Time zones for selects, sorted by their current UTC offset (as in Beacon).
function offsetMinutes(zone: string, at: Date) {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: zone, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric' })
    .formatToParts(at)
    .reduce<Record<string, number>>((acc, p) => (p.type === 'literal' ? acc : { ...acc, [p.type]: Number(p.value) }), {})
  const asUTC = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute)
  return Math.round((asUTC - Math.floor(at.getTime() / 60000) * 60000) / 60000)
}

function offsetLabel(min: number) {
  const a = Math.abs(min)
  return `UTC${min < 0 ? '−' : '+'}${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`
}

export type Zone = { id: string; offset: number; label: string }
let cache: Zone[] | null = null

export function timezones(): Zone[] {
  if (cache) return cache
  const now = new Date()
  let ids: string[] = []
  try {
    ids = (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf('timeZone')
  } catch {
    ids = []
  }
  if (!ids.includes('UTC')) ids = ['UTC', ...ids]
  cache = ids
    .map((id) => {
      const offset = offsetMinutes(id, now)
      return { id, offset, label: `(${offsetLabel(offset)}) ${id.replaceAll('_', ' ')}` }
    })
    .sort((a, b) => a.offset - b.offset || a.id.localeCompare(b.id))
  return cache
}

export function browserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

export function zoneLabel(id: string) {
  return timezones().find((z) => z.id === id)?.label ?? id
}
