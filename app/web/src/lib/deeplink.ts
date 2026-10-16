import { DEFAULT_STATE, type VisState } from '../pages/visualize/state'

// The link Beacon incidents open: /go/incident?ci=&ip=&ref=&from=&to= becomes a Visualize view
// of the traffic of the address over the incident's time; without an address, of the Ledger
// object ref (source_ref, e.g. inventory-db:dcim.device:100), else of the configuration item ci.

function quote(v: string) {
  return `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
}

const IP = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/

export function incidentState(params: URLSearchParams, now = Date.now()): VisState {
  const ip = (params.get('ip') ?? '').trim()
  const ci = (params.get('ci') ?? '').trim()
  const ref = (params.get('ref') ?? '').trim()
  // A CI may be an end of the traffic (a host: SrcAddr / DstAddr, SrcCI / DstCI) or the exporter that
  // carried it (a router whose link is overloaded: ExporterAddress / ExporterRef), so both match.
  const terms: string[] = []
  let dimensions = ['SrcAS', 'DstAS']
  if (ip && IP.test(ip)) {
    const op = ip.includes('/') ? '<<' : '='
    terms.push(`SrcAddr ${op} ${ip}`, `DstAddr ${op} ${ip}`, `ExporterAddress ${op} ${ip}`)
    dimensions = ['SrcAddr', 'DstAddr', 'Proto']
  }
  if (ref) {
    terms.push(`SrcCI = ${quote(ref)}`, `DstCI = ${quote(ref)}`, `ExporterRef = ${quote(ref)}`)
    if (!terms.some((x) => x.startsWith('SrcAddr'))) dimensions = ['SrcCI', 'DstCI', 'App']
  } else if (ci && !terms.length) {
    terms.push(`SrcCI = ${quote(ci)}`, `DstCI = ${quote(ci)}`, `ExporterName = ${quote(ci)}`)
    dimensions = ['SrcCI', 'DstCI', 'App']
  }
  const filter = terms.join(' OR ')
  const from = Date.parse(params.get('from') ?? '')
  const to = Date.parse(params.get('to') ?? '')
  let range: VisState['range'] = { preset: '1h' }
  if (Number.isFinite(from)) {
    // Some context around the incident: 15 minutes before it, until its end or now.
    const start = new Date(from - 15 * 60e3)
    const end = new Date(Number.isFinite(to) && to > from ? to + 15 * 60e3 : now)
    range = { start: start.toISOString().replace('.000Z', 'Z'), end: new Date(Math.min(end.getTime(), now)).toISOString().replace('.000Z', 'Z') }
  }
  return { ...DEFAULT_STATE, range, filter, dimensions, graph: 'stacked', bidirectional: false }
}
