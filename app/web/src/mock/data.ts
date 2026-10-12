import type { Exporter } from '../api/types'

// Synthetic but plausible data for the mock mode: a Russian ISP-like network with two border
// routers, transit and peering links and the usual content providers.

export function hash(s: string) {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

export function rng(seed: number) {
  let a = seed || 1
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Values of each dimension with a relative weight; the first ones carry most of the traffic.
export const values: Record<string, [string, number][]> = {
  AS: [
    ['AS15169 Google', 30],
    ['AS13238 Yandex', 22],
    ['AS2906 Netflix', 14],
    ['AS32934 Meta', 9],
    ['AS13335 Cloudflare', 8],
    ['AS47541 VK', 7],
    ['AS16509 Amazon', 5],
    ['AS20940 Akamai', 4],
    ['AS8075 Microsoft', 3],
    ['AS12389 Rostelecom', 3],
    ['AS8359 MTS', 2],
    ['AS31133 MegaFon', 2],
    ['AS49505 Selectel', 1.5],
    ['AS9123 TimeWeb', 1],
    ['AS65010 Internal', 1],
  ],
  Exporter: [
    ['edge-msk-01', 40],
    ['edge-msk-02', 30],
    ['edge-spb-01', 18],
    ['core-msk-01', 8],
    ['dc-ekb-01', 4],
  ],
  Country: [
    ['RU', 48],
    ['US', 17],
    ['NL', 11],
    ['DE', 9],
    ['FI', 5],
    ['SE', 3],
    ['GB', 3],
    ['FR', 2],
    ['SG', 1],
    ['JP', 1],
  ],
  App: [
    ['https', 52],
    ['quic', 24],
    ['http', 6],
    ['dns', 4],
    ['ssh', 3],
    ['bittorrent', 3],
    ['rtp', 2],
    ['smtp', 1.5],
    ['ntp', 1],
    ['bgp', 0.5],
  ],
  Port: [
    ['443', 68],
    ['80', 8],
    ['53', 5],
    ['22', 3],
    ['3478', 3],
    ['8080', 2],
    ['25', 1.5],
    ['123', 1],
    ['179', 0.5],
    ['5060', 0.5],
  ],
  Boundary: [
    ['external', 70],
    ['internal', 30],
  ],
  Provider: [
    ['Rostelecom', 34],
    ['RETN', 24],
    ['MSK-IX', 22],
    ['TransTeleCom', 12],
    ['DATAIX', 8],
  ],
  Connectivity: [
    ['transit', 58],
    ['ix', 30],
    ['pni', 12],
  ],
  Proto: [
    ['TCP', 71],
    ['UDP', 27],
    ['ICMP', 1.2],
    ['GRE', 0.8],
  ],
  Site: [
    ['MSK-DC1', 55],
    ['SPB-DC2', 30],
    ['EKB-DC3', 15],
  ],
  Role: [
    ['border', 75],
    ['core', 18],
    ['dc', 7],
  ],
  IfName: [
    ['Ethernet1/1', 30],
    ['Ethernet1/2', 24],
    ['Port-Channel10', 18],
    ['HundredGigE0/0/0/1', 14],
    ['TenGigE0/1/0/3', 8],
    ['xe-0/0/1', 6],
  ],
  CI: [
    ['web-frontend', 30],
    ['video-cdn', 25],
    ['mail-gw', 10],
    ['crm-app', 9],
    ['vpn-gw', 8],
    ['dns-resolver', 7],
    ['backup', 6],
    ['erp', 5],
  ],
  NetName: [
    ['customers-b2c', 45],
    ['customers-b2b', 25],
    ['dc-services', 18],
    ['cdn-cache', 8],
    ['mgmt', 4],
  ],
  FlowType: [
    ['IPFIX', 55],
    ['NetFlowV9', 30],
    ['SFlow', 15],
  ],
}

function addrValues(prefix: string, n: number): [string, number][] {
  const r = rng(hash(prefix))
  return Array.from({ length: n }, (_, i) => [`${prefix}.${Math.floor(r() * 250) + 2}.${Math.floor(r() * 250) + 2}`, 40 / (i + 1)])
}

// valuesFor maps a column to the list of its values.
export function valuesFor(column: string): [string, number][] {
  const c = column.replace(/^(Src|Dst|In|Out)/, '').replace(/^If/, 'If')
  if (/AS$/.test(column)) return values.AS
  if (/^Exporter(Name|Ref)$/.test(column)) return values.Exporter
  if (column === 'ExporterAddress') return mockExporters.map((e, i) => [e.address, 40 / (i + 1)])
  if (/Country$/.test(column)) return values.Country
  if (column === 'App') return values.App
  if (/Port$/.test(column)) return values.Port
  if (/IfBoundary$/.test(column)) return values.Boundary
  if (/IfProvider$/.test(column)) return values.Provider
  if (/IfConnectivity$/.test(column)) return values.Connectivity
  if (/IfName$/.test(column)) return values.IfName
  if (/IfSpeed$/.test(column)) return [['100000000000', 50], ['10000000000', 40], ['1000000000', 10]]
  if (column === 'Proto') return values.Proto
  if (/Site$/.test(column)) return values.Site
  if (/Role$/.test(column)) return values.Role
  if (/CI$/.test(column)) return values.CI
  if (/NetName$/.test(column)) return values.NetName
  if (column === 'FlowType') return values.FlowType
  if (column === 'SrcAddr') return addrValues('203.0', 16)
  if (column === 'DstAddr') return addrValues('10.20', 16)
  if (/NetPrefix$/.test(column)) return [['10.20.0.0/16', 40], ['10.30.0.0/16', 25], ['185.12.64.0/22', 18], ['2a00:1450::/32', 10], ['198.51.100.0/24', 7]]
  if (/Region$/.test(column)) return [['Central', 60], ['North-West', 28], ['Ural', 12]]
  if (/Tenant$/.test(column)) return [['retail', 50], ['enterprise', 35], ['internal', 15]]
  if (/Group$/.test(column)) return [['border', 70], ['aggregation', 30]]
  if (/Vlan$/.test(column)) return [['100', 40], ['200', 30], ['300', 20], ['0', 10]]
  if (/Description$/.test(column)) return [['Transit: Rostelecom 100G', 34], ['IX: MSK-IX', 22], ['Transit: RETN 100G', 24], ['Uplink core-msk-01', 12], ['Customers B2B', 8]]
  if (/Host$/.test(column)) return [['www.google.com', 30], ['ya.ru', 22], ['nflxvideo.net', 14], ['vk.com', 9], ['cdn.cloudflare.net', 8]]
  if (/City$/.test(column)) return [['Moscow', 40], ['Saint Petersburg', 20], ['Frankfurt', 15], ['Amsterdam', 15], ['Helsinki', 10]]
  if (column === 'NextHop') return [['198.51.100.1', 50], ['198.51.100.5', 30], ['192.0.2.9', 20]]
  if (column === 'EType') return [['IPv4', 78], ['IPv6', 22]]
  if (column === 'ForwardingStatus') return [['64', 97], ['128', 3]]
  if (column === 'IPTos') return [['0', 80], ['46', 12], ['26', 8]]
  if (c.startsWith('ICMP')) return [['0', 50], ['8', 40], ['3', 10]]
  return [['value-a', 50], ['value-b', 30], ['value-c', 20]]
}

const now = Date.now()
const ago = (s: number) => new Date(now - s * 1000).toISOString()

function ifs(seed: string, list: [string, string, number, string, string][]): Exporter['interfaces'] {
  const r = rng(hash(seed))
  return list.map(([name, description, speed, boundary, provider], i) => {
    const load = boundary === 'external' ? 0.25 + r() * 0.55 : 0.05 + r() * 0.4
    return {
      index: 500 + i * 3,
      name,
      description,
      speed,
      boundary,
      provider,
      in_bps: Math.round(speed * load),
      out_bps: Math.round(speed * load * (boundary === 'external' ? 0.18 + r() * 0.2 : 0.6 + r() * 0.6)),
    }
  })
}

const G = 1e9

export const mockExporters: Exporter[] = [
  {
    address: '10.0.0.1',
    name: 'edge-msk-01',
    ref: 'inventory-db:dcim.device:101',
    site: 'MSK-DC1',
    role: 'border',
    last_seen: ago(3),
    flows_per_second: 18420,
    sampling_rates: [1000],
    interfaces: ifs('edge-msk-01', [
      ['HundredGigE0/0/0/1', 'Transit: Rostelecom 100G', 100 * G, 'external', 'Rostelecom'],
      ['HundredGigE0/0/0/2', 'Transit: RETN 100G', 100 * G, 'external', 'RETN'],
      ['TenGigE0/1/0/3', 'IX: MSK-IX', 10 * G, 'external', 'MSK-IX'],
      ['Bundle-Ether10', 'Uplink core-msk-01', 200 * G, 'internal', ''],
    ]),
  },
  {
    address: '10.0.0.2',
    name: 'edge-msk-02',
    ref: 'inventory-db:dcim.device:102',
    site: 'MSK-DC1',
    role: 'border',
    last_seen: ago(5),
    flows_per_second: 14210,
    sampling_rates: [1000],
    interfaces: ifs('edge-msk-02', [
      ['Ethernet1/1', 'Transit: TransTeleCom 100G', 100 * G, 'external', 'TransTeleCom'],
      ['Ethernet1/2', 'IX: DATAIX', 40 * G, 'external', 'DATAIX'],
      ['Port-Channel10', 'Uplink core-msk-01', 200 * G, 'internal', ''],
    ]),
  },
  {
    address: '10.1.0.1',
    name: 'edge-spb-01',
    ref: 'inventory-db:dcim.device:201',
    site: 'SPB-DC2',
    role: 'border',
    last_seen: ago(2),
    flows_per_second: 8930,
    sampling_rates: [2000, 1000],
    interfaces: ifs('edge-spb-01', [
      ['xe-0/0/1', 'Transit: Rostelecom 10G', 10 * G, 'external', 'Rostelecom'],
      ['xe-0/0/2', 'IX: SPB-IX', 10 * G, 'external', 'SPB-IX'],
      ['ae0', 'Customers B2B', 40 * G, 'internal', ''],
    ]),
  },
  {
    address: '10.0.1.1',
    name: 'core-msk-01',
    ref: 'inventory-db:dcim.device:110',
    site: 'MSK-DC1',
    role: 'core',
    last_seen: ago(4),
    flows_per_second: 5120,
    sampling_rates: [4000],
    interfaces: ifs('core-msk-01', [
      ['HundredGigE1/0/1', 'To edge-msk-01', 100 * G, 'internal', ''],
      ['HundredGigE1/0/2', 'To edge-msk-02', 100 * G, 'internal', ''],
      ['HundredGigE1/0/3', 'DC fabric', 100 * G, 'internal', ''],
    ]),
  },
  {
    address: '10.2.0.1',
    name: 'dc-ekb-01',
    ref: '',
    site: 'EKB-DC3',
    role: 'dc',
    last_seen: ago(410),
    flows_per_second: 640,
    sampling_rates: [512],
    interfaces: ifs('dc-ekb-01', [
      ['TenGigE0/0/0/0', 'Transit: MTS 10G', 10 * G, 'external', 'MTS'],
      ['TenGigE0/0/0/1', 'Servers', 10 * G, 'internal', ''],
    ]),
  },
]

// diurnal is the shape of a day of eyeball traffic: low at 5:00, peak at 21:00 (Moscow time).
export function diurnal(t: number) {
  const h = (new Date(t).getUTCHours() + 3 + new Date(t).getUTCMinutes() / 60) % 24
  const x = ((h - 21 + 24) % 24) / 24
  return 0.32 + 0.68 * (0.5 + 0.5 * Math.cos(2 * Math.PI * x)) ** 1.6
}
