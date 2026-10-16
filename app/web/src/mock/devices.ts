import type { Candidate, Child, Client, Device, DeviceDetail, Facts, Found, Iface, Neighbor, Platform, PlatformsView, Topology, TopoEdge, TopoNode } from '../pages/devices/model'

// Mock handlers of Network → Devices, Clients and Map (VITE_MOCK=1), shaped like
// internal/app/devices.go. Credentials are write-only: only `credentials.set` comes back.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown): Reply => ({ status: 200, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })
const ago = (sec: number) => new Date(Date.now() - sec * 1e3).toISOString()

const SNMP_CREDS = ['snmp_version', 'snmp_community', 'snmp_user', 'snmp_auth_protocol', 'snmp_auth_password', 'snmp_priv_protocol', 'snmp_priv_password']
const all = ['hostname', 'interface', 'dns', 'ntp', 'flow_export', 'reboot', 'endpoint_block', 'command', 'backup']
const plat = (key: string, vendor: string, title: string, kind: string, transports: [string, number][], creds: string[], caps: string[], hint = '', segment: Platform['segment'] = 'smb'): Platform => ({
  key,
  vendor,
  title,
  segment,
  kind,
  transports: transports.map(([name, port]) => ({ name, port })),
  credentials: creds,
  hint,
  capabilities: Object.fromEntries(transports.map(([n]) => [n, n === 'snmp' ? ['hostname', 'interface'] : caps])),
})

const platforms: Platform[] = [
  plat('mikrotik', 'MikroTik', 'MikroTik RouterOS 7', 'router', [['api', 443], ['http', 80], ['ssh', 22], ['snmp', 161]], ['username', 'password', 'private_key', ...SNMP_CREDS], ['hostname', 'interface', 'dns', 'ntp', 'flow_export', 'reboot', 'command', 'backup'], 'REST API (www-ssl) or SSH with RouterOS 7.13+', 'any'),
  plat('cisco_ios', 'Cisco', 'Cisco IOS / IOS-XE', 'switch', [['ssh', 22], ['snmp', 161]], ['username', 'password', 'private_key', 'enable_password', ...SNMP_CREDS], ['hostname', 'interface', 'dns', 'ntp', 'flow_export', 'reboot', 'command', 'backup'], 'SSH; flow export as Flexible NetFlow', 'enterprise'),
  plat('juniper', 'Juniper', 'Juniper Junos', 'router', [['ssh', 22], ['snmp', 161]], ['username', 'password', 'private_key', ...SNMP_CREDS], ['hostname', 'interface', 'dns', 'ntp', 'flow_export', 'reboot', 'command', 'backup'], '', 'enterprise'),
  plat('unifi', 'Ubiquiti', 'UniFi Network controller', 'controller', [['https', 443]], ['username', 'password', 'api_key'], ['reboot', 'endpoint_block'], 'The Site field is the UniFi site name'),
  plat('omada', 'TP-Link', 'TP-Link Omada SDN Controller', 'controller', [['https', 8043], ['http', 8088]], ['api_key', 'api_secret'], ['reboot', 'endpoint_block'], 'Open API: Client ID and Client Secret'),
  plat('keenetic', 'Keenetic', 'Keenetic', 'router', [['http', 80], ['https', 443]], ['username', 'password'], ['hostname', 'interface', 'dns', 'ntp', 'reboot', 'endpoint_block', 'command', 'backup'], '', 'home'),
  plat('opnsense', 'Deciso', 'OPNsense', 'firewall', [['https', 443], ['http', 80], ['snmp', 161]], ['api_key', 'api_secret', ...SNMP_CREDS], ['hostname', 'dns', 'ntp', 'flow_export', 'reboot', 'backup']),
  plat('linux', 'Linux', 'Linux server', 'server', [['ssh', 22], ['snmp', 161]], ['username', 'password', 'private_key', ...SNMP_CREDS], ['hostname', 'interface', 'dns', 'ntp', 'flow_export', 'reboot', 'command', 'backup']),
  plat('tplink', 'TP-Link', 'TP-Link (Archer, Deco, Easy Smart, etc.)', 'router', [['snmp', 161]], SNMP_CREDS, ['hostname', 'interface'], 'Polled over SNMP', 'home'),
  plat('gnmi', 'OpenConfig', 'Any gNMI device (OpenConfig)', 'router', [['gnmi', 0]], [], [], 'Uses the gNMI profile of Flow that covers the address', 'enterprise'),
]

const platformsView: PlatformsView = {
  platforms,
  actions: all,
  action_titles: {},
  admin_actions: ['reboot', 'command', 'backup'],
  secret_fields: ['password', 'api_key', 'api_secret', 'private_key', 'enable_password', 'snmp_community', 'snmp_auth_password', 'snmp_priv_password'],
  roles: ['router', 'switch', 'firewall', 'ap', 'controller', 'server', 'other'],
  flow_protocols: ['netflow5', 'netflow9', 'ipfix', 'sflow'],
  snmp_auth_protocols: ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'],
  snmp_priv_protocols: ['des', 'aes', 'aes192', 'aes256', 'aes192c', 'aes256c'],
}

const facts = (hostname: string, vendor: string, model: string, os: string, version: string, mac: string, uptime: number, cpu: number, mem: number): Facts => ({
  hostname,
  vendor,
  model,
  os,
  version,
  serial: `SN${mac.replace(/:/g, '').slice(-8).toUpperCase()}`,
  mac,
  uptime_seconds: uptime,
  cpu_percent: cpu,
  memory_percent: mem,
})

const iface = (name: string, idx: number, speed: number, up: boolean, util: number | null, desc = '', addrs: string[] = []): Iface => {
  const bps = util == null ? null : (speed * 1e6 * util) / 100
  return {
    name,
    index: idx,
    description: desc,
    type: 'ether',
    mac: '',
    admin_up: true,
    oper_up: up,
    speed_mbps: speed,
    mtu: 1500,
    addresses: addrs,
    rx_bytes: null,
    tx_bytes: null,
    vlan: null,
    rx_bps: bps,
    tx_bps: bps == null ? null : bps * 0.4,
    utilization: util,
  }
}

type Row = { d: Device; interfaces: Iface[]; neighbors: Neighbor[]; children: Child[]; secrets: string[] }
const base = (id: number, name: string, platform: string, host: string, transport: string, site: string, role: string, f: Facts, extra: Partial<Device> = {}): Device => {
  const p = platforms.find((x) => x.key === platform)!
  return {
    id,
    name,
    platform,
    platform_title: p.title,
    vendor: p.vendor,
    kind: p.kind,
    host,
    port: null,
    transport,
    verify_tls: false,
    controller_site: '',
    inventory_id: 100 + id,
    source_ref: `inventory-db:dcim.device:${100 + id}`,
    bound: true,
    inventory_missing: false,
    site,
    role,
    tags: [],
    note: '',
    enabled: true,
    poll_seconds: 300,
    flow_exporter_ip: '',
    ssh_host_key: transport === 'ssh' ? 'SHA256:3q2+7w6c4mDHG3hQ0bq3tQ8p4mZ0mXkC2u1n7Ykq9aE' : '',
    status: 'up',
    failures: 0,
    last_poll_at: ago(40 + id * 17),
    last_ok_at: ago(40 + id * 17),
    last_error: '',
    down_since: null,
    alerted: false,
    facts: f,
    capabilities: p.capabilities[transport] ?? [],
    counts: { interfaces: 0, interfaces_up: 0, neighbors: 0, children: 0, endpoints: 0 },
    credentials: { username: 'flow', snmp_version: '', snmp_user: '', snmp_auth_protocol: '', snmp_priv_protocol: '', snmp_source: 'own', set: { password: true } },
    exporter_ips: [host],
    created_by: 'admin',
    created_at: ago(86400 * 20),
    updated_at: ago(86400 * 3),
    ...extra,
  }
}

const rows: Row[] = [
  {
    d: base(1, 'edge-msk-01', 'juniper', '10.0.0.1', 'ssh', 'MSK-DC1', 'router', facts('edge-msk-01', 'Juniper', 'MX204', 'Junos', '23.4R1', 'a8:d0:e5:10:00:01', 86400 * 41, 23, 41), { tags: ['border'] }),
    interfaces: [
      iface('et-0/0/0', 1, 100000, true, 64, 'Transit: Rostelecom 100G', ['198.51.100.2/30']),
      iface('et-0/0/1', 2, 100000, true, 47, 'Transit: RETN 100G', ['198.51.100.6/30']),
      iface('xe-0/1/0', 3, 10000, true, 88, 'IX: MSK-IX', ['195.208.208.10/23']),
      iface('ae0', 4, 200000, true, 31, 'Uplink core-msk-01', ['10.0.0.1/31']),
    ],
    neighbors: [{ local_interface: 'ae0', remote_name: 'core-msk-01', remote_ip: '10.0.0.2', remote_mac: '', remote_interface: 'Po1', remote_platform: 'Cisco Nexus 9300', protocol: 'lldp' }],
    children: [],
    secrets: ['password'],
  },
  {
    d: base(2, 'core-msk-01', 'cisco_ios', '10.0.0.2', 'ssh', 'MSK-DC1', 'switch', facts('core-msk-01', 'Cisco', 'C9500-48Y4C', 'IOS-XE', '17.9.4', '00:1b:54:20:00:02', 86400 * 120, 12, 35)),
    interfaces: [
      iface('Port-channel1', 1, 200000, true, 31, 'to edge-msk-01'),
      iface('TwentyFiveGigE1/0/1', 2, 25000, true, 22, 'to access-msk-01'),
      iface('TwentyFiveGigE1/0/2', 3, 25000, true, 9, 'to fw-msk-01'),
      iface('TwentyFiveGigE1/0/3', 4, 25000, false, null, 'spare'),
    ],
    neighbors: [
      { local_interface: 'Po1', remote_name: 'edge-msk-01', remote_ip: '10.0.0.1', remote_mac: '', remote_interface: 'ae0', remote_platform: 'Juniper MX204', protocol: 'lldp' },
      { local_interface: 'Twe1/0/1', remote_name: 'access-msk-01', remote_ip: '10.0.0.3', remote_mac: '', remote_interface: 'sfp-sfpplus1', remote_platform: 'MikroTik CRS326', protocol: 'cdp' },
      { local_interface: 'Twe1/0/2', remote_name: 'fw-msk-01', remote_ip: '10.0.0.4', remote_mac: '', remote_interface: 'igb0', remote_platform: 'OPNsense', protocol: 'lldp' },
      { local_interface: 'Twe1/0/4', remote_name: 'hv-msk-07', remote_ip: '10.0.5.7', remote_mac: '3c:ec:ef:00:07:01', remote_interface: 'eno1', remote_platform: 'Linux Proxmox VE', protocol: 'lldp' },
    ],
    children: [],
    secrets: ['password', 'enable_password'],
  },
  {
    d: base(3, 'access-msk-01', 'mikrotik', '10.0.0.3', 'api', 'MSK-DC1', 'switch', facts('access-msk-01', 'MikroTik', 'CRS326-24S+2Q+', 'RouterOS', '7.16.1', '48:a9:8a:30:00:03', 86400 * 9, 8, 22)),
    interfaces: [iface('sfp-sfpplus1', 1, 10000, true, 19, 'uplink core'), iface('ether1', 2, 1000, true, 4, 'office-1'), iface('ether2', 3, 1000, true, 71, 'unifi uplink')],
    neighbors: [{ local_interface: 'sfp-sfpplus1', remote_name: 'core-msk-01', remote_ip: '10.0.0.2', remote_mac: '', remote_interface: 'Twe1/0/1', remote_platform: 'Cisco IOS-XE', protocol: 'mndp' }],
    children: [],
    secrets: ['password'],
  },
  {
    d: base(4, 'fw-msk-01', 'opnsense', '10.0.0.4', 'https', 'MSK-DC1', 'firewall', facts('fw-msk-01', 'Deciso', 'DEC2750', 'OPNsense', '24.7.6', 'f4:90:ea:40:00:04', 86400 * 63, 31, 54)),
    interfaces: [iface('igb0', 1, 10000, true, 12, 'LAN'), iface('igb1', 2, 10000, true, 38, 'DMZ')],
    neighbors: [],
    children: [],
    secrets: ['api_key', 'api_secret'],
  },
  {
    d: base(5, 'unifi-office', 'unifi', '10.0.10.5', 'https', 'MSK-Office', 'controller', facts('unifi-office', 'Ubiquiti', 'UniFi Network 9.0', 'UniFi OS', '9.0.114', '', 86400 * 5, 4, 36), { controller_site: 'default' }),
    interfaces: [],
    neighbors: [],
    children: [
      { mac: '74:ac:b9:50:00:11', name: 'ap-office-2f', model: 'U7 Pro', kind: 'ap', ip: '10.0.10.21', online: true, version: '7.0.66', uplink_mac: '48:a9:8a:30:00:03', uplink_port: 'ether2', clients: 18 },
      { mac: '74:ac:b9:50:00:12', name: 'ap-office-3f', model: 'U6 Lite', kind: 'ap', ip: '10.0.10.22', online: true, version: '6.6.77', uplink_mac: '48:a9:8a:30:00:03', uplink_port: 'ether2', clients: 11 },
      { mac: '74:ac:b9:50:00:13', name: 'ap-meeting', model: 'U6 Mesh', kind: 'ap', ip: '10.0.10.23', online: false, version: '6.6.77', uplink_mac: '', uplink_port: '', clients: 0 },
    ],
    secrets: ['username', 'password'],
  },
  {
    d: base(6, 'edge-spb-01', 'mikrotik', '10.1.0.1', 'ssh', 'SPB-DC2', 'router', facts('edge-spb-01', 'MikroTik', 'CCR2216-1G-12XS-2XQ', 'RouterOS', '7.15.3', '48:a9:8a:60:00:06', 3600 * 3, 0, 0), {
      status: 'down',
      failures: 4,
      last_error: 'dial tcp 10.1.0.1:22: i/o timeout',
      down_since: ago(1500),
      alerted: true,
      last_ok_at: ago(2100),
    }),
    interfaces: [iface('sfp28-1', 1, 25000, true, null, 'Transit: MTS'), iface('sfp28-2', 2, 25000, true, null, 'to core-spb')],
    neighbors: [],
    children: [],
    secrets: ['password'],
  },
  {
    d: base(7, 'office-archer', 'tplink', '10.0.20.1', 'snmp', 'MSK-Office', 'router', facts('office-archer', 'TP-Link', 'Archer AX55', 'TP-Link', '1.1.4', 'c0:c9:e3:70:00:07', 86400 * 2, 0, 0), {
      status: 'error',
      failures: 1,
      last_error: 'request timeout (after 1 retries)',
      inventory_id: null,
      source_ref: '',
      bound: false,
      credentials: { username: '', snmp_version: '2c', snmp_user: '', snmp_auth_protocol: '', snmp_priv_protocol: '', snmp_source: 'profile', set: {} },
    }),
    interfaces: [iface('eth0', 1, 1000, true, 3, 'WAN')],
    neighbors: [],
    children: [],
    secrets: [],
  },
]

const hosts = ['alice-laptop', 'bob-iphone', 'printer-2f', 'conf-room-tv', 'cam-entrance', 'nas-office', 'kiosk-lobby', 'dev-desktop-14', 'galaxy-s24', 'ipad-reception', 'pos-terminal-1', 'thermostat', '', '', '']
const vendors = ['Apple', 'Apple', 'HP Inc.', 'Samsung', 'Hikvision', 'Synology', 'Lenovo', 'Dell', 'Samsung', 'Apple', 'Ingenico', 'Google', 'Random MAC', 'Intel', 'Espressif']
const clients: Client[] = Array.from({ length: 34 }, (_, i) => {
  const wifi = i % 3 !== 2
  const ap = rows[4].children[i % 2]
  const online = i % 7 !== 6
  const name = hosts[i % hosts.length]
  return {
    mac: `de:ad:be:ef:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`,
    ip: `10.0.10.${100 + i}`,
    hostname: name ? `${name}${i >= hosts.length ? `-${i}` : ''}` : '',
    alias: i === 2 ? 'Printer, 2nd floor' : '',
    note: i === 2 ? 'Room 214' : '',
    vendor: vendors[i % vendors.length],
    device_id: wifi ? 5 : 3,
    device_name: wifi ? 'unifi-office' : 'access-msk-01',
    interface: wifi ? '' : 'ether1',
    source: wifi ? 'wifi' : i % 2 ? 'bridge' : 'dhcp',
    attached_to: wifi ? ap.mac : '',
    port: wifi ? '' : 'ether1',
    ssid: wifi ? (i % 4 ? 'Office' : 'Guest') : '',
    signal: wifi ? -45 - (i % 30) : null,
    vlan: wifi ? (i % 4 ? 10 : 30) : 20,
    blocked: i === 11,
    first_seen: ago(86400 * (1 + (i % 9))),
    last_seen: online ? ago(60 + i * 7) : ago(3600 * (2 + i)),
    name: i === 2 ? 'Printer, 2nd floor' : name,
    online,
  }
})

const candidates: Candidate[] = [
  { id: 210, name: 'core-spb-01', ref: 'inventory-db:dcim.device:210', site: 'SPB-DC2', role: 'switch', status: 'active', manufacturer: 'Cisco', model: 'C9500-24Y4C', platform: 'IOS-XE', host: '10.1.0.2', platform_guess: 'cisco_ios' },
  { id: 211, name: 'access-spb-01', ref: 'inventory-db:dcim.device:211', site: 'SPB-DC2', role: 'switch', status: 'active', manufacturer: 'MikroTik', model: 'CRS354', platform: 'RouterOS', host: '10.1.0.3', platform_guess: 'mikrotik' },
  { id: 212, name: 'omada-warehouse', ref: 'inventory-db:dcim.device:212', site: 'Warehouse', role: 'controller', status: 'active', manufacturer: 'TP-Link', model: 'OC200', platform: 'Omada', host: '10.2.0.5', platform_guess: 'omada' },
  { id: 213, name: 'keenetic-branch-7', ref: 'inventory-db:dcim.device:213', site: 'Branch-7', role: 'router', status: 'active', manufacturer: 'Keenetic', model: 'Giga KN-1012', platform: '', host: '10.7.0.1', platform_guess: 'keenetic' },
]

const positions: Record<string, [number, number] | null> = {}

function view(r: Row): Device {
  const ups = r.interfaces.filter((i) => i.oper_up).length
  const endpoints = clients.filter((c) => c.device_id === r.d.id && c.online).length
  return { ...r.d, counts: { interfaces: r.interfaces.length, interfaces_up: ups, neighbors: r.neighbors.length, children: r.children.length, endpoints } }
}

function detail(r: Row): DeviceDetail {
  return {
    ...view(r),
    interfaces: r.interfaces,
    neighbors: r.neighbors,
    children: r.children,
    endpoints: clients.filter((c) => c.device_id === r.d.id),
    collector: { address: 'flow.example.net', ip: '192.0.2.10', netflow_port: 2055, sflow_port: 6343, source: 'public_url' },
    platform_info: platforms.find((p) => p.key === r.d.platform),
    snmp_profile: r.d.credentials.snmp_source === 'profile' ? { id: 'p-legacy', name: 'Legacy v2c' } : undefined,
  }
}

function topology(offline: boolean): Topology {
  const nodes: TopoNode[] = []
  const edges: TopoEdge[] = []
  const byName = new Map<string, string>()
  for (const r of rows) {
    const id = `dev:${r.d.id}`
    const pos = positions[id]
    nodes.push({ id, type: 'device', label: r.d.name, role: r.d.role, status: r.d.status, vendor: r.d.vendor, model: r.d.facts.model, ip: r.d.host, device_id: r.d.id, platform: r.d.platform, site: r.d.site, x: pos?.[0] ?? null, y: pos?.[1] ?? null, clients: 0, interfaces: r.interfaces.length, error: r.d.last_error })
    byName.set(r.d.name, id)
  }
  const seen = new Set<string>()
  for (const r of rows)
    for (const n of r.neighbors) {
      let target = byName.get(n.remote_name)
      if (!target) {
        target = `nb:${n.remote_mac || n.remote_ip}`
        if (!nodes.some((x) => x.id === target)) nodes.push({ id: target, type: 'neighbor', label: n.remote_name, role: 'other', status: 'unknown', ip: n.remote_ip, model: n.remote_platform, platform_guess: 'linux', clients: 0 })
      }
      const key = [`dev:${r.d.id}`, target].sort().join('|')
      if (seen.has(key)) continue
      seen.add(key)
      const i = r.interfaces.find((x) => x.name.toLowerCase().replace('twentyfivegige', 'twe') === n.local_interface.toLowerCase() || x.name === n.local_interface)
      edges.push({ source: `dev:${r.d.id}`, target, kind: 'link', source_port: n.local_interface, target_port: n.remote_interface, protocol: n.protocol, bps: i?.rx_bps ?? null, utilization: i?.utilization ?? null, speed_mbps: i?.speed_mbps ?? null })
    }
  for (const c of rows[4].children) {
    const id = `mac:${c.mac}`
    nodes.push({ id, type: 'child', label: c.name, role: c.kind, status: c.online ? 'up' : 'down', model: c.model, ip: c.ip, mac: c.mac, controller: 'dev:5', clients: 0 })
    edges.push(c.uplink_mac ? { source: 'dev:3', target: id, kind: 'link', target_port: c.uplink_port, utilization: 34 } : { source: 'dev:5', target: id, kind: 'managed' })
  }
  edges.push({ source: 'dev:3', target: 'dev:5', kind: 'wired', source_port: 'ether1' })
  for (const c of clients) {
    if (!c.online && !offline) continue
    const parent = c.attached_to ? `mac:${c.attached_to}` : `dev:${c.device_id}`
    nodes.push({ id: `ep:${c.mac}`, type: 'endpoint', label: c.name || c.ip, status: c.online ? 'online' : 'offline', ip: c.ip, mac: c.mac, vendor: c.vendor, ssid: c.ssid, signal: c.signal, blocked: c.blocked, parent, clients: 0 })
    edges.push({ source: parent, target: `ep:${c.mac}`, kind: c.ssid ? 'wifi' : 'wired', label: c.ssid })
    const p = nodes.find((n) => n.id === parent)
    if (p) p.clients++
  }
  nodes.push({ id: 'internet', type: 'internet', label: 'Internet', status: 'up', clients: 0 })
  for (const r of rows) if (r.d.role === 'router' && r.d.site.endsWith('DC1')) edges.unshift({ source: 'internet', target: `dev:${r.d.id}`, kind: 'wan' })
  edges.unshift({ source: 'internet', target: 'dev:6', kind: 'wan' })
  edges.push({ source: 'dev:1', target: 'dev:6', kind: 'link', source_port: 'et-0/0/1', target_port: 'sfp28-2', protocol: 'lldp', utilization: 12 })
  edges.push({ source: 'dev:4', target: 'dev:7', kind: 'link', source_port: 'igb1', target_port: 'eth0', protocol: 'lldp', utilization: 3 })
  const count = (t: string) => nodes.filter((n) => n.type === t).length
  return {
    nodes,
    edges,
    stats: { devices: count('device'), children: count('child'), neighbors: count('neighbor'), endpoints: count('endpoint'), online: nodes.filter((n) => n.status === 'online').length, down: nodes.filter((n) => n.type === 'device' && (n.status === 'down' || n.status === 'error')).length },
    generated_at: new Date().toISOString(),
  }
}

let nextId = 8

export function deviceExporterLink(address: string) {
  const r = rows.find((x) => x.d.exporter_ips.includes(address))
  return r ? { id: r.d.id, name: r.d.name, status: r.d.status, platform: r.d.platform } : undefined
}

export function devicesMock(method: string, p: string, body: unknown, q: URLSearchParams): Reply | null {
  if (!p.startsWith('/api/devices') && !p.startsWith('/api/endpoints') && !p.startsWith('/api/topology') && p !== '/api/settings/devices') return null
  const b = (body ?? {}) as Record<string, unknown>
  if (p === '/api/devices/platforms') return ok(platformsView)
  if (p === '/api/devices' && method === 'GET') return ok({ results: rows.map(view).sort((a, b) => a.name.localeCompare(b.name)) })
  if (p === '/api/devices/inventory-candidates') return ok({ connected: true, loaded: true, devices: candidates.filter((c) => !rows.some((r) => r.d.inventory_id === c.id)) })
  if (p === '/api/devices/test') {
    const host = String(b.host ?? '')
    if (host.startsWith('10.9.')) return fail(422, 'device_error', 'dial tcp ' + host + ':22: connect: connection refused')
    return ok({ ok: true, facts: facts('test-device', 'MikroTik', 'hEX S', 'RouterOS', '7.16', '', 3600, 3, 20), interfaces: 6, neighbors: 1, endpoints: 14, children: 0, host_key: 'SHA256:9mY0c1vF3Q2b7t+Zp8yQ4wq6s1e0n5Xk2r3a4b5c6d7' })
  }
  if (p === '/api/devices/discover') {
    const target = String(b.target ?? '')
    const found: Found[] = [
      { host: '10.0.0.3', reachable: true, ports: [22, 443], evidence: ['ssh: ROSSSH', 'web:443 mikrotik'], snmp: null, platforms: ['mikrotik'], name: 'access-msk-01', known: true, device_id: 3 },
      { host: '10.0.0.9', reachable: true, ports: [22, 161], evidence: ['snmp: Cisco IOS Software, C2960X'], snmp: { sysName: 'sw-lab-09' }, platforms: ['cisco_ios'], name: 'sw-lab-09', known: false },
      { host: '10.0.0.12', reachable: true, ports: [443, 8443], evidence: ['web:8443 unifi'], snmp: null, platforms: ['unifi'], name: '', known: false },
    ]
    return ok({ results: target.includes('/') ? found : found.slice(1, 2).map((f) => ({ ...f, host: target })) })
  }
  if (p === '/api/devices' && method === 'POST') {
    const inv = candidates.find((c) => c.id === b.inventory_id)
    if (!inv) return fail(400, 'invalid_device', 'Inventory DB is connected: pick the device in Inventory DB')
    if (rows.some((r) => r.d.inventory_id === inv.id || r.d.host === b.host)) return fail(409, 'duplicate_device', 'This device is already managed')
    const pl = platforms.find((x) => x.key === b.platform) ?? platforms[0]
    const transport = String(b.transport || pl.transports[0].name)
    const creds = (b.credentials ?? {}) as Record<string, string>
    const d = base(nextId, inv.name, pl.key, String(b.host), transport, inv.site, inv.role, facts(inv.name, pl.vendor, inv.model, '', '', '', 60, 5, 20), {
      inventory_id: inv.id,
      source_ref: inv.ref,
      status: 'unknown',
      last_poll_at: null,
      last_ok_at: null,
      credentials: { username: creds.username ?? '', snmp_version: '', snmp_user: '', snmp_auth_protocol: '', snmp_priv_protocol: '', snmp_source: 'own', set: Object.fromEntries(platformsView.secret_fields.map((f) => [f, !!creds[f]])) },
    })
    nextId++
    const r: Row = { d, interfaces: [], neighbors: [], children: [], secrets: [] }
    rows.push(r)
    setTimeout(() => Object.assign(r.d, { status: 'up', last_poll_at: new Date().toISOString(), last_ok_at: new Date().toISOString() }), 1500)
    return { status: 201, body: view(r) }
  }
  if (p === '/api/settings/devices') {
    const settings = { collector_address: '', netflow_port: 0, sflow_port: 0, endpoint_offline_minutes: 15, endpoint_retention_days: 90, concurrency: 6, ...(method === 'PUT' ? b : {}) }
    return ok({ settings, collector: { address: 'flow.example.net', ip: '192.0.2.10', netflow_port: 2055, sflow_port: 6343, source: 'public_url' } })
  }
  if (p === '/api/endpoints' && method === 'GET') {
    const s = (q.get('q') ?? '').toLowerCase()
    return ok({ results: clients.filter((c) => !s || [c.mac, c.ip, c.hostname, c.alias, c.vendor].some((v) => v.toLowerCase().includes(s))) })
  }
  if (p === '/api/topology' && method === 'GET') return ok(topology(q.get('offline') === 'true'))
  if (p === '/api/topology/positions' && method === 'PUT') {
    Object.assign(positions, b)
    return { status: 204 }
  }
  let m = p.match(/^\/api\/endpoints\/([^/]+)(\/block)?$/)
  if (m) {
    const c = clients.find((x) => x.mac === decodeURIComponent(m![1]).toLowerCase().replace(/-/g, ':'))
    if (!c) return fail(404, 'not_found', 'network client not found')
    if (m[2]) {
      if (c.device_id !== 5) return fail(400, 'unsupported_action', 'No device that saw this client can block it')
      c.blocked = b.blocked !== false
      return ok({ ok: true, output: '', device_id: 5, device_name: 'unifi-office' })
    }
    if (method === 'PATCH') {
      if (typeof b.alias === 'string') c.alias = b.alias.trim()
      if (typeof b.note === 'string') c.note = b.note
      c.name = c.alias || c.hostname
      return ok(c)
    }
    if (method === 'DELETE') {
      clients.splice(clients.indexOf(c), 1)
      return { status: 204 }
    }
    return ok({ ...c, sightings: [] })
  }
  m = p.match(/^\/api\/devices\/(\d+)(\/[a-z-]+)?$/)
  if (!m) return fail(404, 'not_found', p)
  const r = rows.find((x) => x.d.id === Number(m![1]))
  if (!r) return fail(404, 'not_found', 'device not found')
  switch (m[2] ?? '') {
    case '':
      if (method === 'GET') return ok(detail(r))
      if (method === 'DELETE') {
        rows.splice(rows.indexOf(r), 1)
        return { status: 204 }
      }
      if (method === 'PATCH') {
        if (r.d.bound && ((b.name !== undefined && b.name !== r.d.name) || (b.site !== undefined && b.site !== r.d.site))) return fail(400, 'invalid_device', 'The name, site and role of a bound device come from Inventory DB')
        for (const k of ['host', 'transport', 'note', 'enabled', 'poll_seconds', 'flow_exporter_ip', 'verify_tls', 'controller_site', 'tags'] as const) if (b[k] !== undefined) (r.d as Record<string, unknown>)[k] = b[k]
        if (!r.d.bound) for (const k of ['name', 'site', 'role'] as const) if (typeof b[k] === 'string' && b[k]) (r.d as Record<string, unknown>)[k] = b[k]
        return ok(view(r))
      }
      break
    case '/poll':
      r.d.last_poll_at = new Date().toISOString()
      return ok(r.d.status === 'down' ? { ok: false, status: 'down', failures: ++r.d.failures, error: r.d.last_error } : { ok: true, status: 'up', failures: 0, error: '' })
    case '/actions': {
      const a = String(b.action)
      if (!r.d.capabilities.includes(a)) return fail(400, 'unsupported_action', `${r.d.platform_title}: not supported over ${r.d.transport}`)
      const params = (b.params ?? {}) as Record<string, unknown>
      if (a === 'hostname' && !/^[A-Za-z0-9._-]{1,63}$/.test(String(params.name ?? ''))) return fail(400, 'invalid_params', "Name: Latin letters, digits, '.', '_', '-', up to 63 characters")
      if (r.d.status === 'down') return fail(422, 'device_error', r.d.last_error)
      const out = a === 'command' ? `[flow@${r.d.name}] > ${String(params.command)}\n  uptime: 9d4h12m\n  cpu-load: 8%\n  free-memory: 812.4MiB` : a === 'flow_export' ? `/ip traffic-flow set enabled=yes\n/ip traffic-flow target add dst-address=192.0.2.10 port=2055 version=ipfix` : 'ok'
      return ok({ ok: true, output: out })
    }
    case '/reset-host-key':
      r.d.ssh_host_key = ''
      return ok(view(r))
  }
  return fail(404, 'not_found', p)
}
