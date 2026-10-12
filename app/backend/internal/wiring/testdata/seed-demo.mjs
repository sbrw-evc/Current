// Seeds a fresh local Inventory DB with the network simulated by `flow demo`
// (internal/demoexporter.DefaultConfig with a loopback target): the exporters
// edge-01 (127.0.0.11, NetFlow v9), edge-02 (127.0.0.12, IPFIX) and dc-sw-01
// (127.0.0.13, sFlow), their interfaces with the snmp_index custom field set
// to the demo ifIndexes, transit / IX / PNI circuits cabled to the external
// interfaces, and the local prefixes. Prints {"token": "<xc-token>"}.
//
//   node seed-demo.mjs http://localhost:8091
const base = process.argv[2] || 'http://localhost:8091';
let auth = {};
async function call(method, path, body) {
  const r = await fetch(base + '/api/v1' + path, {
    method,
    headers: { 'content-type': 'application/json', ...auth },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${text}`);
  return text ? JSON.parse(text) : null;
}
const su = await call('POST', '/auth/signup', { email: 'flow-demo@test.local', password: 'Passw0rd!Passw0rd', name: 'Flow demo' });
auth = { authorization: `Bearer ${su.token}` };
await call('GET', '/netbox/me');
const tok = await call('POST', '/tokens', { description: 'flow demo' });

await call('POST', '/extras/custom-fields', { object_types: ['dcim.interface'], type: 'integer', name: 'snmp_index', label: 'SNMP ifIndex' });
const region = await call('POST', '/dcim/regions', { name: 'Moscow' });
const tenant = await call('POST', '/tenancy/tenants', { name: 'NetOps' });
const site = await call('POST', '/dcim/sites', { name: 'MSK-DC1', region: region.id, tenant: tenant.id });
const mf = await call('POST', '/dcim/manufacturers', { name: 'Generic' });
const dt = await call('POST', '/dcim/device-types', { manufacturer: mf.id, model: 'Router' });
const edgeRole = await call('POST', '/dcim/device-roles', { name: 'Edge router' });
const swRole = await call('POST', '/dcim/device-roles', { name: 'DC switch' });
const core = await call('POST', '/dcim/devices', { name: 'core-01', device_type: dt.id, role: edgeRole.id, site: site.id });
const coreIf = await call('POST', '/dcim/interfaces', { device: core.id, name: 'Te1/1', type: '10gbase-x-sfpp' });

const g = 1_000_000; // Inventory DB speeds are in Kbps
const transit = await call('POST', '/circuits/circuit-types', { name: 'IP Transit', slug: 'ip-transit' });
const ix = await call('POST', '/circuits/circuit-types', { name: 'IX', slug: 'ix' });
const pni = await call('POST', '/circuits/circuit-types', { name: 'PNI', slug: 'pni' });
const providers = {};
async function provider(name) {
  if (!providers[name]) providers[name] = await call('POST', '/circuits/providers', { name });
  return providers[name];
}

const devices = [
  { name: 'edge-01', ip: '127.0.0.11', role: edgeRole, ifs: [
    { idx: 1001, name: 'Te0/0/0', descr: 'Transit: Cogent [CID-12345]', speed: 10 * g, circuit: ['CID-12345', 'Cogent', transit, 2 * g] },
    { idx: 1002, name: 'Te0/0/1', descr: 'IX: MSK-IX peering', speed: 10 * g, circuit: ['MSKIX-77', 'MSK-IX', ix, 0] },
    { idx: 1010, name: 'Te0/1/0', descr: 'core-01 Te1/1', speed: 10 * g, peer: coreIf },
    { idx: 1011, name: 'Te0/1/1', descr: 'core-02 Te1/1', speed: 10 * g },
  ] },
  { name: 'edge-02', ip: '127.0.0.12', role: edgeRole, ifs: [
    { idx: 2001, name: 'xe-0/0/0', descr: 'Transit: RETN [CID-67890]', speed: 10 * g, circuit: ['CID-67890', 'RETN', transit, 1 * g] },
    { idx: 2002, name: 'xe-0/0/1', descr: 'PNI: Netflix OCA', speed: 100 * g, circuit: ['NFLX-1', 'Netflix', pni, 0] },
    { idx: 2010, name: 'ae0', descr: 'core-01 ae2', speed: 40 * g },
    { idx: 2011, name: 'ae1', descr: 'core-02 ae2', speed: 40 * g },
  ] },
  { name: 'dc-sw-01', ip: '127.0.0.13', role: swRole, ifs: [
    { idx: 3001, name: 'Ethernet1', descr: 'Transit: local ISP backup', speed: 1 * g, circuit: ['LOCAL-1', 'Local ISP', transit, 500_000] },
    { idx: 3010, name: 'Ethernet10', descr: 'srv-web-01', speed: 10 * g },
    { idx: 3011, name: 'Ethernet11', descr: 'srv-db-01', speed: 10 * g },
  ] },
];
const out = {};
for (const d of devices) {
  const dev = await call('POST', '/dcim/devices', { name: d.name, device_type: dt.id, role: d.role.id, site: site.id, tenant: tenant.id });
  const lo = await call('POST', '/dcim/interfaces', { device: dev.id, name: 'lo0', type: 'virtual' });
  const ip = await call('POST', '/ipam/ip-addresses', { address: `${d.ip}/32`, assigned_object_type: 'dcim.interface', assigned_object_id: lo.id, dns_name: `${d.name}.demo.net` });
  await call('PATCH', `/dcim/devices/${dev.id}/`, { primary_ip4: ip.id });
  for (const i of d.ifs) {
    const itf = await call('POST', '/dcim/interfaces', { device: dev.id, name: i.name, type: '10gbase-x-sfpp', speed: i.speed, description: i.descr, custom_fields: { snmp_index: i.idx } });
    if (i.circuit) {
      const [cid, prov, type, commit] = i.circuit;
      const c = await call('POST', '/circuits/circuits', { cid, provider: (await provider(prov)).id, type: type.id, ...(commit ? { commit_rate: commit } : {}) });
      const ct = await call('POST', '/circuits/circuit-terminations', { circuit: c.id, term_side: 'A', site: site.id });
      await call('POST', '/dcim/cables', { a_terminations: [{ object_type: 'dcim.interface', object_id: itf.id }], b_terminations: [{ object_type: 'circuits.circuittermination', object_id: ct.id }] });
    }
    if (i.peer) {
      await call('POST', '/dcim/cables', { a_terminations: [{ object_type: 'dcim.interface', object_id: itf.id }], b_terminations: [{ object_type: 'dcim.interface', object_id: i.peer.id }] });
    }
  }
  out[d.name] = dev.id;
}
const servers = await call('POST', '/ipam/roles', { name: 'Servers' });
for (const [prefix, description] of [['10.10.0.0/16', 'DC servers'], ['10.20.0.0/16', 'Office'], ['198.51.100.0/24', 'Public services'],
  ['2001:db8:10::/48', 'DC servers v6'], ['2001:db8:20::/48', 'Office v6']]) {
  await call('POST', '/ipam/prefixes', { prefix, description, site: site.id, tenant: tenant.id, role: servers.id });
}
console.log(JSON.stringify({ token: tok.token, devices: out }));
