// Seeds a local Inventory DB with a small network for the Flow integration test.
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
const su = await call('POST', '/auth/signup', { email: 'flow@test.local', password: 'Passw0rd!Passw0rd', name: 'Flow' });
auth = { authorization: `Bearer ${su.token}` };
await call('GET', '/netbox/me');
const tok = await call('POST', '/tokens', { description: 'flow' });

await call('POST', '/extras/custom-fields', { object_types: ['dcim.interface'], type: 'integer', name: 'snmp_index', label: 'SNMP ifIndex' });
const region = await call('POST', '/dcim/regions', { name: 'Europe' });
const tenant = await call('POST', '/tenancy/tenants', { name: 'NetOps' });
const site = await call('POST', '/dcim/sites', { name: 'DC1', region: region.id, tenant: tenant.id });
const mf = await call('POST', '/dcim/manufacturers', { name: 'Juniper' });
const dt = await call('POST', '/dcim/device-types', { manufacturer: mf.id, model: 'MX204' });
const role = await call('POST', '/dcim/device-roles', { name: 'Edge router' });
const plat = await call('POST', '/dcim/platforms', { name: 'JunOS' });
await call('POST', '/extras/tags', { name: 'Core' });
const edge = await call('POST', '/dcim/devices', { name: 'edge-01', device_type: dt.id, role: role.id, site: site.id, tenant: tenant.id, platform: plat.id, tags: ['core'] });
const core = await call('POST', '/dcim/devices', { name: 'core-01', device_type: dt.id, role: role.id, site: site.id });
const mk = (device, name, extra = {}) => call('POST', '/dcim/interfaces', { device, name, type: '10gbase-x-sfpp', speed: 10000000, ...extra });
const ae0 = await call('POST', '/dcim/interfaces', { device: edge.id, name: 'ae0', type: 'lag', custom_fields: { snmp_index: 600 } });
const xe0 = await mk(edge.id, 'xe-0/0/0', { description: 'Transit: Telia', custom_fields: { snmp_index: 501 } });
const xe1 = await mk(edge.id, 'xe-0/0/1', { custom_fields: { snmp_index: 502 }, lag: ae0.id });
const xe2 = await mk(edge.id, 'xe-0/0/2', { custom_fields: { snmp_index: 503 } });
const lo0 = await call('POST', '/dcim/interfaces', { device: edge.id, name: 'lo0', type: 'virtual', custom_fields: { snmp_index: 16 } });
const cxe0 = await mk(core.id, 'xe-0/0/0');
const ip = await call('POST', '/ipam/ip-addresses', { address: '192.0.2.1/32', assigned_object_type: 'dcim.interface', assigned_object_id: lo0.id, dns_name: 'edge-01.example.net' });
await call('POST', '/ipam/ip-addresses', { address: '2001:db8::1/128', assigned_object_type: 'dcim.interface', assigned_object_id: lo0.id });
await call('PATCH', `/dcim/devices/${edge.id}/`, { primary_ip4: ip.id });
await call('POST', '/ipam/ip-addresses', { address: '10.1.0.1/24', assigned_object_type: 'dcim.interface', assigned_object_id: xe2.id });
const vrf = await call('POST', '/ipam/vrfs', { name: 'prod', rd: '65000:1' });
const prole = await call('POST', '/ipam/roles', { name: 'Servers' });
const vlan = await call('POST', '/ipam/vlans', { vid: 100, name: 'servers', site: site.id });
await call('POST', '/ipam/prefixes', { prefix: '10.0.0.0/8', status: 'container', description: 'RFC1918' });
await call('POST', '/ipam/prefixes', { prefix: '10.1.0.0/24', site: site.id, tenant: tenant.id, role: prole.id, vlan: vlan.id, vrf: vrf.id });
await call('POST', '/ipam/prefixes', { prefix: '2001:db8::/32', description: 'doc v6' });
const prov = await call('POST', '/circuits/providers', { name: 'Telia' });
const ctype = await call('POST', '/circuits/circuit-types', { name: 'IP Transit', slug: 'ip-transit' });
const circ = await call('POST', '/circuits/circuits', { cid: 'TEL-123', provider: prov.id, type: ctype.id, commit_rate: 1000000 });
const ct = await call('POST', '/circuits/circuit-terminations', { circuit: circ.id, term_side: 'A', site: site.id });
await call('POST', '/dcim/cables', { a_terminations: [{ object_type: 'dcim.interface', object_id: xe0.id }], b_terminations: [{ object_type: 'circuits.circuittermination', object_id: ct.id }] });
await call('POST', '/dcim/cables', { a_terminations: [{ object_type: 'dcim.interface', object_id: xe1.id }], b_terminations: [{ object_type: 'dcim.interface', object_id: cxe0.id }] });
const ctt = await call('POST', '/virtualization/cluster-types', { name: 'VMware' });
const cl = await call('POST', '/virtualization/clusters', { name: 'c1', type: ctt.id, site: site.id });
const vm = await call('POST', '/virtualization/virtual-machines', { name: 'app-vm-01', cluster: cl.id });
const vmi = await call('POST', '/virtualization/interfaces', { virtual_machine: vm.id, name: 'eth0' });
await call('POST', '/ipam/ip-addresses', { address: '10.1.0.50/24', assigned_object_type: 'virtualization.vminterface', assigned_object_id: vmi.id, dns_name: 'app.example.net' });
console.log(JSON.stringify({ token: tok.token, edge: edge.id, vm: vm.id }));
