# Current: business processes

Current shows what the network is doing (traffic from NetFlow / IPFIX / sFlow and cloud flow logs, routing from BMP)
and manages network devices (status, interfaces, neighbours, clients, settings, configuration backups). How Current
works with Keystone, Ledger and Beacon is in [family.md](family.md); this page is about the processes inside Current.

## Roles in the processes

| Who | Permissions (role given in Keystone) | Does |
| --- | --- | --- |
| Administrator | everything | installs, connects Ledger and Beacon, credentials, roles |
| Network engineer | `devices:edit`, `devices:operate`, Flows, Detector | adds devices, changes settings, arranges the map, writes detection rules |
| Device administrator | `devices:admin` | reboots, runs commands, takes configuration backups |
| NOC / analyst | view of Flows, Visualize and Devices | looks at traffic, devices, clients and the map |
| Ledger, scripts | API token (`flow_…`) of a role with `integrations.inventory:read` | read the traffic of devices, interfaces, circuits and prefixes |

## C1. Install

1. The administrator copies `.env.example` to `.env` in `deploy/current` and runs `docker compose up -d`; OpenBao is
   initialized and the setup code is printed to the log.
2. After the setup code, the wizard checks and saves: general settings, OpenBao, PostgreSQL, ClickHouse with
   retention, NATS, the collector ports, Ledger (optional), Beacon (optional), GeoIP (optional) and the Keystone key
   (optional when `SPA_CONNECTION_KEY` gives it), then shows a review before it finishes.
3. Whoever Keystone gives the `admin` role is the administrator.

## C2. Bring a device under management

1. With Ledger connected, the engineer opens Devices → Add and picks a Ledger device that is not managed yet; its
   name, site and role come from Ledger and cannot be changed in Current. Without Ledger, the engineer creates a
   standalone record (one record per address).
2. "Find in network" can probe an address or scan a subnet up to /22 and suggests the platform from the SSH banner,
   web fingerprints or SNMP.
3. The engineer chooses the platform and transport and enters credentials, or chooses the SNMP / gNMI profile that
   matches the address. Credentials go to OpenBao only.
4. "Test connection" reads the device without saving. Saving schedules the first poll; the SSH host key is pinned
   on first use.

## C3. Watch devices

1. Every 15 seconds the poller (one instance in a cluster) polls the devices whose interval has passed: facts,
   interfaces with rates, neighbours (LLDP / CDP / MNDP), clients (ARP, DHCP, Wi-Fi, bridge tables) and controller
   children.
2. Clients are merged by MAC address, preferring the most precise source.
3. One failed poll marks the device `error`; two in a row mark it `down` and send a `use.device.down` event to Beacon
   with the device's Ledger reference. The next successful poll sends the resolve event.
4. The network map is built from devices, neighbours, controller children and clients; people with `devices:edit`
   arrange it by dragging devices, which pins their positions for everyone.

## C4. Change a device

1. An operator changes the hostname, an interface (enable / disable, description), DNS, NTP or flow export; an
   administrator reboots, runs a command or downloads the configuration.
2. Current checks the parameters strictly, checks the permission and that the platform supports the action, applies
   it through the driver, writes the audit log and re-reads the device.
3. Planned changes start with a maintenance window in Beacon; changes of what the device is (name, site, role) are
   made in Ledger.
4. A client can be blocked on the controller or router that saw it.

## C5. Collect and analyse traffic

1. "Flow export" on a device (or the device's own configuration) sends flows to Current's collector.
2. The collector decodes NetFlow v5 / v9, IPFIX and sFlow, applies sampling, and the enricher adds exporter and
   interface names, sites, boundaries and providers from Ledger, plus GeoIP, AS, application, threat lists, rDNS and
   classifiers.
3. Flows are stored in ClickHouse as raw flows plus 1-minute, 5-minute and 1-hour aggregates; people explore them in
   Visualize and Flows with filters and saved views. People whose role has `scope:umbrella` see only their Beacon
   visibility scope.

## C6. Detect problems

1. Detection rules run on a schedule: the detector checks every 5 seconds which rules are due, and each rule runs
   at its own interval (built-in defaults: DDoS volume and SYN every 30 s, link utilisation, silent exporters, threat
   contacts and custom rules every minute, anomalies and traffic drop every 5 minutes, link commit every 15 minutes).
2. A firing rule sends an event to Beacon; the incident's "Traffic" link opens Current on the same CI and period.
3. Dependencies seen in traffic are proposed to Beacon's CMDB.

## C7. Work with Ledger

1. Ledger sends a signed hook on every relevant change; Current also synchronizes on a schedule (15 minutes).
2. Ledger's device, interface, circuit and prefix pages show traffic from Current.
3. An address seen in traffic but missing in Ledger can be created in Ledger from Current, when Current has the
   optional Ledger editor token.

## C8. Operate

1. `GET /api/status` (permission `status:view`) shows the state of the collector, bus, enricher, writer, Ledger
   synchronization, detector and the optional sources; every container of the Docker stack has a health check.
   Settings → OpenBao shows OpenBao's state and moves the secrets to another OpenBao.
2. Upgrades are `git pull` and `docker compose up -d --build` in `deploy/current`; migrations run on start.
3. Backups are PostgreSQL, ClickHouse BACKUP, the OpenBao snapshot and the data volume (Current has no backup job).
