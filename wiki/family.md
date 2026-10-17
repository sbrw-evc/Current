# The Umbrella family: who does what

The Umbrella family has four applications. Each owns one job, and each piece of data has exactly one owner
(its *source of truth*). The other applications read that data or send events; they do not keep their own copy to
edit. This page is the map of the business processes between the applications. Each application's own processes
are in its `docs/processes.md`.

| Application | Formerly | Its one job | Source of truth for |
| --- | --- | --- | --- |
| **Keystone** | SPA, Single Point of Authorization | who a person is and what they may do | people, groups, passwords, second factor, passkeys, directories and external sign-in providers, which role a person has in each application |
| **Ledger** | Inventory DB | what exists: the inventory | sites, racks, devices, interfaces, cables, circuits, prefixes, IP addresses, VLANs, VRFs, tenants; free-form inventory tables |
| **Beacon** | Umbrella Monitoring | what is wrong and who is fixing it | events, incidents, business services and their CIs, teams and on-call ownership, maintenance windows, paging, notifications, incident response |
| **Current** | Umbrella Flow | what the network is doing, and changing it | traffic (NetFlow / IPFIX / sFlow, cloud flow logs), routing (BMP), live device state, network clients, topology, device settings and configuration backups |

Network Control is a separate product for a single home or small-office network. Its device management was taken
over by Current; it is not part of the family processes below.

## Ownership rules

1. **People only in Keystone.** No application has passwords, a password policy, passkeys, a second factor or
   directory settings. An application keeps a local record of a person only to hang its own data on (Beacon's team
   membership and visibility scope, Ledger's base membership, API tokens) and locks that record when Keystone
   disables the person.
2. **Roles are defined by the application, given by Keystone.** Each application publishes its role catalogue
   (`PUT /api/spa/v1/roles`); Keystone decides who gets which role. An application never assigns roles itself.
3. **Inventory only in Ledger.** Beacon and Current read devices, interfaces and prefixes from Ledger. Current's
   managed devices are bound to Ledger devices, and Beacon's CIs for physical objects come from Ledger. Beacon's
   NetBox synchronization is only for sites that run a real NetBox instead of Ledger; Beacon refuses to read both.
4. **Incidents only in Beacon.** Current and Ledger have no alert lists, Telegram bots or e-mail of their own:
   Current sends traffic and device events to Beacon, and Ledger shows Beacon's alert state on its devices.
5. **Notifications only in Beacon.** E-mail, Telegram, Teams, Zoom, PagerDuty and voice calls are Beacon's.
6. **Network state and changes only in Current.** Only Current connects to devices (SSH, REST, SNMP, gNMI, BMP).
   It does not store what a device *is* (that is Ledger's), only how to reach it and what it reports now.
7. **Each application keeps its own platform plumbing**: OpenBao for its secrets, PostgreSQL, a setup or status
   page and its own audit log of its own actions. These are infrastructure, not business functions, and are not
   duplicates.

## Processes between the applications

### P1. Install the family

1. The administrator installs **Keystone** first and signs in as its built-in administrator.
2. In Keystone → Applications they connect each application (Beacon, Ledger, Current) and copy its connection key
   (`spa1.…`). The rules on that page say who gets which role.
3. Each application is installed with its key (setup wizard or `SPA_CONNECTION_KEY`). On start it publishes its
   role catalogue to Keystone and reads its people.
4. The first administrator of each application is whoever Keystone gives its `admin` role; no application creates
   a local administrator.

### P2. A person signs in

1. The person opens any application; it sends them to Keystone (OpenID Connect with PKCE).
2. Keystone signs them in by the methods its policy allows, with a second factor where required, and checks they
   have a role in that application.
3. The application takes the role from the `roles` claim and starts its own session.
4. Every 5 minutes each application reads Keystone's user list. A person disabled in Keystone loses their sessions
   and API tokens everywhere at the next synchronization.

### P3. A person joins, moves or leaves

1. HR or the administrator changes the person in Keystone (or in the directory Keystone reads).
2. Roles change through Keystone's rules or the person's page in Keystone.
3. Team membership for on-call (Beacon) and base membership (Ledger) are changed in those applications, because
   they are about the work, not about access.
4. When the person leaves, disabling them in Keystone is enough: every application locks them; Ledger suspends their
   API tokens, Beacon refuses tokens of service accounts they own.

### P4. A new device appears in the network

1. An engineer creates the device in **Ledger** (by hand, CSV import or the NetBox-compatible API), with site, role,
   interfaces and management IP.
2. Ledger notifies Current (signed hook); Current refreshes its inventory at once.
3. In **Current** → Devices the engineer picks the Ledger device, chooses the platform and credentials, and tests
   the connection. Current now polls it: status, facts, interfaces, neighbours and clients.
4. Current can point the device's flow export at its collector; the exporter is then named and enriched from
   Ledger with no manual mapping.
5. **Beacon** reads the device from Ledger as a CI (every 15 minutes) and puts it into services and teams.

### P5. A device or link has a problem

1. Current detects it: a device stops answering, a link is overloaded, traffic drops, a DDoS starts, an exporter
   goes silent, a host talks to a known threat.
2. Current sends an event to Beacon (`/api/ingest/<slug>`, the `network-flow` connector), with the CI's Ledger
   reference.
3. Beacon collapses it into an incident on that CI, routes it CI → service → team, pages through PagerDuty or the
   fallback channels, and runs the response policy.
4. From the incident, "Traffic" opens Current on the CI and time range; "Grafana" opens the context dashboard.
5. Ledger shows the alert state on the device page; Current shows device status and traffic.
6. When the device answers again or the traffic is normal, Current sends the resolve event; Beacon resolves the
   incident and notifies the same people.

### P6. Change a device's settings

1. An operator opens the device in Current (permission given by Keystone) and changes the hostname, an interface,
   DNS, NTP or flow export, or (administrator) runs a command, reboots or downloads the configuration.
2. Current checks the parameters and the permission, applies the change through the device driver, writes the
   audit log and re-reads the device.
3. If the change is planned, the operator first creates a maintenance window in Beacon for the CI so that the
   expected outage does not page anyone.
4. If the change changes what the device *is* (name, role, site), it is made in Ledger; Current takes it from there.

### P7. Find who depends on what

1. Current sees which hosts talk to which services in the traffic.
2. It proposes these dependencies to Beacon (`POST /api/cmdb/proposals`).
3. A Beacon user accepts or rejects them on the CMDB map; accepted ones become service dependencies.

### P8. A person sees only their part

1. Beacon decides a person's visibility scope (all services, the services of their teams, chosen services).
2. Current asks Beacon for it (`GET /api/integrations/flow/scope`) and filters traffic and devices to the CIs in
   scope. Neither Current nor Ledger keeps a scope of their own.

### P9. Plan a change or maintenance

1. The change owner creates a maintenance window in Beacon for the CIs or services.
2. Events for those CIs during the window are recorded but do not page.

## Where duplicates were removed

| Was in | Duplicate of | Now |
| --- | --- | --- |
| Monitoring, Inventory DB, Flow: own users, passwords, passkeys, LDAP, Entra | Keystone | removed; sign-in and roles from Keystone |
| Network Control: device registry, alerts, Telegram | Ledger, Beacon | Current manages devices bound to Ledger and sends events to Beacon |
| Network Control: flow collector, detector, threat lists | Current | not taken over; Current already has them |
| Current: device credentials next to SNMP / gNMI credential profiles | itself | one set of credentials per device, used for polling and interface names |
| Beacon: NetBox sync and Ledger feed at the same time | Ledger | one inventory source per Beacon installation |

## Contracts

The wire formats (endpoints, signatures, payloads) between the applications are in Current's
[docs/integrations.md](integrations.md); the sign-in protocol is in Keystone's `docs/protocol.md`. Identifiers on the
wire keep their historical spelling (`spa1.` keys, `/api/spa/v1`, `x-umbrella-*` and `x-inventory-*` headers,
`inventory-db:` references, `umb_` tokens) so that existing installations keep working after the rename.
