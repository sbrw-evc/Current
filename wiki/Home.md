# Current

*Formerly **Umbrella Flow**. Current, part of the Umbrella family, shows what the network is doing and manages the
network devices: traffic (NetFlow / IPFIX / sFlow, cloud flow logs), routing (BMP), device state and settings.*

The other members of the family: [Keystone](https://onedev.evcsbrw.ru/Monitoring/Keystone) (sign-in and access; formerly SPA),
[Beacon](https://onedev.evcsbrw.ru/Monitoring/Beacon) (incidents; formerly Umbrella Monitoring),
[Ledger](https://onedev.evcsbrw.ru/Monitoring/Ledger) (inventory; formerly Inventory DB) and Network Control, whose device
management Current took over. Who owns what between them: [docs/family.md](family.md).

Network traffic analysis for NetFlow v5 / v9, IPFIX and sFlow and management of the network devices, built into the
Umbrella family:

- **[Beacon](https://onedev.evcsbrw.ru/Monitoring/Beacon)** gets traffic incidents (link overload,
  DDoS, anomalies, silent exporters, threat contacts) on the right CI, and a "Traffic" link from every incident.
- **[Ledger](https://onedev.evcsbrw.ru/Monitoring/Ledger)** (DCIM / IPAM) is the enrichment source: exporter
  names, sites, roles, interfaces, boundaries, providers and networks come from it with no hand-written mapping, and
  its device, interface and circuit pages show traffic from Current.

One Go binary, a React console, flows in ClickHouse, configuration in PostgreSQL, every secret in OpenBao. It is
deployed with Docker Compose (one command) or a Helm chart, and configured in a first-run setup wizard.

![Overview with live demo traffic](https://onedev.evcsbrw.ru/Monitoring/Current/~raw?revision=main&file=app/docs/screens/home-live.png)

## Contents

- [Key features](#key-features)
- [Architecture](#architecture)
- [Quick start (Docker)](#quick-start-docker)
- [Sending traffic to Current](#sending-traffic-to-current)
- [Other ways to run](#other-ways-to-run)
- [Integrations](#integrations)
- [Sign-in and access](#sign-in-and-access)
- [Security and secrets](#security-and-secrets)
- [Operations](#operations)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [Compatibility after the rename](#compatibility-after-the-rename)
- [License](#license)

## Key features

- **Every flow source in one place.** NetFlow v5 / v9, IPFIX, sFlow v5 and cloud flow logs (AWS, Azure, GCP), with
  sampling rates learned from option templates or set per exporter and interface.
- **Flows that already know the network.** Each flow carries the exporter's site and role, interface names and
  speeds, internal / external boundary, provider, network, tenant and CI, taken from Ledger and kept in sync
  through a signed change hook.
- **Routing and device data.** A built-in BMP receiver adds AS paths, communities and next hops (including VPN, labeled
  unicast and EVPN routes); gNMI and SNMP fill interface data for devices outside Ledger.
- **More context per address.** GeoIP and ASN, applications by port, reverse DNS, threat intelligence from public
  blocklists, and custom CEL classifiers with a live preview.
- **Answers in a few clicks.** Visualize by any dimension as stacked, lines, grid or sankey graphs, in and out on one
  graph, bps / pps / % utilisation and the 95th percentile, with a filter language that completes as you type
  (`SrcAS = 65000 AND InIfBoundary = external`), saved views and shareable links; raw flow search; an overview of what
  needs attention.
- **Incidents, not just graphs.** Rules for link utilisation, circuit commit, volumetric and SYN DDoS, baseline
  anomalies, traffic drops, silent exporters and threat contacts raise Beacon incidents on the right CI and resolve
  them when traffic is back to normal.
- **Traffic where engineers already look.** Traffic chips, sparklines and circuit 95th percentile in Ledger, a
  "Traffic" link from Beacon incidents, per-interface metrics on `/metrics` and a "CI traffic" dashboard.
- **The network devices themselves.** 28 platform families (MikroTik, Cisco, Juniper, Aruba, Huawei, FortiGate,
  Keenetic, OpenWrt, UniFi, Omada, Meraki, Redfish, SNMP and others) plus gNMI. Each is polled on a schedule for
  interfaces, LLDP / CDP neighbours and clients merged by MAC, and drawn on a network map. Name, interfaces, DNS, NTP
  and flow export are set from the console. Devices come from Ledger, credentials stay in OpenBao, and an
  unreachable device becomes a Beacon incident ([docs/devices.md](devices.md)).
- **CMDB from real traffic.** Steady CI-to-CI flows become dependency proposals on Beacon's CMDB map.
- **Fast storage, long history.** Raw flows plus 1 min / 5 min / 1 h aggregates in ClickHouse, with the resolution
  picked for the requested period and separate retention for each level.
- **Sign-in and access are managed in [Keystone](https://onedev.evcsbrw.ru/Monitoring/Keystone).** People sign in through
  Keystone, the sign-in service of the Umbrella family (passwords, passkeys, LDAP / AD, Entra ID, Google, Apple and
  OpenID Connect live there); Current reads its people and their roles from Keystone and publishes its own roles to it
  ([docs/identity-federation.md](identity-federation.md)).
- **Secure by default.** Every secret in OpenBao, no passwords kept in Current, page-level roles,
  visibility limited to a user's Beacon services, API tokens and an audit log.
- **Up in one command.** One image for every role, a Docker Compose stack or a Helm chart, a first-run setup wizard
  with a check at every step, horizontal scaling by role.
- **Russian and English UI**, light and dark themes, a phone layout.

| Visualize (sankey) | Exporters |
|---|---|
| ![Visualize](https://onedev.evcsbrw.ru/Monitoring/Current/~raw?revision=main&file=app/docs/screens/visualize-sankey-live.png) | ![Exporters](https://onedev.evcsbrw.ru/Monitoring/Current/~raw?revision=main&file=app/docs/screens/exporters-live.png) |

## Architecture

```mermaid
flowchart LR
  R[Routers, switches,<br/>firewalls, clouds] -- "NetFlow / IPFIX / sFlow,<br/>flow logs, BMP" --> COL[collector]
  COL --> BUS[(NATS JetStream<br/>or in-process bus)]
  BUS --> EN[enricher<br/>Ledger, GeoIP, BMP,<br/>gNMI / SNMP, CEL]
  EN --> CH[(ClickHouse<br/>flows + 1m / 5m / 1h)]
  API[api + web console] --> CH
  API --> PG[(PostgreSQL<br/>configuration)]
  DET[detector] --> CH
  DET -- events --> UMB[Beacon]
  INV[Ledger] -- "DCIM / IPAM, change hook" --> EN
  API -- "traffic status, sparklines" --> INV
  OB[(OpenBao)] -. secrets .-> API & EN & DET
```

The same binary runs every role: `all` (default, one container for small and medium installs), or `collector`,
`enricher`, `detector` and `api` as separate processes for load, connected by NATS JetStream. Collectors scale behind a
UDP load balancer, enrichers as a JetStream consumer group.

| Component | Choice |
|---|---|
| Backend | Go 1.26, own BMP / BGP decoder, CEL, pgx, goose |
| Web console | React 19, TypeScript, Vite, TanStack Query, react-router 7, Apache ECharts, CodeMirror 6 |
| Flow storage | ClickHouse 25.8 LTS (raw flows 15 days, aggregates 30 days / 90 days / 2 years by default) |
| Configuration | PostgreSQL 17 |
| Bus | NATS JetStream 2.11 (optional in role `all`) |
| Secrets | OpenBao 2.7 (KV v2, AppRole) |
| Dashboards | Grafana 13 with the ClickHouse datasource |

Details and the reasoning behind each choice: [docs/plan.md](plan.md).

## Quick start (Docker)

You need Docker with Compose v2 (Docker Engine on Linux, or Docker Desktop on macOS / Windows), about 6 GB of memory
for the containers (ClickHouse alone is limited to 4 GB) and a few GB of disk.

```sh
git clone https://onedev.evcsbrw.ru/Monitoring/Current
cd current/deploy/current
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD, NATS_TOKEN and CLICKHOUSE_GRAFANA_PASSWORD
docker compose --profile demo up -d --build
docker compose logs current | grep setup_code
```

The first start builds the `current` image from `app/` and starts Current, PostgreSQL, ClickHouse, NATS and
OpenBao. `openbao-init` initialises and unseals OpenBao, creates the `flow` mount and AppRole and copies the
passwords from `.env` into it. `--profile demo` adds a container that sends synthetic NetFlow v9, IPFIX and sFlow
traffic; leave it out for a real installation.

Then:

1. Open <http://localhost:8080> (or `http://<host>:8080`).
2. Enter the setup code from the log.
3. Click through the wizard: OpenBao, PostgreSQL, ClickHouse and NATS are prefilled for the bundled services.
   Ledger, Beacon and GeoIP are optional and can be set later in the console.
4. Paste the Keystone connection key (or set `SPA_CONNECTION_KEY` in `.env`, see [Sign-in and access](#sign-in-and-access)).
   The wizard writes `flow.json` to the `flow-data` volume and opens the sign-in page; whoever Keystone gives Current's
   `admin` role administers Current.

With the demo profile the graphs fill within a minute: three exporters (`edge-01`, `edge-02`, `dc-sw-01`) appear on the
Exporters page and in Visualize.

**On a host that already runs Beacon**, its OpenBao already holds port 8200: set `OPENBAO_PORT=8201`
(or another free port) in `.env` before the first start. Check the other published ports the same way (8080, 8123,
3000, 2055 and 6343).

**Keep `deploy/current/secrets/openbao/init.txt` safe.** It holds OpenBao's unseal keys and root token; without it the
secrets, and so the installation, cannot be recovered.

Useful profiles and files:

| Command | What it adds |
|---|---|
| `docker compose --profile demo up -d` | synthetic traffic generator |
| `docker compose --profile geoip up -d` | MaxMind GeoLite2 updates (`GEOIPUPDATE_*` in `.env`, then `FLOW_GEOIP_DATABASES`) |
| `docker compose --profile grafana up -d` | Grafana with the "CI traffic" dashboard on <http://localhost:3000> |
| `COMPOSE_FILE=docker-compose.yml:docker-compose.umbrella.yml` in `.env` | joins the shared `umbrella` network with Beacon and Ledger |

From `app/` the same is `make stack` and `make stack-demo`. The full Docker guide (ports, secrets, upgrades, backups):
[deploy/current/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/current/README.md).

## Sending traffic to Current

| Port | Protocol | What |
|---|---|---|
| 8080 | TCP | web console, API, `/metrics`, `/healthz` |
| 2055 | UDP | NetFlow v5 / v9, IPFIX |
| 6343 | UDP | sFlow v5 |
| 10179 | TCP | BMP, listened to only after it is enabled under Data collection → BMP routing |

Point the exporters at the Docker host, from a stable source address (a loopback): Current identifies an exporter by the
source address of its datagrams and matches it to the Ledger device by its primary IP. Export the interface and
sampler option templates so Current learns interface names and sampling rates. Configuration examples for Cisco IOS XE /
IOS XR, Junos and sFlow switches are in [deploy/current/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/current/README.md#pointing-routers-at-current).

Cloud flow logs are posted to `/api/ingest/flowlogs/{aws,azure,gcp}`; the Data collection → Cloud flow logs page shows
the URLs, tokens and setup snippets for each provider.

## Other ways to run

**Kubernetes.** The Helm chart in [deploy/helm/current](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/helm/current/README.md) runs Current as one
Deployment or one Deployment per role, against external ClickHouse, PostgreSQL, NATS and OpenBao
(`--set dev.enabled=true` bundles throwaway ones for evaluation).

**From source**, with Go 1.26+, Node.js 22, PostgreSQL 17, ClickHouse 25.8 and OpenBao (NATS optional):

```sh
cd app
make openbao-dev          # OpenBao dev server in Docker: address http://127.0.0.1:8200, token dev-root, mount flow
make build && make run    # http://localhost:8080, the setup code is in the log
make demo                 # synthetic traffic to 127.0.0.1:2055
```

Single-host and split-role walkthroughs: [app/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/app/README.md#run).

## Integrations

| With | What happens | Where it is set up |
|---|---|---|
| Ledger → Current | exporters, interfaces, circuits, prefixes and CIs enrich every flow; a signed hook triggers an early sync on changes | wizard step or Integrations → Ledger |
| Current → Ledger | traffic chips, 24 h sparklines and circuit 95th percentile on device, interface and circuit pages; live addresses missing from IPAM | Ledger integration `kind: flow` with a Current API token |
| Current → Beacon | detector events and unreachable network devices (`use.device.down`) become incidents on the right CI, with a link back to Current | Beacon quick connect `network-flow`, then wizard step or Integrations → Beacon |
| Beacon → Current | users see only the flows of their Beacon services; steady CI ↔ CI traffic becomes CMDB relation proposals | Beacon service-account token under Integrations → Beacon |
| Grafana | "CI traffic" dashboard with the same `var-ci` variables as Beacon's Grafana links | `--profile grafana`, or import into an existing Grafana |

Contracts between the three applications: [docs/integrations.md](integrations.md). Grafana:
[deploy/grafana/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/grafana/README.md).

## Sign-in and access

Sign-in and access are managed in **Keystone**, the sign-in service of the Umbrella family
([repository](https://onedev.evcsbrw.ru/Monitoring/Keystone), contract: [docs/protocol.md](https://onedev.evcsbrw.ru/Monitoring/Keystone/~files/main/docs/protocol.md)). Current keeps no
passwords, password policy, passkeys or directory settings; it has no sign-in form and no first administrator of its
own.

To connect Current:

1. In Keystone: **Applications → Connect an application**, type `current` (Keystone still accepts the former `umbrella-flow`), the address of Current. The redirect address
   is `<address>/api/auth/spa/callback`, the address after sign-out `<address>/`.
2. On the **Access** step assign Current's roles (`admin`, `viewer` and the custom roles Current publishes) to people and
   groups.
3. Give Current the **connection key** (`spa1.…`) Keystone shows: `SPA_CONNECTION_KEY`, a file named by
   `SPA_CONNECTION_KEY_FILE`, or the setup wizard (kept in OpenBao at `spa#connection_key`). Set `SPA_PUBLIC_URL` when
   Current is reached under another address than the request's.

Current then sends people to Keystone to sign in, synchronizes its users every 5 minutes (Settings → Keystone → Synchronize now),
disables people Keystone disables or removes (their sessions and API tokens stop working) and publishes its role catalogue
whenever its roles change. Password and passkeys: user menu → **Account and security** (Keystone). Details:
[docs/identity-federation.md](identity-federation.md).

## Security and secrets

- OpenBao is the only secret store. Database passwords, Ledger and Beacon tokens, the Keystone connection key
  (when given in the wizard) and session keys live there; PostgreSQL and `flow.json` keep only
  `openbao://mount/path#key` references. Current keeps no passwords: people sign in through Keystone.
- Current signs in to OpenBao with AppRole and caches reads for 30 s, so a rotation in OpenBao needs no restart.
- The API never returns a secret (only a `*_set` flag), and secrets never reach logs or the audit log.
- `.env` in the Docker stack holds only bootstrap passwords for the bundled service containers; the `current` container
  never sees them.
- Sessions are HttpOnly cookies with CSRF protection, started after the Keystone sign-in (OpenID Connect with PKCE S256, a
  nonce and a signed single-use state); API tokens are stored as HMACs, shown once and stop working when Keystone disables
  the person who issued them.
- Behind an HTTPS reverse proxy set `FLOW_SECURE_COOKIES=true` and `FLOW_TRUSTED_PROXIES`.
- BMP is unauthenticated: limit who can reach TCP 10179 and list the allowed routers in the BMP settings.

The full list of OpenBao paths: [app/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/app/README.md#secrets).

## Operations

- Health: `docker compose ps` (every service has a healthcheck) and `curl http://localhost:8080/healthz`.
- Component status: `GET /api/status` (collector, bus, enricher, writer, Ledger sync, detector and the optional
  sources).
- Metrics: Prometheus format on `http://<host>:8080/metrics` (`flow_*`, plus per-interface utilisation).
- Logs: `docker compose logs -f current`.
- Upgrade: `git pull && docker compose up -d --build`; PostgreSQL and ClickHouse migrations run on start. Back up
  first.
- Backup: PostgreSQL (`pg_dump`), ClickHouse (`BACKUP DATABASE`), an OpenBao raft snapshot together with
  `secrets/openbao/init.txt`, and the `flow-data` volume. Commands:
  [deploy/current/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/current/README.md#backup-and-restore).

## Development

```sh
cd app
make dev-api              # backend on :8080 (go run)
make dev-web              # Vite dev server on :5173
cd web && npm run dev:mock   # console against the built-in mock server, no backend needed
make test                 # go vet, go test, web typecheck and Vitest
make fmt                  # gofmt
make image                # Docker image current:<version>
```

Backend tests use real PostgreSQL on `localhost:5432` (`postgres` / `postgres`) and ClickHouse on `localhost:9000`;
`FLOW_TEST_POSTGRES=off` and `FLOW_TEST_CLICKHOUSE=off` skip those tests. OpenBao is faked.
`FLOW_TEST_E2E=1 go test ./internal/wiring` runs the whole pipeline in one process.

Tests that need the environment (they fail, not skip, when it is missing; CI provides both):

| Test | Needs | Fails without it with |
|---|---|---|
| `TestStepChecks` (`internal/setup`) | a PostgreSQL that checks passwords on TCP (`scram-sha-256` or `md5` in `pg_hba.conf`; a `trust` line for `127.0.0.1` accepts any password) and ClickHouse at `FLOW_TEST_CLICKHOUSE` | `wrong password accepted: …`, then `this test needs ClickHouse …` |
| `TestCompleteDockerStyle` (`internal/setup`) | ClickHouse at `FLOW_TEST_CLICKHOUSE` (the setup migrates its schema) | `this test needs ClickHouse …` (`clickhouse_unavailable`) |

The other ClickHouse tests (`chtest`) skip when the server is unreachable. A PostgreSQL elsewhere:
`FLOW_TEST_POSTGRES=postgres://postgres:postgres@127.0.0.1:55432/postgres?sslmode=disable`.

CI ([.github/workflows/ci.yml](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/.github/workflows/ci.yml)) runs on every pull request: `gofmt`, `go vet`,
`go test -race` against PostgreSQL and ClickHouse, the web typecheck, tests and build, the Compose configuration
checks and the image build. Work goes to a branch from `main` and is merged by pull request once CI is green.

Conventions: documentation and code comments are in English, the UI is bilingual (RU / EN). Dependencies must be
open source with permissive licences.

## Repository layout

```
app/
  backend/          Go: cmd/current (entry point, roles) and internal/ packages (collector, bus, enrich, bmp,
                    gnmi, snmp, query, detector, setup, auth, secrets, store, …)
  web/              React console
  docs/screens/     screenshots
  Dockerfile        one image for every role (distroless, non-root)
  Makefile
deploy/
  current/          Docker Compose stack: Current, PostgreSQL, ClickHouse, NATS, OpenBao (+ demo, geoip, grafana)
  helm/current/     Helm chart
  grafana/          "CI traffic" dashboard and provisioning
docs/
  plan.md           goals, architecture, stack and stages
  api.md            REST API contract
  devices.md        network device management
  family.md         the Umbrella family: who owns what, processes between the applications
  processes.md      business processes inside Current
  integrations.md   contracts with Beacon and Ledger
```

## Documentation

| Document | What is in it |
|---|---|
| [app/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/app/README.md) | what each part does, secrets, running from source, environment variables, package layout |
| [deploy/current/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/current/README.md) | Docker deployment: services, ports, router configuration, upgrades, backups |
| [deploy/helm/current/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/helm/current/README.md) | Kubernetes: roles, values, services |
| [deploy/grafana/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/deploy/grafana/README.md) | the "CI traffic" dashboard |
| [docs/plan.md](plan.md) | plan, architecture, data model, stack |
| [docs/api.md](api.md) | REST API |
| [docs/devices.md](devices.md) | network devices: platforms, Ledger binding, polling, actions, clients, map, events |
| [docs/family.md](family.md) | the Umbrella family: which application owns which data, processes between the applications |
| [docs/processes.md](processes.md) | business processes inside Current: install, devices, traffic, detection, Ledger, operations |
| [docs/integrations.md](integrations.md) | cross-application contracts |

## Troubleshooting

| Symptom | What to check |
|---|---|
| No `setup_code` in the log | Current waits for its dependencies: `docker compose ps` must show `openbao-init`, `postgres`, `clickhouse` and `nats` healthy. The code is also kept in the `flow-data` volume (`/data/setup-token`), and `FLOW_SETUP_TOKEN` sets a fixed one. |
| `clickhouse` keeps restarting | not enough memory for the container: give Docker more memory or lower `CLICKHOUSE_MEMORY_LIMIT` in `.env`. |
| After the rename, `docker compose up` in `deploy/current` reports busy ports, or OpenBao stays sealed | the stack moved from `deploy/flow` (project `umbrella-flow`) to `deploy/current` (project `current`): stop the old containers with `docker compose -p umbrella-flow down` (volumes stay), and move `.env` and `secrets/` from `deploy/flow` to `deploy/current` before `docker compose up -d --build`. |
| Port 8080, 2055 or 6343 is busy | change `FLOW_HTTP_PORT`, `FLOW_NETFLOW_PORT` or `FLOW_SFLOW_PORT` in `.env`. |
| `openbao` fails with "port is already allocated" | another OpenBao or Vault (often Beacon's) uses 8200 on the host: set `OPENBAO_PORT=8201` in `.env`. The port is only for the OpenBao UI on the host; Current reaches OpenBao inside the Compose network either way. |
| `nats` stays unhealthy, log shows a parse or nil pointer error | older checkouts read an all-digit `NATS_TOKEN` (such as `12345`) as a number: `git pull`, or use a token with a letter in it. |
| Current joined to the `umbrella` network talks to the wrong database | an installation set up before the `flow-*` host aliases has `postgres`, `clickhouse`, `nats` and `openbao` as hosts, and Beacon's containers may answer to the same names. Change them to `flow-postgres`, `flow-clickhouse`, `flow-nats` and `flow-openbao` in `flow.json` (the `flow-data` volume) and restart `current`, or stay off the shared network. |
| Exporters show up under the wrong address | something between the router and Current rewrites the UDP source address (NAT, a load balancer with SNAT). Keep the original source; on Linux the default Docker setup does. |
| Flows arrive but without names, sites or boundaries | connect Ledger (Integrations → Ledger) and check that each exporter's source address is the device's primary IP. |
| Graphs show bytes too low | the exporter does not report its sampling rate: set it on the Exporters page. |
| OpenBao is sealed after a host restart | `OPENBAO_AUTO_UNSEAL=true` (default) unseals it with the keys in `secrets/openbao/init.txt`; check that the file is still there. |

## Compatibility after the rename

Current was called Umbrella Flow (and "Flow" in its own interface). The product, the Go module
(`github.com/sbrw-evc/current/app/backend`), the binary (`cmd/current`, `/current` in the image), the Docker image
(`current`), the compose stack (`deploy/current`, project and service `current`), the Helm chart (`deploy/helm/current`,
chart `current`), the web package (`current-web`) and the Go packages `internal/beacon` and `internal/keystone` carry the
new names, and the other apps are called Keystone, Beacon and Ledger. The console pages Settings → Beacon, Ledger and
Keystone moved to `/settings/beacon`, `/settings/ledger` and `/settings/keystone`; the old addresses
(`/settings/umbrella`, `/settings/inventory-db`, `/settings/spa`) redirect. The GitHub repository is to be renamed to
`sbrw-evc/current`; GitHub redirects the old address.

These identifiers keep the old spelling on purpose, because existing installations and the other apps depend on them:

| kept | why |
| --- | --- |
| environment variables `FLOW_*` (`FLOW_ROLE`, `FLOW_DATA_DIR`, `FLOW_IMAGE`, `FLOW_TEST_POSTGRES`, `FLOW_SETUP_DEFAULTS_*`, …) | existing deployments, `.env` files and Helm values |
| the Keystone protocol: `SPA_CONNECTION_KEY`, `SPA_CONNECTION_KEY_FILE`, `SPA_PUBLIC_URL`, the key prefix `spa1.`, `/api/auth/spa`, `/api/auth/spa/start` and `/api/auth/spa/callback`, Keystone's `/api/spa/v1/*`, the OpenBao key `spa#connection_key`, `source = spa` of people from Keystone, the Helm value `spa.connectionKeySecret` | the wire format between Keystone and its applications (Keystone's `docs/protocol.md`) |
| the Keystone application type `umbrella-flow` | Keystone accepts it and stores it as `current`; new connections use `current` |
| the configuration file `flow.json`, the OpenBao mount and AppRole `flow`, the policy `flow-policy.hcl`, the OpenBao paths (`postgres`, `clickhouse`, `nats`, `inventory-db`, `inventory-db-hook`, `inventory-db-write`, `umbrella`, `umbrella-api`, `spa`, `devices/<id>`, `keys`, …; [app/README.md](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/app/README.md#secrets)) | existing configuration and secrets |
| the PostgreSQL and ClickHouse database and user `flow`, the tables, the ClickHouse files `flow.xml` | existing data |
| the compose volumes `umbrella-flow_*` (pinned with `name:`), the host aliases `flow-postgres`, `flow-clickhouse`, `flow-nats`, `flow-openbao`, the host names `flow` and `umbrella-flow` of the `current` service (in the stack and on the shared `umbrella` network) | existing data; Beacon, Ledger and Grafana configured with `http://flow:8080` keep working |
| the NATS JetStream streams and subjects (`FLOWS`, `FLOW_BMP`, `flow.*`) and the `Flow-Bmp-*` message headers | messages in flight and running replicas during an upgrade |
| the metrics prefix `flow_` | dashboards and alert rules |
| the cookies `flow_session` and `flow_spa`, the token prefix `flow_`, the `localStorage` keys `flow.*` | sessions, issued API tokens and saved preferences |
| the API paths (`/api/integrations/inventory-db/*`, `/api/inventory-db`, `/api/settings/umbrella`, `/api/settings/umbrella/api/*`, `/api/settings/spa`, …) and the JSON keys `inventory`, `umbrella`, `spa`, `links.flow`, `flow_url` | Ledger, Beacon, scripts and the web console of an older release |
| the permission IDs (`settings.umbrella`, `settings.inventory`, `integrations.inventory:read`, `scope:umbrella`, …) and the setup steps `inventory`, `umbrella`, `spa` | roles stored with their permissions and published to Keystone |
| the change-hook headers `x-inventory-timestamp` and `x-inventory-signature` | Ledger signs its hooks with them |
| the source references `inventory-db:…`, the Ledger integration kind `flow` | stored CIs and flows and the contracts with Ledger and Beacon |
| the `source` `umbrella-flow` of dependency proposals and events, the label `umbrella_test` of test events, the Beacon connector template `network-flow` | Beacon matches proposals, events and test events by them (Beacon's connector preset for Current lives in Beacon's repository) |
| Beacon's permission `integrations.flow:read` and its path `/api/integrations/flow/scope` | Beacon's API |
| Grafana UIDs `flow-ci-traffic` and `flow-clickhouse`, the dashboard provider `umbrella-flow` and the dashboard file `flow-ci-traffic.json` | dashboard links stored in Beacon's settings; the file is identical in Beacon's `deploy/grafana` |

Upgrading an existing installation:

- **Docker Compose.** The stack moved from `deploy/flow` to `deploy/current` and the compose project from
  `umbrella-flow` to `current`. Stop the old containers (`docker compose -p umbrella-flow down`; the volumes stay), move
  `.env` and `secrets/` (OpenBao's `init.txt`) from `deploy/flow` to `deploy/current`, then
  `docker compose up -d --build` there. The volumes keep their names, so the data is found. A `FLOW_IMAGE` set to
  `umbrella-flow:latest` in `.env` keeps working; the default is now `current:latest`.
- **Helm.** The chart is `deploy/helm/current` (chart name `current`). A release installed with the `umbrella-flow`
  chart keeps its resource names, selector labels and PersistentVolumeClaim with `--set nameOverride=umbrella-flow`.

## License

Proprietary. See [LICENSE](https://onedev.evcsbrw.ru/Monitoring/Current/~files/main/LICENSE).
