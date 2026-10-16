# Current: application

*Formerly **Umbrella Flow**. Current, part of the Umbrella family: network traffic and network devices. What kept its
old name after the rename is listed in the [repository README](../README.md#compatibility-after-the-rename).*

NetFlow / IPFIX / sFlow analysis and network device management integrated with Beacon and Ledger. Backend in Go (one binary,
every pipeline role), web console in React + TypeScript, configuration in PostgreSQL, flows in ClickHouse, secrets
in OpenBao. Plan: [docs/plan.md](../docs/plan.md), REST contract: [docs/api.md](../docs/api.md).

Deployment is Docker-first: [deploy/current](../deploy/current/README.md) brings up the whole stack with one command.

## What works

| Part | What it does | Package |
|---|---|---|
| Setup wizard | opens on the first start (no `flow.json`): setup code (log + `FLOW_DATA_DIR/setup-token`, 5 wrong codes lock it for a minute), general settings, OpenBao, PostgreSQL (can attach to an existing Current database), ClickHouse with retention, NATS, collector addresses, optional Ledger / Beacon / GeoIP, the Keystone connection key (optional: it can come from `SPA_CONNECTION_KEY`); there is no first administrator — whoever Keystone gives Current's `admin` role administers Current. Every step has a check (`POST /api/setup/test/{step}`); the final `POST /api/setup` re-checks everything, writes secrets to OpenBao, migrates PostgreSQL and ClickHouse, writes `flow.json` and switches to the console without a restart. In Docker the fields are prefilled from `FLOW_SETUP_DEFAULTS_*` | `internal/setup` |
| Sign-in and access | through [Keystone](https://github.com/sbrw-evc/keystone), sign-in and access for the Umbrella family (its docs/protocol.md): `GET /api/auth/spa/start` → Keystone (OpenID Connect code flow, PKCE S256, nonce, signed single-use state, verifier cookie on `/api/auth/spa/`) → `GET /api/auth/spa/callback` (ID token verified against Keystone's JWKS: RS256, `iss`, `aud`, `exp`, `nonce`), then Current's own session (HttpOnly cookie `flow_session`, 12 h idle, 7 days max, `X-CSRF-Token` on state-changing requests); sign-out ends it and goes to Keystone's sign-out. The connection key `spa1.…` comes from `SPA_CONNECTION_KEY`, `SPA_CONNECTION_KEY_FILE` or OpenBao (`spa#connection_key`) | `internal/keystone`, `internal/oidcx`, `internal/auth`, `internal/app/keystone.go` |
| Users from Keystone | every 5 minutes (one replica, PostgreSQL advisory lock) and on Settings → Keystone → Synchronize now: `GET /api/spa/v1/users` with ETags creates, updates and disables the users (bound by Keystone user ID; an account made before Keystone is bound once by user name, unclaimed ones are disabled), maps the `roles` claim to the user's role and ends sessions of disabled people; API tokens of a disabled person stop working. Current publishes its roles (`PUT /api/spa/v1/roles`, by their stable `ident`; Administrator is `admin`, Viewer `viewer`) at start and whenever they change. Settings → Users is read-only ("Managed in Keystone") | `internal/app/keystone.go`, `internal/store/keystone.go` |
| API tokens | service accounts with a role and bearer tokens `flow_…` (HMAC-SHA256 with `keys#tokens`, plaintext shown once, expiry, last use, revoke; no CSRF); Settings → API tokens; audit of creation, revocation and use from a new address | `internal/auth`, `internal/store`, `internal/app` |
| Roles | permissions `<page>:<function>` (`GET /api/access/catalog`), built-in Administrator (everything, `admin` in Keystone) and Viewer (visualize, flows, exporters, `viewer`), custom roles with a stable `ident` published to Keystone; Keystone assigns them. Settings → Roles lists the roles and creates, edits (name, description, permissions from the catalog) and deletes custom ones through `/api/roles` (each change republishes the catalogue to Keystone); built-in roles are read-only, a role given to people cannot be deleted | `internal/access`, `internal/app`, `web/src/pages/settings/Roles.tsx` |
| Configuration | relational PostgreSQL schema (goose migrations embedded in the binary): users, roles, sessions, settings, saved views, classifier rules, Ledger connection, sampling overrides, audit log | `internal/store` |
| Platform API | `/healthz`, `/metrics`, `/api/version`, sign-in through Keystone, users (read-only), roles, Keystone connection and synchronization, saved views, classifiers (with validation through the classifier package), Ledger connection / test / sync / schedule, sampling overrides, general settings, Beacon connection with a test event, OpenBao status / test / move to another OpenBao, service accounts and API tokens, system status, audit log, `/api/schema` | `internal/app` |
| Traffic API | visualize (time series and sankey; `query.ValidationError` / filter errors → 400), filter validation and completion (columns, operators, values: built-in symbols plus the most frequent values of the last 24 h from ClickHouse, `flows_1h` for aggregated columns), raw flow search, exporters (ClickHouse aggregates merged with the collector registry in role `all`), home widgets, unknown Ledger objects, classifier validation / preview | `internal/wiring` over `internal/query`, `internal/filter`, `internal/inventory`, `internal/classifier` |
| Pipeline | collector (NetFlow v5/v9, IPFIX, sFlow; sampling overrides from PostgreSQL applied at run time) → bus (in-process in role `all` without NATS, NATS JetStream otherwise) → enricher (Ledger snapshot, interface names learned by the collector, CEL classifiers, GeoIP, applications) → batching ClickHouse writer (schema migrated on start). Stop order: collector, then bus consumer (drained), then writer flush | `internal/collector`, `internal/bus`, `internal/enrich`, `internal/storage/clickhouse`, wired by `internal/wiring` and `cmd/current` |
| Ledger sync | the enricher / detector processes follow the connection stored in PostgreSQL (token read from OpenBao on each sync): sync on start, every interval, at once on a settings change or a sync requested from the API; result in `last_sync` | `internal/wiring` (`Inventory`), `internal/inventory` |
| Ledger integration | Current side of [integrations.md §2](../docs/integrations.md): `GET /api/integrations/inventory-db/status` (current 5-minute rates, 48-point sparkline, speed / utilisation, monthly p95 against the circuit commit, console link, last seen; one ClickHouse query per part for all ids) and `/prefix-addresses` (addresses seen in a prefix, `in_ipam` from the snapshot) for tokens with `integrations.inventory:read`; `POST /api/integrations/inventory-db/hook` (HMAC `x-inventory-signature`, secret in OpenBao, 202 + debounced early sync in every process via `inventory_sync_request`); "Create in Ledger" for unknown addresses with an optional editor token, link to Ledger's device form for unknown exporters (Settings → Ledger) | `internal/app` (`inventory_integration.go`), `internal/wiring` (`InventoryIntegration`), `internal/query` (`inventory_status.go`) |
| Detector | rules from PostgreSQL (`detector_rules`; the built-in set until saved), state and undelivered events in `detector_state`, events to the Beacon ingest URL with the token from OpenBao, exporter last-seen from the collector registry (same process), circuit commit rates from the Ledger snapshot, `/metrics` per-interface utilisation; `GET/PUT /api/detector/rules`, `GET /api/detector/rules/defaults`, `GET /api/detector/status`, Beacon test event | `internal/detector`, `internal/wiring` (`Detector`) |
| Beacon scopes and dependencies | Beacon API connection (address + service-account token in OpenBao, test = the signed-in user's scope); roles with `scope:umbrella` see only the flows of their Beacon CIs (scope fetched per login, cached 60 s, applied to every ClickHouse read by `query.ScopedConn`, fail closed with 503 `scope_unavailable` and a console banner); dependency discovery of steady CI ↔ CI traffic (7 days of raw flows, server = lower port, thresholds) posted daily or on demand as CMDB proposals, Dependencies page (`dependencies:view` / `dependencies:run`); Grafana "CI traffic" dashboard in [deploy/grafana](../deploy/grafana/README.md) | `internal/beacon`, `internal/query` (`scope.go`, `dependencies.go`), `internal/app` (`beacon_*.go`) |
| Reverse DNS | asynchronous PTR resolution in the enricher (bounded worker pool, positive / negative cache with TTLs, rate limit, configurable servers, scope all / private / public) for addresses without a Ledger host name → `SrcHostPTR` / `DstHostPTR`; never blocks the pipeline (first flows get an empty name); `GET/PUT /api/settings/rdns`, `flow_rdns_*` metrics | `internal/rdns`, `internal/enrich` (`rdns.go`), `internal/wiring` (`RDNS`) |
| Threat intelligence | public blocklists (FireHOL level1, Spamhaus DROP, abuse.ch Feodo; any URL list) downloaded at run time on an interval (never stored in the repository or the image) into an LPM trie → `SrcThreat` / `DstThreat`; special-purpose ranges and own prefixes never flagged; detector kind `threat_contact` → `sec.threat.contact` (RED) per internal host, built-in rule enabled with severity `error`; `GET/PUT /api/settings/threat`, `POST /api/settings/threat/refresh`, Settings → Threat intelligence page, `flow_threat_*` metrics | `internal/threat`, `internal/enrich` (`threat.go`), `internal/detector` (`threat.go`), `internal/wiring` (`Threat`) |
| Cloud flow logs | `POST /api/ingest/flowlogs/aws` (VPC Flow Logs v2 and custom formats, header line or `fields`, CloudWatch Logs JSON, Kinesis Data Firehose HTTP delivery with `X-Amz-Firehose-Access-Key`), `/azure` (NSG flow logs v1/v2, VNet flow logs v4), `/gcp` (Pub/Sub push, LogEntry JSON) → flow records on the bus (`FlowType` `aws-vpc`, `azure-vnet`, `gcp-vpc`; synthetic exporter addresses in `fd75:666c::/32` named after the ENI / VPC, NIC or VM); per-provider tokens in OpenBao; `GET/PUT /api/settings/flowlogs` | `internal/flowlogs`, `internal/wiring` (`FlowLogs`) |
| gNMI | interface names / descriptions / speeds over gNMI `Get` of OpenConfig `/interfaces/interface/state` (`ifindex`, `description`), subinterfaces, Ethernet port speed (`SPEED_*` identities → bits/s) and LAG speed, JSON_IETF with a JSON fallback, for exporters seen in flows and listed devices; per profile `Get` every refresh period or a `Subscribe` stream (TARGET_DEFINED, initial state then updates and deletes, falls back to `Get` when refused); credential profiles by prefix with username / password metadata, TLS on / off, skip-verify, certificate name, CA PEM and a client certificate / key for mutual TLS, all secrets in OpenBao; refresh interval and TTL cache; the enricher uses it after Ledger and the collector's option data and before SNMP; `GET/PUT /api/settings/gnmi`, `POST /api/settings/gnmi/test`, Settings → gNMI page, `flow_gnmi_*` metrics | `internal/gnmi`, `internal/wiring` (`GNMI`) |
| SNMP | fallback interface names / descriptions / speeds (SNMPv2c / v3, GETBULK of `ifName`, `ifDescr`, `ifAlias`, `ifHighSpeed`, `ifSpeed`) for exporters seen in flows and listed devices, credential profiles by prefix with community / USM passwords in OpenBao, refresh interval and TTL cache; the enricher uses it after Ledger, the collector's option data and gNMI; `GET/PUT /api/settings/snmp`, `POST /api/settings/snmp/test`, Settings → SNMP page, `flow_snmp_*` metrics | `internal/snmp`, `internal/enrich` (`snmp.go`), `internal/wiring` (`SNMP`) |
| BMP | RFC 7854 receiver on TCP 10179 (own BGP decoder: IPv4 / IPv6 unicast and labeled unicast, VPNv4 / VPNv6 and EVPN IP routes (types 2 and 5) with a table per route distinguisher, RD instance and VRF Loc-RIB peers, Adj-RIB-Out skipped, MP_REACH / MP_UNREACH, 4-byte AS and AS4_PATH, ADD-PATH, communities, large communities), per-peer Adj-RIB-In with post-policy preference in a compact LPM table with interned attributes, withdrawals, peer down / session close cleanup, memory metrics, sessions replicated between enricher processes over NATS JetStream (stream `FLOW_BMP`, snapshots, heartbeats); the enricher looks routes up in the VRF of the input interface and fills `DstASPath`, `DstCommunities`, `DstLargeCommunities`, the next hop when missing, and SrcAS / DstAS through the `routing` AS provider; `GET/PUT /api/settings/bmp`, `GET /api/bmp/lookup`, Settings → BMP page, `flow_bmp_*` metrics | `internal/bmp`, `internal/enrich` (`routing.go`), `internal/wiring` (`BMP`, `Routing`) |
| Status | `GET /api/status` components: `collector`, `bus`, `enricher`, `writer`, `inventory`, `detector`, `rdns`, `threat`, `gnmi`, `snmp`, `bmp` (those running in the process) | `internal/wiring` |
| Web console | React console: setup wizard, overview widgets, Visualize, flow search, exporters with sampling overrides (per exporter / per interface), detector rules (form with per-kind fields, client checks mirroring the server) and status, dependencies, Ledger, classifiers, Beacon (events and API connection), OpenBao, API tokens, Keystone (connection, synchronization, published roles), users (read-only), roles (custom role editor), threat intelligence, reverse DNS, cloud flow logs (write-only tokens, ingest URLs and AWS Firehose / Azure / GCP Pub/Sub setup snippets), gNMI, SNMP, BMP; the mock server (`VITE_MOCK=1`) answers every page; a banner when the Beacon scope cannot be loaded; screenshots with live demo data in [docs/screens](docs/screens) (`*-live.png`) | `web/` |

## Secrets

OpenBao is the only secret store (KV v2, mount `flow`, AppRole `flow`), as in Beacon:

- Everything entered in the wizard, the UI or the API — PostgreSQL, ClickHouse and NATS credentials, the Ledger
  token, the Beacon ingest token, the Keystone connection key — goes straight to OpenBao; PostgreSQL and `flow.json`
  keep only `openbao://<mount>/<path>#<key>` references.
- Local users' password hashes (PBKDF2-SHA256, 600 000 iterations) live at `users/<id>#password_hash`; the `users`
  table has only the reference.
- The session and CSRF HMAC keys live at `keys#session` / `keys#csrf`: PostgreSQL stores only HMAC(session key,
  cookie), and the CSRF token is derived from the cookie, so a database dump gives no usable token.
- `flow.json` holds the OpenBao address, the sign-in method and the paths of the AppRole `role_id` / `secret_id`
  files (Docker), or the token / AppRole values for a manual install (the file is 0600) — nothing else secret.
- Reads go through a 30 s cache, so a rotation in OpenBao needs no restart; tokens are renewed and AppRole signs in
  again when needed.
- Secrets are never returned by the API (only `*_set: true`), never logged and never written to the audit log.
  A test after the setup scans every PostgreSQL table and `flow.json` for the plaintext values.
- Settings → OpenBao: `GET /api/settings/openbao` (status with the token renewal state), `POST
  /api/settings/openbao/test` (the current or another server), and moving the secrets to another OpenBao
  (`/probe`, `/migrate`): every secret of the mount is copied, `openbao://` references in PostgreSQL and `flow.json`
  follow a new mount name, `flow.json` is rewritten and the running client switches in place — no restart for the
  `all` / `api` process; separate `enricher` / `detector` processes pick the new `flow.json` up on restart (the source
  keeps its copy until then).
- API tokens are stored as HMAC-SHA256 with the key `keys#tokens`; the plaintext is shown once.
- Docker: `.env` holds only bootstrap values for the containers themselves (PostgreSQL / ClickHouse / NATS server
  passwords, MaxMind key). `openbao-init` seeds them into OpenBao once; the wizard gets references only.

| OpenBao path (mount `flow`) | Key | What |
|---|---|---|
| `postgres` | `password` | PostgreSQL password |
| `clickhouse` | `password` | ClickHouse password |
| `nats` | `token` | NATS token |
| `inventory-db` | `token` | Ledger API token |
| `inventory-db-hook` | `secret` | Ledger change-notification hook secret |
| `inventory-db-write` | `token` | optional Ledger editor token ("Create in Ledger") |
| `umbrella` | `token` | Beacon ingest Bearer token |
| `flowlogs` | `aws`, `azure`, `gcp` | cloud flow log ingest tokens |
| `umbrella-api` | `token` | Beacon service-account token (visibility scopes, CMDB proposals) |
| `grafana` | `clickhouse_password` | read-only ClickHouse user `grafana` (seeded by the Docker stack; used by Grafana, not by Current) |
| `spa` | `connection_key` | the Keystone connection key `spa1.…` (when given in the setup wizard; `SPA_CONNECTION_KEY` wins) |
| `keys` | `session`, `csrf`, `tokens`, `state` | session / CSRF / API token / Keystone sign-in state HMAC keys |

## Run

Docker (recommended): see [deploy/current](../deploy/current/README.md).

```sh
cd deploy/current && cp .env.example .env && docker compose up -d
docker compose logs current | grep setup_code     # then open http://localhost:8080
```

From source: Go 1.26+, Node.js 22, PostgreSQL 17, ClickHouse 25.8, OpenBao (NATS optional).

```sh
cd app
make openbao-dev        # OpenBao in dev mode, KV v2 mount flow, token dev-root
make build && make run  # http://localhost:8080, data in backend/data
```

Development: `make dev-api` and `make dev-web` (Vite on :5173). Checks: `make test` (`go vet`, `go test`, web
typecheck and tests). Tests use PostgreSQL at `localhost:5432` (`postgres` / `postgres`, a fresh database per test,
`FLOW_TEST_POSTGRES=<dsn>` to change, `=off` to skip) and ClickHouse at `localhost:9000` (`FLOW_TEST_CLICKHOUSE`);
OpenBao is faked. `TestStepChecks` and `TestCompleteDockerStyle` (`internal/setup`) need ClickHouse and a PostgreSQL
that checks passwords (not `trust`), see [Development](../README.md#development). `FLOW_TEST_E2E=1 go test ./internal/wiring` runs the pipeline end to end in one process (demo
exporter → collector → in-process bus → enricher → writer → query). Image: `make image`. Whole stack: `make stack`,
with demo traffic `make stack-demo`.

### Demo on one machine without Docker

What was verified on a single host (ClickHouse, PostgreSQL, OpenBao dev server, optionally NATS and Ledger):

```sh
bao server -dev -dev-root-token-id=dev-root &              # OpenBao, then:
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao secrets enable -path=flow -version=2 kv
createdb flow                                               # PostgreSQL database for the configuration
cd app && make build
FLOW_DATA_DIR=/tmp/current FLOW_WEB_DIR=web/dist FLOW_NETFLOW_ADDR=127.0.0.1:2055 FLOW_SFLOW_ADDR=127.0.0.1:6343 \
  backend/current                                           # role all; the setup code is in the log
```

Open http://localhost:8080 and finish the wizard (OpenBao `http://127.0.0.1:8200`, token `dev-root`; PostgreSQL
database `flow`; ClickHouse `127.0.0.1:9000`; leave NATS empty for the in-process bus). Then send demo traffic:

```sh
backend/current demo -target 127.0.0.1:2055                # edge-01 / edge-02 / dc-sw-01 from 127.0.0.11-13
```

Within seconds Visualize, Exporters and the home widgets show three exporters (NetFlow v9, IPFIX, sFlow) with their
interface names. To get exporter names, sites, roles, boundaries and providers from Ledger, start a fresh
Ledger (`PORT=8091`), seed the demo network with
`node backend/internal/wiring/testdata/seed-demo.mjs http://localhost:8091` (prints the API token) and enter its
address and token under Settings → Ledger (or in the wizard).

Separate processes (NATS JetStream): run `current collector` with `FLOW_NATS_URL=nats://127.0.0.1:4222`, and
`current api`, `current enricher`, `current detector` sharing one `FLOW_DATA_DIR`, each with its own `FLOW_ADDR`; enter the NATS
address in the wizard of the api role. The enricher then has no interface names learned by the collector (they come
from Ledger) and the exporters list has no collector registry merge. A standalone collector applies the
sampling overrides of `FLOW_SAMPLING_OVERRIDES` and, once the shared `flow.json` names PostgreSQL, the stored ones
(re-read every minute); settings changed in the console reach the other processes within a minute.

### End to end with Beacon and Ledger

Verified on one host (OpenBao dev, NATS, ClickHouse, PostgreSQL; Ledger on `:8091` seeded with
`seed-demo.mjs`, Beacon on `:8081` with OpenBao mount `umbrella`, Current in role `all` on NATS JetStream with
`flow demo` and cloud flow logs posted to `/api/ingest/flowlogs/aws`), every link wired through the products' own
APIs and wizards:

| Link | How it was wired | Verified |
|---|---|---|
| Ledger → Current enrichment | wizard step Ledger (`xc-token`) | exporters carry name, site, role, `ExporterRef`, interface descriptions, speeds, boundaries and providers from the circuits |
| Ledger → Current change hook | Current service account + token (`integrations.inventory:read`) → Ledger integration `kind: flow`; its secret → Settings → Ledger | an interface description renamed in Ledger: signed hook delivered (202) 5 s later, early sync 5 s after that, the next flows carry the new description |
| Current → Ledger traffic | same integration | `/integrations/flow/status` (devices, interfaces, circuits) and `/prefix-addresses` (with `in_ipam`) answer through Ledger's proxy; device page "Traffic (Current, 24 h)" card |
| Current → Beacon events | Beacon quick connect `network-flow` → wizard step Beacon | a link-utilization rule with a lowered threshold opened an incident on the right CI (the exporter's `source_ref`) with the "Traffic" link; raising it resolved the incident (the resolved events stayed in the outbox across a Current restart) |
| Beacon → Current links | Beacon Settings → Alerting → Current address | `/go/incidents/{id}/flow` and `/go/cis/{id}/flow` redirect to `/go/incident`, which filters on the CI as a traffic end or as the exporter |
| Current → Beacon scopes | Beacon role (`integrations.flow:read`, `cmdb:propose`) + service account token → Settings → Beacon API | a Current user with `scope:umbrella`, matching a Beacon user with one selected service, sees only that CI's flows in Visualize (time series, bidirectional, sankey), flow search, widgets, exporters and filter completion |
| Current → Beacon dependencies | same token; Dependencies → run now (`min_flows` 10, `min_days` 1) | steady app → db traffic became a proposal on Beacon's CMDB map with the implied service dependency |

Screenshots: [visualize-e2e.png](docs/screens/visualize-e2e.png) (the Beacon "Traffic" link opened in Current),
[settings-flowlogs-e2e.png](docs/screens/settings-flowlogs-e2e.png), [settings-rdns-e2e.png](docs/screens/settings-rdns-e2e.png).

`flow -version` prints the version, `flow -healthcheck` probes `/healthz` (used by the image), `flow <role>` is
`FLOW_ROLE=<role>`, `flow demo -target host:2055` runs the demo exporter.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `FLOW_ADDR` | `:8080` | HTTP listen address (console, API, `/metrics`, `/healthz`) |
| `FLOW_DATA_DIR` | `data` | `flow.json` and `setup-token` |
| `FLOW_WEB_DIR` | `../web/dist` | built web console |
| `FLOW_STARTUP_WAIT` | `2m` | how long to wait for OpenBao and PostgreSQL on start |
| `FLOW_SETUP_TOKEN` | random | fixed setup code |
| `FLOW_SECURE_COOKIES` | `false` | `Secure` cookie flag (behind HTTPS) |
| `FLOW_TRUSTED_PROXIES` | — | addresses / CIDRs whose `X-Forwarded-For` (audit) and `X-Forwarded-Proto` / `-Host` (Keystone redirect address) are trusted |
| `FLOW_ROLE` | `all` | `all`, `collector`, `enricher`, `api`, `detector` |
| `FLOW_NETFLOW_ADDR` | `:2055` | UDP for NetFlow v5/v9 and IPFIX |
| `FLOW_SFLOW_ADDR` | `:6343` | UDP for sFlow |
| `FLOW_SAMPLING_OVERRIDES` | — | sampling overrides of the collector, `CIDR[@ifindex\|@ifname]=rate` separated by commas or semicolons (`192.0.2.0/24=1000, 192.0.2.1@17=4000`); win over the stored ones with the same exporter and interface |
| `FLOW_BMP_ADDR` | `:10179` | TCP for BMP (enricher process), listened to only while BMP is enabled in the settings |
| `FLOW_NATS_URL` | — | NATS JetStream URL: required by the `collector` role; for the other roles it overrides `nats.url` of `flow.json`. Empty everywhere = in-process bus (role `all` only; `enricher` fails without NATS) |
| `SPA_CONNECTION_KEY` | — | the Keystone connection key `spa1.…` ([Keystone protocol](https://github.com/sbrw-evc/keystone/blob/main/docs/protocol.md)); without it and `SPA_CONNECTION_KEY_FILE` the key is read from OpenBao (`spa#connection_key`) |
| `SPA_CONNECTION_KEY_FILE` | — | a file holding the connection key (Docker / Kubernetes secret) |
| `SPA_PUBLIC_URL` | — | the address of Current when it differs from the request address (redirect addresses) |
| `FLOW_SETUP_DEFAULTS_*` | — | wizard prefill, see `internal/setup/defaults.go`; secrets only as `openbao://` references |

Roles: `all` and `api` serve the wizard and the console; `enricher` and `detector` wait for `flow.json` (shared
data volume) and serve `/healthz` and `/metrics`; `collector` needs no configuration.

## Structure

```
app/
  backend/
    cmd/current/         entry point: roles, setup vs normal mode, pipeline start-up (pipeline.go)
    internal/
      access/            permission catalog, built-in roles
      app/               HTTP application: router, auth middleware, platform handlers, Deps interfaces
      auth/              session / CSRF / API token / state keys in OpenBao, sessions, API tokens
      config/            environment and flow.json
      oidcx/             OpenID Connect relying party: discovery, PKCE, ID token verification (JWKS)
      keystone/          Keystone client: connection key, sign-in, federation API; keystonetest is a fake Keystone
      httpx/             JSON, errors {error, message}, security headers, web console serving, client address
      secrets/           OpenBao KV v2 client (token / AppRole, renewal, 30 s cache), secretstest fake
      setup/             first-run wizard and connection checks
      store/             PostgreSQL schema (goose) and repositories, storetest helpers
      wiring/            adapters between the pipeline / traffic packages and internal/app: bus, collector,
                         enricher reloads, Ledger loop, detector, query / filter / classifier services
      schema/            column registry                    (other package)
      collector/ bus/ enrich/ inventory/ geoip/ classifier/ apps/ filter/ query/ storage/ demoexporter/ flow/ detector/
                         pipeline and traffic packages
  web/                   React console
  Dockerfile             node + go build → distroless, one image for every role
  Makefile
deploy/current/          Docker Compose: Current, PostgreSQL, ClickHouse, NATS, OpenBao (+ demo, geoip)
deploy/helm/current/     Helm chart: all-in-one or one Deployment per role, services for HTTP, UDP flows and BMP
```

## Not done yet

Nothing from the plan is pending.
