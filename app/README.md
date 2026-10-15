# Umbrella Flow: application

NetFlow / IPFIX / sFlow analysis integrated with Umbrella Monitoring and Inventory DB. Backend in Go (one binary,
every pipeline role), web console in React + TypeScript, configuration in PostgreSQL, flows in ClickHouse, secrets
in OpenBao. Plan: [docs/plan.md](../docs/plan.md), REST contract: [docs/api.md](../docs/api.md).

Deployment is Docker-first: [deploy/flow](../deploy/flow/README.md) brings up the whole stack with one command.

## What works

| Part | What it does | Package |
|---|---|---|
| Setup wizard | opens on the first start (no `flow.json`): setup code (log + `FLOW_DATA_DIR/setup-token`, 5 wrong codes lock it for a minute), general settings, OpenBao, PostgreSQL (can attach to an existing Flow database), ClickHouse with retention, NATS, collector addresses, optional Inventory DB / Umbrella / GeoIP, first administrator with the password policy. Every step has a check (`POST /api/setup/test/{step}`); the final `POST /api/setup` re-checks everything, writes secrets to OpenBao, migrates PostgreSQL and ClickHouse, writes `flow.json` and switches to the console without a restart. In Docker the fields are prefilled from `FLOW_SETUP_DEFAULTS_*` | `internal/setup` |
| Sign-in | local users (PBKDF2-SHA256 hashes in OpenBao), LDAP / AD (service account bind, user bind, nested groups, group → role mapping, default role), Microsoft Entra ID (OpenID Connect code flow + PKCE, ID token verified against the tenant keys, groups from the token or Microsoft Graph, group → role mapping, users created on first sign-in with the default role; Settings → Entra ID); sessions in an HttpOnly cookie `flow_session` (12 h idle, 7 days max), `X-CSRF-Token` on state-changing requests, lockout after 5 failures (or as the password policy says) | `internal/auth`, `internal/directory`, `internal/entra`, `internal/app` |
| Umbrella Identity | passkeys (WebAuthn with user verification: Windows Hello face / fingerprint / PIN, Touch ID, Face ID, Android, FIDO2 keys; profile registration, administrator removal; Settings → Sign-in), Google Workspace, Sign in with Apple and any OpenID Connect provider (allowed domains, existing accounts only, role of new accounts), Umbrella single sign-in: connected with the key made by Umbrella Monitoring in three steps (key → roles → options), sign-in buttons for every method of the hub (`idp_hint`), synchronization of users, roles (Umbrella role / directory group → Flow role), disabled accounts, the password policy and passkeys every 5 minutes with ETags; the password policy of the family (length, classes, alphabets, common passwords, history, expiry, lockout); Settings → Users, Password policy, Profile ([docs/identity-federation.md](../docs/identity-federation.md)) | `internal/passkey`, `internal/oidcx`, `internal/umbrellaid`, `internal/app/identity_*.go` |
| API tokens | service accounts with a role and bearer tokens `flow_…` (HMAC-SHA256 with `keys#tokens`, plaintext shown once, expiry, last use, revoke; no CSRF); Settings → API tokens; audit of creation, revocation and use from a new address | `internal/auth`, `internal/store`, `internal/app` |
| Roles | permissions `<page>:<function>` (`GET /api/access/catalog`), built-in Administrator (everything) and Viewer (visualize, flows, exporters), custom roles; the last enabled administrator cannot be removed | `internal/access`, `internal/app` |
| Configuration | relational PostgreSQL schema (goose migrations embedded in the binary): users, roles, sessions, settings, saved views, classifier rules, Inventory DB connection, sampling overrides, LDAP group mapping, audit log | `internal/store` |
| Platform API | `/healthz`, `/metrics`, `/api/version`, auth, users, roles, LDAP, saved views, classifiers (with validation through the classifier package), Inventory DB connection / test / sync / schedule, sampling overrides, general settings and password policy, Umbrella connection with a test event, OpenBao status / test / move to another OpenBao, Entra ID, service accounts and API tokens, system status, audit log, `/api/schema` | `internal/app` |
| Traffic API | visualize (time series and sankey; `query.ValidationError` / filter errors → 400), filter validation and completion (columns, operators, values: built-in symbols plus the most frequent values of the last 24 h from ClickHouse, `flows_1h` for aggregated columns), raw flow search, exporters (ClickHouse aggregates merged with the collector registry in role `all`), home widgets, unknown Inventory DB objects, classifier validation / preview | `internal/wiring` over `internal/query`, `internal/filter`, `internal/inventory`, `internal/classifier` |
| Pipeline | collector (NetFlow v5/v9, IPFIX, sFlow; sampling overrides from PostgreSQL applied at run time) → bus (in-process in role `all` without NATS, NATS JetStream otherwise) → enricher (Inventory DB snapshot, interface names learned by the collector, CEL classifiers, GeoIP, applications) → batching ClickHouse writer (schema migrated on start). Stop order: collector, then bus consumer (drained), then writer flush | `internal/collector`, `internal/bus`, `internal/enrich`, `internal/storage/clickhouse`, wired by `internal/wiring` and `cmd/flow` |
| Inventory DB sync | the enricher / detector processes follow the connection stored in PostgreSQL (token read from OpenBao on each sync): sync on start, every interval, at once on a settings change or a sync requested from the API; result in `last_sync` | `internal/wiring` (`Inventory`), `internal/inventory` |
| Inventory DB integration | Flow side of [integrations.md §2](../docs/integrations.md): `GET /api/integrations/inventory-db/status` (current 5-minute rates, 48-point sparkline, speed / utilisation, monthly p95 against the circuit commit, console link, last seen; one ClickHouse query per part for all ids) and `/prefix-addresses` (addresses seen in a prefix, `in_ipam` from the snapshot) for tokens with `integrations.inventory:read`; `POST /api/integrations/inventory-db/hook` (HMAC `x-inventory-signature`, secret in OpenBao, 202 + debounced early sync in every process via `inventory_sync_request`); "Create in Inventory DB" for unknown addresses with an optional editor token, link to Inventory DB's device form for unknown exporters (Settings → Inventory DB) | `internal/app` (`inventory_integration.go`), `internal/wiring` (`InventoryIntegration`), `internal/query` (`inventory_status.go`) |
| Detector | rules from PostgreSQL (`detector_rules`; the built-in set until saved), state and undelivered events in `detector_state`, events to the Umbrella ingest URL with the token from OpenBao, exporter last-seen from the collector registry (same process), circuit commit rates from the Inventory DB snapshot, `/metrics` per-interface utilisation; `GET/PUT /api/detector/rules`, `GET /api/detector/rules/defaults`, `GET /api/detector/status`, Umbrella test event | `internal/detector`, `internal/wiring` (`Detector`) |
| Umbrella scopes and dependencies | Umbrella API connection (address + service-account token in OpenBao, test = the signed-in user's scope); roles with `scope:umbrella` see only the flows of their Umbrella CIs (scope fetched per login, cached 60 s, applied to every ClickHouse read by `query.ScopedConn`, fail closed with 503 `scope_unavailable` and a console banner); dependency discovery of steady CI ↔ CI traffic (7 days of raw flows, server = lower port, thresholds) posted daily or on demand as CMDB proposals, Dependencies page (`dependencies:view` / `dependencies:run`); Grafana "CI traffic" dashboard in [deploy/grafana](../deploy/grafana/README.md) | `internal/umbrella`, `internal/query` (`scope.go`, `dependencies.go`), `internal/app` (`umbrella_*.go`) |
| Reverse DNS | asynchronous PTR resolution in the enricher (bounded worker pool, positive / negative cache with TTLs, rate limit, configurable servers, scope all / private / public) for addresses without an Inventory DB host name → `SrcHostPTR` / `DstHostPTR`; never blocks the pipeline (first flows get an empty name); `GET/PUT /api/settings/rdns`, `flow_rdns_*` metrics | `internal/rdns`, `internal/enrich` (`rdns.go`), `internal/wiring` (`RDNS`) |
| Threat intelligence | public blocklists (FireHOL level1, Spamhaus DROP, abuse.ch Feodo; any URL list) downloaded at run time on an interval (never stored in the repository or the image) into an LPM trie → `SrcThreat` / `DstThreat`; special-purpose ranges and own prefixes never flagged; detector kind `threat_contact` → `sec.threat.contact` (RED) per internal host, built-in rule enabled with severity `error`; `GET/PUT /api/settings/threat`, `POST /api/settings/threat/refresh`, Settings → Threat intelligence page, `flow_threat_*` metrics | `internal/threat`, `internal/enrich` (`threat.go`), `internal/detector` (`threat.go`), `internal/wiring` (`Threat`) |
| Cloud flow logs | `POST /api/ingest/flowlogs/aws` (VPC Flow Logs v2 and custom formats, header line or `fields`, CloudWatch Logs JSON, Kinesis Data Firehose HTTP delivery with `X-Amz-Firehose-Access-Key`), `/azure` (NSG flow logs v1/v2, VNet flow logs v4), `/gcp` (Pub/Sub push, LogEntry JSON) → flow records on the bus (`FlowType` `aws-vpc`, `azure-vnet`, `gcp-vpc`; synthetic exporter addresses in `fd75:666c::/32` named after the ENI / VPC, NIC or VM); per-provider tokens in OpenBao; `GET/PUT /api/settings/flowlogs` | `internal/flowlogs`, `internal/wiring` (`FlowLogs`) |
| gNMI | interface names / descriptions / speeds over gNMI `Get` of OpenConfig `/interfaces/interface/state` (`ifindex`, `description`), subinterfaces, Ethernet port speed (`SPEED_*` identities → bits/s) and LAG speed, JSON_IETF with a JSON fallback, for exporters seen in flows and listed devices; per profile `Get` every refresh period or a `Subscribe` stream (TARGET_DEFINED, initial state then updates and deletes, falls back to `Get` when refused); credential profiles by prefix with username / password metadata, TLS on / off, skip-verify, certificate name, CA PEM and a client certificate / key for mutual TLS, all secrets in OpenBao; refresh interval and TTL cache; the enricher uses it after Inventory DB and the collector's option data and before SNMP; `GET/PUT /api/settings/gnmi`, `POST /api/settings/gnmi/test`, Settings → gNMI page, `flow_gnmi_*` metrics | `internal/gnmi`, `internal/wiring` (`GNMI`) |
| SNMP | fallback interface names / descriptions / speeds (SNMPv2c / v3, GETBULK of `ifName`, `ifDescr`, `ifAlias`, `ifHighSpeed`, `ifSpeed`) for exporters seen in flows and listed devices, credential profiles by prefix with community / USM passwords in OpenBao, refresh interval and TTL cache; the enricher uses it after Inventory DB, the collector's option data and gNMI; `GET/PUT /api/settings/snmp`, `POST /api/settings/snmp/test`, Settings → SNMP page, `flow_snmp_*` metrics | `internal/snmp`, `internal/enrich` (`snmp.go`), `internal/wiring` (`SNMP`) |
| BMP | RFC 7854 receiver on TCP 10179 (own BGP decoder: IPv4 / IPv6 unicast and labeled unicast, VPNv4 / VPNv6 and EVPN IP routes (types 2 and 5) with a table per route distinguisher, RD instance and VRF Loc-RIB peers, Adj-RIB-Out skipped, MP_REACH / MP_UNREACH, 4-byte AS and AS4_PATH, ADD-PATH, communities, large communities), per-peer Adj-RIB-In with post-policy preference in a compact LPM table with interned attributes, withdrawals, peer down / session close cleanup, memory metrics, sessions replicated between enricher processes over NATS JetStream (stream `FLOW_BMP`, snapshots, heartbeats); the enricher looks routes up in the VRF of the input interface and fills `DstASPath`, `DstCommunities`, `DstLargeCommunities`, the next hop when missing, and SrcAS / DstAS through the `routing` AS provider; `GET/PUT /api/settings/bmp`, `GET /api/bmp/lookup`, Settings → BMP page, `flow_bmp_*` metrics | `internal/bmp`, `internal/enrich` (`routing.go`), `internal/wiring` (`BMP`, `Routing`) |
| Status | `GET /api/status` components: `collector`, `bus`, `enricher`, `writer`, `inventory`, `detector`, `rdns`, `threat`, `gnmi`, `snmp`, `bmp` (those running in the process) | `internal/wiring` |
| Web console | React console: setup wizard, overview widgets, Visualize, flow search, exporters with sampling overrides (per exporter / per interface), detector rules (form with per-kind fields, client checks mirroring the server) and status, dependencies, Inventory DB, classifiers, Umbrella (events and API connection), OpenBao, API tokens, Entra ID, threat intelligence, reverse DNS, cloud flow logs (write-only tokens, ingest URLs and AWS Firehose / Azure / GCP Pub/Sub setup snippets), gNMI, SNMP, BMP; the mock server (`VITE_MOCK=1`) answers every page; a banner when the Umbrella scope cannot be loaded; screenshots with live demo data in [docs/screens](docs/screens) (`*-live.png`) | `web/` |

## Secrets

OpenBao is the only secret store (KV v2, mount `flow`, AppRole `flow`), as in Umbrella Monitoring:

- Everything entered in the wizard, the UI or the API — PostgreSQL, ClickHouse and NATS credentials, the Inventory DB
  token, the Umbrella ingest token, the LDAP bind password — goes straight to OpenBao; PostgreSQL and `flow.json`
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
| `inventory-db` | `token` | Inventory DB API token |
| `inventory-db-hook` | `secret` | Inventory DB change-notification hook secret |
| `inventory-db-write` | `token` | optional Inventory DB editor token ("Create in Inventory DB") |
| `umbrella` | `token` | Umbrella ingest Bearer token |
| `flowlogs` | `aws`, `azure`, `gcp` | cloud flow log ingest tokens |
| `umbrella-api` | `token` | Umbrella service-account token (visibility scopes, CMDB proposals) |
| `grafana` | `clickhouse_password` | read-only ClickHouse user `grafana` (seeded by the Docker stack; used by Grafana, not by Flow) |
| `ldap` | `bind_password` | LDAP / AD service account |
| `users/<id>` | `password_hash` | local user password hash |
| `entra` | `client_secret` | Microsoft Entra ID application client secret |
| `identity/umbrella`, `identity/umbrella/token` | `client_secret`, `token` | the Umbrella Identity client secret and synchronization token (from the connection key) |
| `identity/providers/<kind>/client-secret`, `…/private-key` | `client_secret`, `private_key` | Google / OpenID Connect client secrets, the Sign in with Apple key |
| `users/<id>/history` | `hashes` | hashes of the previous passwords of a local user (password history) |
| `keys` | `session`, `csrf`, `tokens` | session / CSRF / API token HMAC keys |

## Run

Docker (recommended): see [deploy/flow](../deploy/flow/README.md).

```sh
cd deploy/flow && cp .env.example .env && docker compose up -d
docker compose logs flow | grep setup_code     # then open http://localhost:8080
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
OpenBao is faked. `FLOW_TEST_E2E=1 go test ./internal/wiring` runs the pipeline end to end in one process (demo
exporter → collector → in-process bus → enricher → writer → query). Image: `make image`. Whole stack: `make stack`,
with demo traffic `make stack-demo`.

### Demo on one machine without Docker

What was verified on a single host (ClickHouse, PostgreSQL, OpenBao dev server, optionally NATS and Inventory DB):

```sh
bao server -dev -dev-root-token-id=dev-root &              # OpenBao, then:
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root bao secrets enable -path=flow -version=2 kv
createdb flow                                               # PostgreSQL database for the configuration
cd app && make build
FLOW_DATA_DIR=/tmp/flow FLOW_WEB_DIR=web/dist FLOW_NETFLOW_ADDR=127.0.0.1:2055 FLOW_SFLOW_ADDR=127.0.0.1:6343 \
  backend/flow                                              # role all; the setup code is in the log
```

Open http://localhost:8080 and finish the wizard (OpenBao `http://127.0.0.1:8200`, token `dev-root`; PostgreSQL
database `flow`; ClickHouse `127.0.0.1:9000`; leave NATS empty for the in-process bus). Then send demo traffic:

```sh
backend/flow demo -target 127.0.0.1:2055                   # edge-01 / edge-02 / dc-sw-01 from 127.0.0.11-13
```

Within seconds Visualize, Exporters and the home widgets show three exporters (NetFlow v9, IPFIX, sFlow) with their
interface names. To get exporter names, sites, roles, boundaries and providers from Inventory DB, start a fresh
Inventory DB (`PORT=8091`), seed the demo network with
`node backend/internal/wiring/testdata/seed-demo.mjs http://localhost:8091` (prints the API token) and enter its
address and token under Settings → Inventory DB (or in the wizard).

Separate processes (NATS JetStream): run `flow collector` with `FLOW_NATS_URL=nats://127.0.0.1:4222`, and
`flow api`, `flow enricher`, `flow detector` sharing one `FLOW_DATA_DIR`, each with its own `FLOW_ADDR`; enter the NATS
address in the wizard of the api role. The enricher then has no interface names learned by the collector (they come
from Inventory DB) and the exporters list has no collector registry merge. A standalone collector applies the
sampling overrides of `FLOW_SAMPLING_OVERRIDES` and, once the shared `flow.json` names PostgreSQL, the stored ones
(re-read every minute); settings changed in the console reach the other processes within a minute.

### End to end with Umbrella Monitoring and Inventory DB

Verified on one host (OpenBao dev, NATS, ClickHouse, PostgreSQL; Inventory DB on `:8091` seeded with
`seed-demo.mjs`, Umbrella on `:8081` with OpenBao mount `umbrella`, Flow in role `all` on NATS JetStream with
`flow demo` and cloud flow logs posted to `/api/ingest/flowlogs/aws`), every link wired through the products' own
APIs and wizards:

| Link | How it was wired | Verified |
|---|---|---|
| Inventory DB → Flow enrichment | wizard step Inventory DB (`xc-token`) | exporters carry name, site, role, `ExporterRef`, interface descriptions, speeds, boundaries and providers from the circuits |
| Inventory DB → Flow change hook | Flow service account + token (`integrations.inventory:read`) → Inventory DB integration `kind: flow`; its secret → Settings → Inventory DB | an interface description renamed in Inventory DB: signed hook delivered (202) 5 s later, early sync 5 s after that, the next flows carry the new description |
| Flow → Inventory DB traffic | same integration | `/integrations/flow/status` (devices, interfaces, circuits) and `/prefix-addresses` (with `in_ipam`) answer through Inventory DB's proxy; device page "Traffic (Flow, 24 h)" card |
| Flow → Umbrella events | Umbrella quick connect `network-flow` → wizard step Umbrella | a link-utilization rule with a lowered threshold opened an incident on the right CI (the exporter's `source_ref`) with the "Traffic" link; raising it resolved the incident (the resolved events stayed in the outbox across a Flow restart) |
| Umbrella → Flow links | Umbrella Settings → Alerting → Umbrella Flow address | `/go/incidents/{id}/flow` and `/go/cis/{id}/flow` redirect to `/go/incident`, which filters on the CI as a traffic end or as the exporter |
| Flow → Umbrella scopes | Umbrella role (`integrations.flow:read`, `cmdb:propose`) + service account token → Settings → Umbrella API | a Flow user with `scope:umbrella`, matching an Umbrella user with one selected service, sees only that CI's flows in Visualize (time series, bidirectional, sankey), flow search, widgets, exporters and filter completion |
| Flow → Umbrella dependencies | same token; Dependencies → run now (`min_flows` 10, `min_days` 1) | steady app → db traffic became a proposal on Umbrella's CMDB map with the implied service dependency |

Screenshots: [visualize-e2e.png](docs/screens/visualize-e2e.png) (the Umbrella "Traffic" link opened in Flow),
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
| `FLOW_TRUSTED_PROXIES` | — | addresses / CIDRs whose `X-Forwarded-For` is trusted (sign-in lockout, audit) |
| `FLOW_ROLE` | `all` | `all`, `collector`, `enricher`, `api`, `detector` |
| `FLOW_NETFLOW_ADDR` | `:2055` | UDP for NetFlow v5/v9 and IPFIX |
| `FLOW_SFLOW_ADDR` | `:6343` | UDP for sFlow |
| `FLOW_SAMPLING_OVERRIDES` | — | sampling overrides of the collector, `CIDR[@ifindex\|@ifname]=rate` separated by commas or semicolons (`192.0.2.0/24=1000, 192.0.2.1@17=4000`); win over the stored ones with the same exporter and interface |
| `FLOW_BMP_ADDR` | `:10179` | TCP for BMP (enricher process), listened to only while BMP is enabled in the settings |
| `FLOW_NATS_URL` | — | NATS JetStream URL: required by the `collector` role; for the other roles it overrides `nats.url` of `flow.json`. Empty everywhere = in-process bus (role `all` only; `enricher` fails without NATS) |
| `FLOW_SETUP_DEFAULTS_*` | — | wizard prefill, see `internal/setup/defaults.go`; secrets only as `openbao://` references |

Roles: `all` and `api` serve the wizard and the console; `enricher` and `detector` wait for `flow.json` (shared
data volume) and serve `/healthz` and `/metrics`; `collector` needs no configuration.

## Structure

```
app/
  backend/
    cmd/flow/            entry point: roles, setup vs normal mode, pipeline start-up (pipeline.go)
    internal/
      access/            permission catalog, built-in roles
      app/               HTTP application: router, auth middleware, platform handlers, Deps interfaces
      auth/              PBKDF2 passwords in OpenBao, session / CSRF keys, sessions, lockout, password policy
      config/            environment and flow.json
      directory/         LDAP / AD sign-in and groups
      entra/             Microsoft Entra ID sign-in (OIDC + PKCE, Graph groups), entratest fake provider
      oidcx/             Google, Apple and OpenID Connect sign-in; JWT verification (RS256, ES256)
      passkey/           passkey (WebAuthn) ceremonies; passkeytest is a software authenticator
      umbrellaid/        Umbrella Identity member client (connection key, SSO, federation API); hubtest fake hub
      httpx/             JSON, errors {error, message}, security headers, SPA serving, client address
      secrets/           OpenBao KV v2 client (token / AppRole, renewal, 30 s cache), secretstest fake
      setup/             first-run wizard and connection checks
      store/             PostgreSQL schema (goose) and repositories, storetest helpers
      wiring/            adapters between the pipeline / traffic packages and internal/app: bus, collector,
                         enricher reloads, Inventory DB loop, detector, query / filter / classifier services
      schema/            column registry                    (other package)
      collector/ bus/ enrich/ inventory/ geoip/ classifier/ apps/ filter/ query/ storage/ demoexporter/ flow/ detector/
                         pipeline and traffic packages
  web/                   React console
  Dockerfile             node + go build → distroless, one image for every role
  Makefile
deploy/flow/             Docker Compose: Flow, PostgreSQL, ClickHouse, NATS, OpenBao (+ demo, geoip)
deploy/helm/umbrella-flow/  Helm chart: all-in-one or one Deployment per role, services for HTTP, UDP flows and BMP
```

## Not done yet

Nothing from the plan is pending.
