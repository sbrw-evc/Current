# Umbrella Flow: application

NetFlow / IPFIX / sFlow analysis integrated with Umbrella Monitoring and Inventory DB. Backend in Go (one binary,
every pipeline role), web console in React + TypeScript, configuration in PostgreSQL, flows in ClickHouse, secrets
in OpenBao. Plan: [docs/plan.md](../docs/plan.md), REST contract: [docs/api.md](../docs/api.md).

Deployment is Docker-first: [deploy/flow](../deploy/flow/README.md) brings up the whole stack with one command.

## What works

| Part | What it does | Package |
|---|---|---|
| Setup wizard | opens on the first start (no `flow.json`): setup code (log + `FLOW_DATA_DIR/setup-token`, 5 wrong codes lock it for a minute), general settings, OpenBao, PostgreSQL (can attach to an existing Flow database), ClickHouse with retention, NATS, collector addresses, optional Inventory DB / Umbrella / GeoIP, first administrator with the password policy. Every step has a check (`POST /api/setup/test/{step}`); the final `POST /api/setup` re-checks everything, writes secrets to OpenBao, migrates PostgreSQL and ClickHouse, writes `flow.json` and switches to the console without a restart. In Docker the fields are prefilled from `FLOW_SETUP_DEFAULTS_*` | `internal/setup` |
| Sign-in | local users (PBKDF2-SHA256 hashes in OpenBao), LDAP / AD (service account bind, user bind, nested groups, group → role mapping, default role); sessions in an HttpOnly cookie `flow_session` (12 h idle, 7 days max), `X-CSRF-Token` on state-changing requests, lockout after 5 failures | `internal/auth`, `internal/directory`, `internal/app` |
| Roles | permissions `<page>:<function>` (`GET /api/access/catalog`), built-in Administrator (everything) and Viewer (visualize, flows, exporters), custom roles; the last enabled administrator cannot be removed | `internal/access`, `internal/app` |
| Configuration | relational PostgreSQL schema (goose migrations embedded in the binary): users, roles, sessions, settings, saved views, classifier rules, Inventory DB connection, sampling overrides, LDAP group mapping, audit log | `internal/store` |
| Platform API | `/healthz`, `/metrics`, `/api/version`, auth, users, roles, LDAP, saved views, classifiers (with validation through the classifier package), Inventory DB connection / test / sync / schedule, sampling overrides, general settings and password policy, Umbrella connection with a test event, OpenBao status / test, system status, audit log, `/api/schema` | `internal/app` |
| Traffic API | visualize (time series and sankey; `query.ValidationError` / filter errors → 400), filter validation and completion (columns, operators, values: built-in symbols plus the most frequent values of the last 24 h from ClickHouse, `flows_1h` for aggregated columns), raw flow search, exporters (ClickHouse aggregates merged with the collector registry in role `all`), home widgets, unknown Inventory DB objects, classifier validation / preview | `internal/wiring` over `internal/query`, `internal/filter`, `internal/inventory`, `internal/classifier` |
| Pipeline | collector (NetFlow v5/v9, IPFIX, sFlow; sampling overrides from PostgreSQL applied at run time) → bus (in-process in role `all` without NATS, NATS JetStream otherwise) → enricher (Inventory DB snapshot, interface names learned by the collector, CEL classifiers, GeoIP, applications) → batching ClickHouse writer (schema migrated on start). Stop order: collector, then bus consumer (drained), then writer flush | `internal/collector`, `internal/bus`, `internal/enrich`, `internal/storage/clickhouse`, wired by `internal/wiring` and `cmd/flow` |
| Inventory DB sync | the enricher / detector processes follow the connection stored in PostgreSQL (token read from OpenBao on each sync): sync on start, every interval, at once on a settings change or a sync requested from the API; result in `last_sync` | `internal/wiring` (`Inventory`), `internal/inventory` |
| Detector | rules from PostgreSQL (`detector_rules`; the built-in set until saved), state and undelivered events in `detector_state`, events to the Umbrella ingest URL with the token from OpenBao, exporter last-seen from the collector registry (same process), circuit commit rates from the Inventory DB snapshot, `/metrics` per-interface utilisation; `GET/PUT /api/detector/rules`, `GET /api/detector/status`, Umbrella test event | `internal/detector`, `internal/wiring` (`Detector`) |
| Status | `GET /api/status` components: `collector`, `bus`, `enricher`, `writer`, `inventory`, `detector` (those running in the process) | `internal/wiring` |
| Web console | React console: setup wizard, overview widgets, Visualize, flow search, exporters, Inventory DB, classifiers, OpenBao; screenshots with live demo data in [docs/screens](docs/screens) (`*-live.png`) | `web/` |

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
- Settings → OpenBao: `GET /api/settings/openbao` (status), `POST /api/settings/openbao/test` (the current or
  another server). Moving secrets to another OpenBao is not implemented yet.
- Docker: `.env` holds only bootstrap values for the containers themselves (PostgreSQL / ClickHouse / NATS server
  passwords, MaxMind key). `openbao-init` seeds them into OpenBao once; the wizard gets references only.

| OpenBao path (mount `flow`) | Key | What |
|---|---|---|
| `postgres` | `password` | PostgreSQL password |
| `clickhouse` | `password` | ClickHouse password |
| `nats` | `token` | NATS token |
| `inventory-db` | `token` | Inventory DB API token |
| `umbrella` | `token` | Umbrella ingest Bearer token |
| `ldap` | `bind_password` | LDAP / AD service account |
| `users/<id>` | `password_hash` | local user password hash |
| `keys` | `session`, `csrf` | session / CSRF HMAC keys |

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
from Inventory DB), the exporters list has no collector registry merge, and sampling overrides are not applied by a
standalone collector (it has no configuration database); settings changed in the console reach the other processes
within a minute.

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
```

## Not done yet

- Entra ID sign-in, moving secrets to another OpenBao, API tokens.
- Detector pages in the web console (the API is there: `/api/detector/*`).
- Per-interface sampling overrides (`if_index` ≠ 0) are stored but not applied: the collector overrides per exporter
  prefix only. A standalone `collector` role applies no overrides.
- AS names in labels come only from GeoIP lookups made by the enricher of the same process (role `all`).
- Inventory DB webhooks (changes arrive with the periodic sync).
