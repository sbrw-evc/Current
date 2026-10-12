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
| Traffic API | visualize, filter validation / completion, raw flow search, exporters, home widgets, unknown Inventory DB objects, classifier preview: thin handlers over interfaces (`internal/app/deps.go`); 501 until wired | provided by `internal/query`, `internal/filter`, `internal/inventory`, `internal/classifier` |
| Pipeline | collector (NetFlow v5/v9, IPFIX, sFlow) → bus (in-process or NATS JetStream) → enricher (Inventory DB, GeoIP, classifiers) → ClickHouse writer | provided by `internal/collector`, `internal/bus`, `internal/enrich`, `internal/storage/clickhouse` (wired in `cmd/flow`) |
| Web console | | provided by `web/` |

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
OpenBao is faked. Image: `make image`. Whole stack: `make stack`, with demo traffic `make stack-demo`; demo traffic
from this machine: `make demo DEMO_TARGET=127.0.0.1:2055`.

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
| `FLOW_NATS_URL` | — | NATS for the collector role (empty = in-process bus); other roles use `flow.json` |
| `FLOW_SETUP_DEFAULTS_*` | — | wizard prefill, see `internal/setup/defaults.go`; secrets only as `openbao://` references |

Roles: `all` and `api` serve the wizard and the console; `enricher` and `detector` wait for `flow.json` (shared
data volume) and serve `/healthz` and `/metrics`; `collector` needs no configuration.

## Structure

```
app/
  backend/
    cmd/flow/            entry point: roles, setup vs normal mode, TODO wiring points for the pipeline
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
      schema/            column registry                    (other package)
      collector/ bus/ enrich/ inventory/ geoip/ classifier/ apps/ filter/ query/ storage/ demoexporter/ flow/
                         pipeline and traffic packages       (other packages)
  web/                   React console                       (other package)
  Dockerfile             node + go build → distroless, one image for every role
  Makefile
deploy/flow/             Docker Compose: Flow, PostgreSQL, ClickHouse, NATS, OpenBao (+ demo, geoip)
```

## Not done yet

- Entra ID sign-in, moving secrets to another OpenBao, API tokens.
- Detector (stage 4) and the pipeline wiring in `cmd/flow` (marked `TODO(coordinator)`).
