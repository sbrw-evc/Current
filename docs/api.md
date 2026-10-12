# Umbrella Flow: REST API (contract between the backend and the web UI)

All paths are under `/api`. Responses are JSON; errors are `{"error": "<code>", "message": "<text>"}` with an HTTP
4xx/5xx status. The session is the HttpOnly cookie `flow_session`; mutating requests carry `X-CSRF-Token` (the `csrf`
value from `/api/auth/login` and `/api/auth/me`), as in Umbrella. Times are RFC 3339 UTC.

## Service

| Method | Path | Response |
|---|---|---|
| GET | `/healthz` | `200 ok` |
| GET | `/metrics` | Prometheus |
| GET | `/api/version` | `{version, commit, built_at}` |

## Sign-in

| Method | Path | Body / response |
|---|---|---|
| POST | `/api/auth/login` | `{username, password}` → `{user, csrf}` |
| POST | `/api/auth/logout` | — |
| GET | `/api/auth/me` | `{user: {id, username, name, role, permissions: ["visualize:view", …]}, csrf}` or 401 |

## First-run setup wizard

Opens on first start, while `FLOW_DATA_DIR` has no `flow.json`. The setup code is written to the server log and to
`FLOW_DATA_DIR/setup-token` (or taken from `FLOW_SETUP_TOKEN`); once setup completes the file is deleted, the wizard
never opens again and every `/api/setup*` answers 404. In the Docker stack the fields are prefilled from the
container's environment (`FLOW_SETUP_DEFAULTS_*`: PostgreSQL, ClickHouse, NATS and OpenBao addresses and the AppRole
files), so after `docker compose up -d` only the setup code and the administrator password have to be entered.

| Method | Path | Body / response |
|---|---|---|
| GET | `/api/setup` | `{required: bool, defaults: {language, theme, timezone, public_url, openbao: {...}, postgres: {...}, clickhouse: {...}, nats: {...}, collector: {...}}}` — passwords and secrets are never returned in `defaults`, only a `*_set` flag |
| POST | `/api/setup/check-code` | `{setup_code}` → `{ok}` (401 `setup_code_invalid`) |
| POST | `/api/setup/test/{step}` | `step` = `openbao` \| `postgres` \| `clickhouse` \| `nats` \| `inventory` \| `umbrella` \| `geoip`; body is the step's fields + `setup_code` → `{ok, error?, details?}` (`details`: server version, whether Flow state already exists in the database, Inventory DB device count, etc.) |
| POST | `/api/setup` | everything (below) → `{ok}`; the server re-runs every check, writes secrets to OpenBao, creates the PostgreSQL and ClickHouse schemas, saves `flow.json`, creates the administrator and switches to normal mode without a restart |

Steps (screens) and the fields of `POST /api/setup`:

1. **Setup code** — `setup_code`.
2. **General** — `language` (`ru`/`en`), `theme` (`light`/`dark`/`system`), `timezone`, `public_url` (Flow's address for
   links from Umbrella and Inventory DB; prefilled with the browser's address).
3. **OpenBao** — `openbao: {addr, mount (flow), auth: "token"|"approle", token? | role_id?, secret_id?}`.
4. **PostgreSQL** — `postgres: {host, port, database, username, password, sslmode}`; the password goes to OpenBao. If the
   database already holds Flow state, the wizard offers to attach to it (the Administrator step can then be skipped).
5. **ClickHouse** — `clickhouse: {addr, database (flow), username, password, secure}` + retention
   `retention: {raw_days 15, d1m 30, d5m 90, d1h 730}`.
6. **Bus** — `nats: {url}` (empty = in-process queue).
7. **Flow collection** — `collector: {netflow_addr ":2055", sflow_addr ":6343", default_sampling_rate 1}`; shows which
   addresses to configure on the routers.
8. **Inventory DB (optional)** — `inventory: {enabled, url, token, interval "15m"}` with a check showing the device count.
9. **Umbrella (optional)** — `umbrella: {enabled, ingest_url, token}`: the ingest URL and token from Umbrella's
   "Connect source → Umbrella Flow" dialog; the check sends a test event.
10. **GeoIP (optional)** — `geoip: {databases: ["/geoip/GeoLite2-City.mmdb", …]}`; the check opens the files.
11. **Administrator** — `admin: {username, name, email, password}` with the password policy (collapsed, 12+ characters
    by default).
12. **Review** — summary of every step with its check result, "Finish" button.

Optional steps can be skipped and configured later under Settings.

## Column schema

`GET /api/schema` → `{columns: [{name, kind, dimension, rollup, reverse, metric}]}` — from `internal/schema`.

## Visualize

`POST /api/visualize` (permission `visualize:view`)

```json
{
  "start": "2026-10-12T09:00:00Z",
  "end": "2026-10-12T10:00:00Z",
  "points": 200,
  "dimensions": ["SrcAS", "ExporterName"],
  "limit": 10,
  "filter": "InIfBoundary = 'external' AND Proto = 6",
  "units": "l3bps",
  "bidirectional": false,
  "graph": "stacked"
}
```

- `units`: `l3bps` (L3 bits/s), `l2bps` (+ 18 bytes of Ethernet header per packet), `pps`, `inl2%` / `outl2%`
  (percent of the input / output interface speed).
- `graph`: `stacked`, `lines`, `grid` — time series; `sankey` — no time axis.
- `limit`: 1–50; remaining values are folded into the row `["Other", …]`.
- Empty `dimensions` — a single "Total" row.

Time-series response:

```json
{
  "t": ["2026-10-12T09:00:00Z", "…"],
  "rows": [["AS65000 Example", "edge-01"], ["Other", "Other"]],
  "points": [[123.0, 456.0], [1.0, 2.0]],
  "axis": [1, 1],
  "average": [289.5, 1.5],
  "min": [123.0, 1.0],
  "max": [456.0, 2.0],
  "p95": [440.0, 1.9],
  "resolution": "1m",
  "sql": "SELECT …"
}
```

`axis`: 1 — direct direction, 2 — reverse (only with `bidirectional`; axis-2 rows have positive values and the web UI
draws them below zero). `resolution`: the table the result was computed from (`raw`, `1m`, `5m`, `1h`). `sql` is for
debugging (shown in the UI behind a button).

`sankey` response:

```json
{
  "rows": [["AS65000", "edge-01"]],
  "xps": [123456.0],
  "nodes": ["SrcAS: AS65000", "ExporterName: edge-01"],
  "links": [{"source": "SrcAS: AS65000", "target": "ExporterName: edge-01", "xps": 123456.0}]
}
```

## Filter

| Method | Path | Body / response |
|---|---|---|
| POST | `/api/filter/validate` | `{filter}` → `{valid: bool, errors: [{line, column, offset, message}], parsed: "<normalized text>"}` |
| POST | `/api/filter/complete` | `{what: "column"\|"operator"\|"value", column?, prefix}` → `{completions: [{label, detail, quoted}]}` |

Filter language: `Column op value`, `AND`, `OR`, `NOT`, parentheses; strings in `'…'` or `"…"`; string operators `=`,
`!=`, `IN (…)`, `NOTIN (…)`, `LIKE`, `UNLIKE`, `ILIKE`, `IUNLIKE`; IP operators `=`, `!=`, `<<` (in prefix,
`SrcAddr << 10.0.0.0/8`), `IN`; numeric operators `=`, `!=`, `<`, `<=`, `>`, `>=`, `IN`; special values
`SrcAS = AS65000`, `Proto = tcp`. Comments `-- …` and `/* … */`.

## Saved views

| Method | Path | |
|---|---|---|
| GET | `/api/saved-views` | `{results: [{id, name, owner, shared, request}]}` |
| POST | `/api/saved-views` | `{name, shared, request}` |
| DELETE | `/api/saved-views/{id}` | |

## Exporters

`GET /api/exporters` → `{results: [{address, name, ref, site, role, last_seen, flows_per_second, sampling_rates: [..], interfaces: [{index, name, description, speed, boundary, provider, in_bps, out_bps}]}]}`

## Home (widgets)

`GET /api/widgets/summary` → `{flows_per_second, exporters, bps_in_external, bps_out_external}`  
`GET /api/widgets/top/{what}` (`src-as`, `dst-as`, `src-country`, `dst-country`, `app`, `exporter`, `src-port`, `dst-port`) → `{top: [{name, percent}]}`  
`GET /api/widgets/graph?points=200` → `{t: [], gbps: []}` — external traffic over 24 h  
`GET /api/widgets/last-flow` → the latest flow as an object `{Column: value}`

## Raw flows

`POST /api/flows/search` `{start, end, filter, limit (≤1000), order: "time"|"bytes"}` → `{columns: [..], rows: [[..]]}`

## Inventory DB

| Method | Path | |
|---|---|---|
| GET | `/api/inventory-db` | `{enabled, url, token_set, interval, last_sync: {at, ok, error, devices, interfaces, prefixes, circuits}}` |
| PUT | `/api/inventory-db` | `{enabled, url, token?, interval}` — the token goes to OpenBao |
| POST | `/api/inventory-db/test` | `{ok, error?}` |
| POST | `/api/inventory-db/sync` | `{ok, stats}` |
| GET | `/api/inventory-db/unknown` | `{exporters: [{address, last_seen}], addresses: [{address, bytes}]}` |

## Classifiers

`GET|PUT /api/classifiers` → `{exporter: [CEL…], interface: [CEL…]}`; `POST /api/classifiers/preview` `{kind, rules, sample}` → result.
