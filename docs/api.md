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
| POST | `/api/setup/test/{step}` | `step` = `openbao` \| `postgres` \| `clickhouse` \| `nats` \| `inventory` \| `umbrella` \| `geoip`; body is the step's fields, flat, + `setup_code` → `{ok, error?, details?}` (`details`: server version, `has_state` for PostgreSQL, Inventory DB device count, etc.) |
| POST | `/api/setup` | everything (below) → `{ok}`; the server re-runs every check, writes secrets to OpenBao, creates the PostgreSQL and ClickHouse schemas, saves `flow.json`, creates the administrator and switches to normal mode without a restart |

Steps (screens) and the fields of `POST /api/setup`:

1. **Setup code** — `setup_code`.
2. **General** — `language` (`ru`/`en`), `theme` (`light`/`dark`/`system`), `timezone`, `public_url` (Flow's address for
   links from Umbrella and Inventory DB; prefilled with the browser's address).
3. **OpenBao** — `openbao: {addr, mount (flow), auth: "token"|"approle", token? | role_id?, secret_id?}`.
4. **PostgreSQL** — `postgres: {host, port, database, username, password, sslmode, attach_existing}`; the password goes
   to OpenBao. If the database already holds Flow state (the check answers `details.has_state: true`), the wizard
   offers to attach to it (`attach_existing: true`; the Administrator step can then be skipped).
5. **ClickHouse** — `clickhouse: {addr, database (flow), username, password, secure}` + retention
   `retention: {raw_days 15, d1m 30, d5m 90, d1h 730}` (top level, as the console sends it, or
   `clickhouse.retention`, which wins).
6. **Bus** — `nats: {url}` (empty = in-process queue).
7. **Flow collection** — `collector: {netflow_addr ":2055", sflow_addr ":6343", default_sampling_rate 1}`; shows which
   addresses to configure on the routers.
8. **Inventory DB (optional)** — `inventory: {enabled, url, token, interval "15m"}` with a check showing the device count.
9. **Umbrella (optional)** — `umbrella: {enabled, ingest_url, token}`: the ingest URL and token from Umbrella's
   "Connect source → Umbrella Flow" dialog; the check sends a test event.
10. **GeoIP (optional)** — `geoip: {databases: ["/geoip/GeoLite2-City.mmdb", …]}`; the check opens the files.
11. **Administrator** — `admin: {username, name, email, password}` with the password policy
    `password_policy: {min_length, letters, digits, symbols, not_username}` (top level; collapsed in the console, which
    proposes 12+ characters with letters and digits, not containing the user name). The server applies the same
    rules; without a policy it requires 12+ characters only.
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

From the raw flows of the last 5 minutes; in role `all` merged with the collector's registry (exporters silent in
ClickHouse, sampling rates, last seen, flows/s, interface names and speeds learned from option data / sFlow
counters).

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
| GET | `/api/inventory-db` | `{enabled, url, token_set, interval, last_sync: {at, ok, error, devices, interfaces, prefixes, circuits}}`; `interval` is a duration string (`"15m"`, `"1h"`) |
| PUT | `/api/inventory-db` | `{enabled, url, token?, interval}` — the token goes to OpenBao; `interval` is a duration (`"15m"`) or seconds (`900`), 1 minute to 7 days |
| POST | `/api/inventory-db/test` | `{ok, error?}` |
| POST | `/api/inventory-db/sync` | `{ok, stats}` |
| GET | `/api/inventory-db/unknown` | `{exporters: [{address, last_seen, flows}], addresses: [{address, bytes}]}` — from the enricher of the same process (role `all`); empty lists in the `api` role |

Synchronization runs in the enricher and detector processes (every `interval`, at once when the settings change). In
role `all` `POST /api/inventory-db/sync` refreshes the snapshot the enricher uses; in the `api` role it fetches to
check and count, and the enricher / detector processes follow within a minute.

## Classifiers

`GET|PUT /api/classifiers` → `{exporter: [CEL…], interface: [CEL…]}` (PUT answers 400 `invalid_rule` naming the rule
that does not compile).

`POST /api/classifiers/preview` `{kind: "exporter"|"interface", rules: [CEL…], sample}` →

```json
{
  "valid": true,
  "errors": [],
  "steps": [{"index": 0, "output": {"boundary": "external", "provider": "rostelecom"}}],
  "interface": {"index": 500, "name": "Hu0/0/0/1", "description": "Transit: Rostelecom", "speed": 100000000000,
                "boundary": "external", "connectivity": "", "provider": "rostelecom", "circuit": "", "vlan": 0}
}
```

`sample` is the object the rules see: for `exporter` rules `{name, address, site, region, role, group, tenant, tags}`;
for `interface` rules `{index, name, description, speed, boundary, connectivity, provider, circuit, vlan}` with an
optional `exporter` member (the full form `{exporter: {…}, interface: {…}}` is accepted too). `errors` lists compile
errors `{kind, index, line, column, offset, message}` (then `valid` is false); `steps` has one entry per rule with
what it set (`output`) or its runtime `error`; `exporter` / `interface` is the classified object.

## Detector

| Method | Path | |
|---|---|---|
| GET | `/api/detector/rules` (`detector:view`) | `{rules: [Rule…], default: bool, updated_at?}` — `default: true` while the rules were never saved (the built-in set is returned) |
| PUT | `/api/detector/rules` (`detector:edit`) | `{rules: [Rule…]}` → as GET; each rule is checked (400 `invalid_rule` / `duplicate_rule`); the detector applies them at once (same process) or within a minute |
| GET | `/api/detector/status` (`detector:view`) | `{rules: [{rule, last_eval, next_eval, duration_ms, error, groups, pending, firing}], alerts: [{rule_id, key, state, since, value, group, event…}], queued, sender: {url, outbox, sent, dropped, last_success, last_error, configured}}`; in the `api` role (detector in another process) the alerts and queue come from the state the detector saves in PostgreSQL and `remote: true` is added |

A rule (`internal/detector.Rule`):

```json
{"id": "e2e-ext-bps", "name": "External traffic per exporter", "enabled": true, "kind": "custom",
 "filter": "InIfBoundary = 'external'", "dimensions": ["ExporterName"], "metric": "bps", "operator": ">",
 "thresholds": {"bps": 1000000}, "window": "1m", "for": "0s", "interval": "15s", "severity": "info",
 "signal": "red.traffic.custom"}
```

`kind`: `link_utilization`, `link_commit`, `ddos_volumetric`, `ddos_syn`, `traffic_anomaly`, `traffic_drop`,
`exporter_silent`, `custom`; `thresholds: {bps, pps, percent, ratio, silence}`; durations as `"5m"`, `"7d"`;
`baseline: {weeks, min_samples, window, k, ratio, min_volume, direction}`. Events go to the Umbrella ingest URL of the
settings key `umbrella` with the Bearer token read from OpenBao on each send.

## Settings: Umbrella, OpenBao

| Method | Path | |
|---|---|---|
| GET | `/api/settings/umbrella` | `{enabled, ingest_url, token_set}` |
| PUT | `/api/settings/umbrella` | `{enabled, ingest_url, token?}` — the token goes to OpenBao; the detector switches to the new target |
| POST | `/api/settings/umbrella/test` | `{enabled, ingest_url, token?}` (stored token when omitted) → `{ok, error?, details: {event}}`; sends the detector's test event (`labels.umbrella_test = "true"`) |
| GET | `/api/settings/openbao` | `{addr, mount, auth, role_id?, status: {ok, version, token_expires, renewable, policies, error, reachable, sealed, token_ok, mount_ok, …}}` |
| POST | `/api/settings/openbao/test` | `{}` or no body checks the current connection (read, write and delete probe); `{addr, mount, auth, token | role_id + secret_id}` checks another server → `{ok, error?, details?}` |

## Incident link

`/go/incident?ci=&ip=&ref=&from=&to=` (web route, the "Traffic" link of Umbrella incidents) opens Visualize: by `ip`
(`SrcAddr = ip OR DstAddr = ip`, `<<` for a prefix), else by `ref` (Inventory DB `source_ref`:
`SrcCI = ref OR DstCI = ref`), else by `ci`; from 15 minutes before `from` to 15 minutes after `to` (or now).
