# Umbrella Flow: REST API (contract between the backend and the web UI)

All paths are under `/api`. Responses are JSON; errors are `{"error": "<code>", "message": "<text>"}` with an HTTP
4xx/5xx status. The session is the HttpOnly cookie `flow_session`; mutating requests carry `X-CSRF-Token` (the `csrf`
value from `/api/auth/login` and `/api/auth/me`), as in Umbrella. Machine clients send an API token instead:
`Authorization: Bearer flow_…` (see [API tokens](#api-tokens)); token requests need no CSRF header. Times are RFC 3339
UTC.

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
| GET | `/api/auth/entra` | `{enabled}` (no session needed): show the "Sign in with Microsoft" button |
| GET | `/api/auth/entra/start` | browser navigation: 302 to the Microsoft sign-in page (state and PKCE verifier kept by Flow, state also in the cookie `flow_entra`) |
| GET | `/api/auth/entra/callback` | the redirect URI: redeems the code, verifies the ID token, creates or refreshes the user, sets `flow_session` and redirects to `/`; on failure redirects to `/login?signin_error=<code>` (`entra_off`, `entra_unavailable`, `entra_denied`, `entra_state`, `entra_account`, `entra_no_role`, `entra_conflict`, `user_disabled`, `too_many_attempts`) |

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

AS labels (`AS65000 Example`) are named, in order, from the GeoIP lookups of the enricher in the same process, from
the ClickHouse table `asn_names` (written by every enricher from its GeoIP lookups, `ReplacingMergeTree` keeping the
latest name; read by any process, the `api` role included, cached and refreshed every 5 minutes), then from a built-in
list of well-known ASes.

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
`SrcAS = AS65000`, `Proto = tcp`; array columns (`DstASPath`, `DstCommunities`, `DstLargeCommunities`, see
"BMP") take `=` / `!=` (contains / does not contain) and `IN` / `NOTIN` (any / none). Comments `-- …` and `/* … */`.

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

### Sampling overrides

| Method | Path | Body / answer |
|---|---|---|
| GET | `/api/sampling-overrides` (`exporters:view`) | `{results: [{exporter, if_index, rate, comment}]}` — `exporter` is a prefix (a single address is a `/32` or `/128`), `if_index` 0 = every interface of the exporter |
| PUT | `/api/sampling-overrides` (`exporters:edit`) | `{results: [...]}` replaces the whole list → as GET; 400 `invalid_exporter` (not an address or CIDR), `invalid_rate` (0 or above 2³¹) |

The collector forces the sampling rate of the matching flows: a per-interface override (`if_index` ≠ 0) applies to
the flows whose input interface (else output interface) is that one and wins over an exporter-wide override; among
exporter-wide overrides the longest prefix wins. A collector in the same process applies changes at once, a standalone
`collector` role re-reads them every minute (PostgreSQL from the shared `flow.json`). `FLOW_SAMPLING_OVERRIDES`
(`CIDR[@ifindex|@ifname]=rate`, e.g. `192.0.2.0/24=1000, 192.0.2.1@17=4000`) adds overrides from the environment that
win over stored ones with the same exporter and interface. The Exporters page edits the list (per exporter and per
interface).

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

| Method | Path | |
|---|---|---|
| GET | `/api/inventory-db/integration` (`settings.inventory:view`) | `{hook_secret_set, write_token_set, hook_url, inventory_url}` — `hook_url` is `<public_url>/api/integrations/inventory-db/hook` |
| PUT | `/api/inventory-db/integration` (`settings.inventory:edit`) | `{hook_secret?, write_token?}` (omitted = keep, `""` = remove) → as GET; both go to OpenBao (`inventory-db-hook#secret`, `inventory-db-write#token`) |
| POST | `/api/inventory-db/unknown/create` (`settings.inventory:edit`) | `{address}` → 201 `{ok, address, object: {id, address, display, url?, display_url?}}`: creates `<address>/32` (`/128`) in Inventory DB (`POST /api/v1/ipam/ip-addresses/`, `status: active`, `description: "Discovered by Umbrella Flow"`) with the editor token; 409 `write_token_required` without it, 409 `inventory_rejected` when Inventory DB refuses (duplicate…), 502 otherwise. Schedules an early sync |

## Inventory DB integration (called by Inventory DB)

The Flow side of [integrations.md §2](integrations.md#2-flow--inventory-db). Inventory DB calls these server-side with
a Flow API token (`Authorization: Bearer flow_…`) of a role with `integrations.inventory:read`.

`GET /api/integrations/inventory-db/status?object_type=<type>&ids=1,2,3[&window=24h]`

- `object_type`: `dcim.device`, `dcim.interface`, `circuits.circuit`; `ids`: 1–1000 ids; `window`: `15m` to `31d`
  (Go duration or `<n>d`), default `24h`. Response exactly as in the contract:
  `{window, results: {"<id>": {in_bps, out_bps, speed_bps, utilization_in, utilization_out, [p95_month_bps,
  commit_bps, over_commit,] sparkline: {t, in, out}, flow_url, last_seen}}}`.
- `in_bps` / `out_bps`: the last 5 complete minutes (`flows_1m`). Devices: flows of `ExporterRef =
  inventory-db:dcim.device:<id>` with a known input (in) or output (out) interface; interfaces: the device's flows with
  `InIfName` (in) or `OutIfName` (out) equal to the interface name (case-insensitive); circuits: `InIfCircuit` (in) /
  `OutIfCircuit` (out) equal to the circuit cid.
- `speed_bps`: the Inventory DB interface speed (circuits: the fastest interface terminating the circuit), else the
  speed the flows carried; `null` for devices and when unknown, and then `utilization_*` are `null`.
- `sparkline`: 48 complete buckets ending at the last bucket boundary (`window / 48`, from the coarsest table that fits);
  `t` are bucket starts.
- `p95_month_bps` (circuits and interfaces with a circuit only): the 95th percentile of the 5-minute rates
  (`flows_5m`) since the start of the month (UTC), counting 5-minute periods without traffic as 0, the larger of the
  two directions. `commit_bps`: the circuit commit rate from the Inventory DB snapshot (Kbps × 1000), `null` when not
  set; `over_commit`: `p95_month_bps > commit_bps` (`null` without a commit).
- `last_seen`: the latest minute with flows within the window, `null` when none. `flow_url`: `<public_url>/visualize?q=…`
  (the console's link format) for the object over the window.
- Ids missing from the Inventory DB snapshot are omitted (devices are taken as is while the snapshot is empty). One
  ClickHouse query per part (current, sparkline, p95) covers all ids of the request. In the `api` role the snapshot is
  loaded on demand with the stored connection and refreshed in the background.

`GET /api/integrations/inventory-db/prefix-addresses?prefix=10.0.0.0/24[&vrf=<name>][&window=24h]` →
`{prefix, results: [{address, bytes, flows, last_seen, in_ipam}]}`: addresses inside the prefix seen as source or
destination in the raw flows of the window (at most the raw retention), ordered by bytes, at most 1024. `vrf` keeps
only the flow ends enriched with that IPAM VRF. `in_ipam`: the address exists in the Inventory DB snapshot (in that VRF
when `vrf` is given).

`POST /api/integrations/inventory-db/hook` (no session or token): the change notification of §2.2. Verified with the
hook secret from OpenBao: `x-inventory-timestamp` (unix seconds, at most 5 minutes off) and `x-inventory-signature:
v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>`, several comma-separated signatures accepted during a rotation.
401 `unauthorized` for any failure (no secret configured, missing headers, old timestamp, mismatch), 400 when a signed
body is not JSON, else 202 `{accepted: <events>}`. The sync is debounced (5 s, at most one per 30 s): it records the
settings key `inventory_sync_request`, which the Inventory loops of every process follow (at once in this process,
within a minute in the others).

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
| GET | `/api/detector/rules` (`detector:view`) | `{rules: [Rule…], default: bool, updated_at?, new_defaults: [Rule…]}` — `default: true` while the rules were never saved (the built-in set is returned); `new_defaults`: built-in rules added by a later Flow version that the saved set lacks (never merged silently; see below) |
| GET | `/api/detector/rules/defaults` (`detector:view`) | `{rules: [Rule…], default: true}` — the built-in set (the console's "restore defaults" for one rule or all) |
| PUT | `/api/detector/rules` (`detector:edit`) | `{rules: [Rule…]}` → as GET; each rule is checked (400 `invalid_rule` / `duplicate_rule`); the detector applies them at once (same process) or within a minute |
| POST | `/api/detector/rules/add-defaults` (`detector:edit`) | `{ids?: [id…], dismiss?: [id…]}` → as GET: appends the named `new_defaults` (all of them when the body is empty) to the saved set, `dismiss` stops offering them; saved rules are never changed; 400 `unknown_default` for an id that is not offered |

New built-in rules (for example `threat-contact`) reach installations that saved their rules only through this merge:
the console shows "new default rules available" from `new_defaults`. A built-in rule deleted from the saved set (or
dismissed) is remembered in the settings key `detector_defaults_dismissed` and not offered again; an installation
that deleted a built-in rule before this mechanism existed sees it offered once.
| GET | `/api/detector/status` (`detector:view`) | `{rules: [{rule, last_eval, next_eval, duration_ms, error, groups, pending, firing}], alerts: [{rule_id, key, state, since, value, group, event…}], queued, sender: {url, outbox, sent, dropped, last_success, last_error, configured}}`; in the `api` role (detector in another process) the alerts and queue come from the state the detector saves in PostgreSQL and `remote: true` is added |

A rule (`internal/detector.Rule`):

```json
{"id": "e2e-ext-bps", "name": "External traffic per exporter", "enabled": true, "kind": "custom",
 "filter": "InIfBoundary = 'external'", "dimensions": ["ExporterName"], "metric": "bps", "operator": ">",
 "thresholds": {"bps": 1000000}, "window": "1m", "for": "0s", "interval": "15s", "severity": "info",
 "signal": "red.traffic.custom"}
```

`kind`: `link_utilization`, `link_commit`, `ddos_volumetric`, `ddos_syn`, `traffic_anomaly`, `traffic_drop`,
`exporter_silent`, `custom`, `threat_contact` (see "Threat intelligence"); `thresholds: {bps, pps, percent, ratio, silence}`; durations as `"5m"`, `"7d"`;
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

## Umbrella: API connection, visibility scope, dependencies

Flow's side of [integrations.md §3.2–3.3](integrations.md). The Umbrella API connection is Umbrella's address and a
service-account token (Umbrella permissions `integrations.flow:read` and `cmdb:propose`); the token goes to OpenBao
(`flow/umbrella-api#token`), PostgreSQL keeps the reference (settings key `umbrella_api`).

| Method | Path | Permission | |
|---|---|---|---|
| GET | `/api/settings/umbrella/api` | `settings.umbrella:view` | `{url, token_set}` |
| PUT | `/api/settings/umbrella/api` | `settings.umbrella:edit` | `{url?, token?}` (`token: ""` removes it; a trailing `/api` is dropped) → as GET; drops the scope cache |
| POST | `/api/settings/umbrella/api/test` | `settings.umbrella:edit` | `{url?, token?}` (stored values when omitted) → `{ok, error?, details: {restricted, known, mode, cis, services, refs, addresses}}`: asks Umbrella for the scope of the signed-in user |
| GET | `/api/umbrella/scope` | signed in | the caller's scope: `{restricted, ok, error?, configured, known, mode, cis, services, refs, addresses, checked_at}`; `restricted: false` for roles without `scope:umbrella` |
| GET | `/api/dependencies` | `dependencies:view` | `{settings, configured, available, running, next_run, last_run, runs: [Run…], proposals: [Proposal…]}` — `proposals` are those of the last finished run (the preview) |
| PUT | `/api/dependencies/settings` | `settings.umbrella:edit` | `{enabled, hour, min_flows, min_days, max_proposals}` → as GET |
| POST | `/api/dependencies/run` | `dependencies:run` | `{dry_run?}` → `{run: Run, proposals: [Proposal…]}`; 409 `already_running`; `dry_run` builds the proposals without sending them |

**Visibility scope.** For a user whose role has `scope:umbrella` (never the built-in Administrator), every ClickHouse
query made for the request — visualize (time series, bidirectional, sankey), flow search, home widgets, exporters,
filter value completion, the Inventory DB integration endpoints — reads the flow tables through
`(SrcCI IN refs OR DstCI IN refs OR SrcAddr IN ips OR DstAddr IN ips)` with the refs and addresses of the CIs Umbrella
returns for the user's login (`GET {url}/api/integrations/flow/scope?username=`; cached 60 s per user). Mode `all` is
unrestricted; an unknown user sees nothing. The aggregated tables have no addresses, so there only the CI part
applies; a scope with addresses makes Visualize prefer the raw table while it still covers the range. If Umbrella
cannot be asked (not configured, unreachable, 401…), these endpoints answer **503 `scope_unavailable`** — never
unrestricted data — and `/api/umbrella/scope` reports `ok: false` for the console's banner. The exporters list does not
merge the collector registry for such users. Implemented once in `query.ScopedConn`, which wraps the ClickHouse
connection of the API.

**Dependency discovery.** Reads 7 days of raw flows (the aggregates have no ports): flows whose both ends have an
Inventory DB reference (`SrcCI`, `DstCI`, different), TCP / UDP / SCTP; the server is the side with the lower port
(equal ports: the destination); grouped by client CI, server CI, protocol and server port (requests and responses of
a connection count together); kept when there are at least
`min_flows` flow records on at least `min_days` distinct days; largest `max_proposals` by bytes. Each pair becomes a
proposal `client depends_on server` with the key `flow:<from ref>-><to ref>:<proto>/<port>`, evidence (bytes, flows,
days seen, first / last seen, top application) and `flow_url` (Visualize of the pair over the period, from the public
URL of the general settings), posted to `POST {url}/api/cmdb/proposals` in batches of 200. Daily runs start after
`hour` (UTC) while `enabled` and the Umbrella API is configured; with several `api` processes the day is claimed once
(PostgreSQL). Defaults: `{enabled: false, hour: 3, min_flows: 100, min_days: 3, max_proposals: 500}`.

A run (`Run`): `{id, trigger: "schedule"|"manual", actor, dry_run, started_at, finished_at, ok, error, pairs, sent,
accepted, updated, ignored, params: {days, min_flows, min_days, limit}}`; the last 50 are kept; a run without a result after 30 minutes is shown as
`ok: false, error: "interrupted"`. A `Proposal` is the object of integrations.md §3.3.

## Settings: moving the secrets to another OpenBao

Permission `settings.openbao:migrate`. The target body is `{addr, mount, namespace?, auth: "approle" | "token", token? |
role_id + secret_id?, ca_cert?, skip_verify?}`; without credentials, a target on the current server reuses the current
ones (also AppRole files).

| Method | Path | |
|---|---|---|
| POST | `/api/settings/openbao/probe` | target → `{ok, error?, status: {version, …}, write_ok, kv2_error?, secrets: <already in the target mount>, same?}`: reachable, token works, the mount is KV v2 and writable |
| POST | `/api/settings/openbao/migrate` | `{target, overwrite?}` → `{addr, mount, copied, refs}`; 409 `openbao_target_not_empty` when the target mount has secrets and `overwrite` is not set, 400 `openbao_same_store`, 502 `openbao_migration_failed` |

The move copies every secret of the current mount (same paths and keys), rewrites `openbao://<old mount>/…` references
in every PostgreSQL text / jsonb column and in `flow.json` (when the mount name changes), writes `flow.json` with the new
connection and switches the running OpenBao client in place: the API, the pipeline and the detector of the process use
the new OpenBao at once. Nothing is deleted from the source. On failure nothing is switched, references are restored,
and secrets copied to an empty target are removed. Audit: `settings.openbao.migrate` / `settings.openbao.migrate_failed`.

`GET /api/settings/openbao` → `status.renewal`: `{mode: "renew" | "login" | "none", logged_in_at, logins, renewed_at,
renewals, next_at, last_error?, last_error_at?}` — how the client keeps its token alive (renewed once two thirds of the
lease have passed; a non-renewable AppRole token is replaced by a new sign-in).

## Settings: Microsoft Entra ID

Permissions `users:view` / `users:edit` (as LDAP). Settings key `entra`; the client secret is stored in OpenBao at
`entra#client_secret` and never returned.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/entra` | `{enabled, cloud: "global" \| "usgov" \| "china", tenant_id, client_id, redirect_url, client_secret_set, default_role_id, group_roles: [{group_id, role_id, role}], users}` |
| PUT | `/api/settings/entra` | `{enabled, cloud, tenant_id, client_id, redirect_url, client_secret?, default_role_id, group_roles: [{group_id, role_id}]}` → the view; enabling checks the tenant and the credentials first (400 `entra_unavailable`, `entra_invalid`, `entra_secret_required`); `client_secret` empty or omitted keeps the stored one (only for the same tenant and application); switching off signs Entra users out |
| POST | `/api/settings/entra/test` | same body → `{ok, probe: {issuer, tenant_id, credentials}, error?}` (discovery + a client-credentials token) |

`redirect_url` must be `<Flow address>/api/auth/entra/callback` and registered in Entra ID. Sign-in: OpenID Connect
authorization code flow with PKCE (S256), nonce and state; the ID token (RS256) is verified against the tenant keys
(issuer, audience, expiry, nonce, tenant). The profile comes from Microsoft Graph `/me`. When group mappings exist,
groups come from the `groups` claim, or from Graph `/me/transitiveMemberOf` (nested groups; needs the delegated
permission `GroupMember.Read.All`) when the claim is missing or overflows. Role: the first `group_roles` entry whose
group the user belongs to, else `default_role_id` (0 = no access, `entra_no_role`). The user (`source: "entra"`, user
name = `preferred_username` in lower case) is created on the first sign-in and refreshed on each one; a local or LDAP
user with the same name is never taken over.

## API tokens

Machine access ([integrations §1](integrations.md#1-api-tokens-all-three-apps)). A **service account** has a role; its
tokens carry exactly that role's permissions. Tokens are `flow_` + 32 random bytes (base64url, 48 characters); only
HMAC-SHA256 with the key `keys#tokens` in OpenBao is stored, the plaintext is returned once by `POST /api/tokens`.
Requests: `Authorization: Bearer flow_…`, no CSRF header; an unknown, expired or revoked token, or a token of a disabled
account, gets 401 `invalid_token`. Permissions `tokens:view` / `tokens:edit`; a role can be given to a service account
only by a user who has all its permissions (403 `role_not_grantable`; `scope:umbrella` excepted). Audit:
`service_account.create`, `service_account.delete`, `token.create`, `token.revoke`, `token.use_new_address` (first use
and use from another client address than the last one). `last_used_at` is updated at most once a minute.

| Method | Path | |
|---|---|---|
| GET | `/api/service-accounts` | `{results: [{id, name, description, role_id, role, disabled, tokens: <active>, created_by, created_at, updated_at}]}` |
| POST | `/api/service-accounts` | `{name (1-64, no spaces or /), description?, role_id}` → 201 the account; 409 `conflict` for a taken name |
| DELETE | `/api/service-accounts/{id}` | `{ok}`; its tokens are deleted |
| GET | `/api/tokens` | `?service_account_id=` optional → `{results: [{id, service_account_id, service_account, name, display: "flow_AbCd…", expires_at, last_used_at, last_used_from, created_by, created_at, revoked_at, revoked_by, active}]}`, newest first |
| POST | `/api/tokens` | `{service_account_id, name, expires_at?: "2027-01-31" \| RFC 3339 (future, ≤ 5 years; empty = no expiry)}` → 201 the token view + `token` (the plaintext, shown once) |
| DELETE | `/api/tokens/{id}` | revokes (kept for the audit) → the token view |

Permissions used by integrations: `integrations.inventory:read` (Inventory DB's calls to
`/api/integrations/inventory-db/*`), `scope:umbrella` (a restriction: traffic limited to the user's Umbrella scope; not
part of Administrator).

## Reverse DNS

ElastiFlow-like PTR enrichment in the enricher (`internal/rdns`): a lookup never blocks the pipeline — it answers from a
positive / negative cache and queues a miss for a bounded worker pool that queries the configured servers in turn under
a rate limit. The first flows of an address get an empty name, later ones the cached name (an expired name is served
while it is refreshed). Only addresses without an Inventory DB host name are resolved; the result goes to the
`SrcHostPTR` / `DstHostPTR` columns. Settings key `rdns` (permissions `settings.rdns:view` / `settings.rdns:edit`);
the enricher applies changes at once (same process) or within a minute. Metrics: `flow_rdns_lookups_total{result}`,
`flow_rdns_cache_hits_total`, `flow_rdns_cache_misses_total`, `flow_rdns_dropped_total`, `flow_rdns_cache_entries`,
`flow_rdns_queue_length`, `flow_rdns_query_duration_seconds`; status component `rdns`.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/rdns` | `{settings: {enabled, servers: ["192.0.2.53", "dns.example:5353"] (empty = system resolver), scope: all \| private \| public, workers (8), rate_limit (200 queries/s), positive_ttl (3600 s), negative_ttl (600 s), timeout_ms (2000), cache_size (100000), queue_size (10000)}, stats?}` — `stats` (cache, queue, hits, misses, found, not_found, errors, dropped) when the enricher runs in this process |
| PUT | `/api/settings/rdns` | the `settings` object → as GET; 400 `rdns_invalid` |

## Threat intelligence

The enricher (`internal/threat`) downloads public IP blocklists at run time — FireHOL level1, Spamhaus DROP (v4 / v6;
EDROP, merged into DROP since 2024, is listed disabled) and abuse.ch Feodo Tracker by default, any `http(s)` list can
be added — into a longest-prefix-match trie and fills `SrcThreat` / `DstThreat` with the list name (`""` when none).
List contents are never part of Flow (repository or image): each installation fetches them under the lists' terms of
use, with `If-None-Match` / `If-Modified-Since`, not more often than every 60 minutes (default 360). Formats: one
address or prefix per line with `#` / `;` comments (FireHOL netset, Spamhaus `.txt`, abuse.ch), or JSON lines with a
`cidr` field (Spamhaus `drop_v4.json`). Special-purpose ranges (RFC 1918, CGNAT, loopback, link-local, multicast,
ULA, documentation, reserved — FireHOL level1 includes the bogons) and the `exclude` prefixes are never flagged. A list
that fails keeps its previous content. Settings key `threat`, last status in `threat_status` (written by the
downloading process); permissions `settings.threat:view` / `settings.threat:edit`. Metrics:
`flow_threat_matches_total{list}`, `flow_threat_list_prefixes{list}`, `flow_threat_list_updated_timestamp_seconds{list}`,
`flow_threat_list_error{list}`, `flow_threat_lookups_total`, `flow_threat_prefixes`.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/threat` | `{settings: {enabled, lists: [{name, url, enabled, terms?}], refresh_minutes, exclude: [prefix…], refresh_requested_at?}, status: {updated_at?, prefixes, lists: [{name, url, enabled, prefixes, skipped, updated_at?, checked_at?, error?}]}, default_lists}` — the defaults (enabled, public lists) until saved |
| PUT | `/api/settings/threat` | `{enabled, lists, refresh_minutes, exclude}` → as GET; 400 `threat_invalid`; disabled lists and exclusions apply at once, new lists are downloaded right away |
| POST | `/api/settings/threat/refresh` | 202 `{requested_at}`: the downloading process refreshes at once (same process) or within a minute |

Detector rule kind `threat_contact` → signal `sec.threat.contact`, method RED. Per internal host (the side of the flow
that is not listed; flows with both sides listed are ignored) over `window` (default 5m, raw table), `bps ≥
thresholds.bps` (default 0: any contact). CI: the host's Inventory DB name and `source_ref`, else its PTR name, else
the address; labels `host_ip`, `host`, `host_ci`, `host_ptr`, `threat_list`, `threat_lists`, `threat_ip`, `threat_ips`,
`direction` (`outbound` / `inbound` / `both`), `bps`, `pps`, `flows`, `exporter`. Built-in rule `threat-contact`:
enabled, severity `error`, interval 1m, hysteresis 30m (installations that saved their rules before get it offered in
`new_defaults` and add it with `POST /api/detector/rules/add-defaults`).

## Cloud flow logs

`POST /api/ingest/flowlogs/{aws|azure|gcp}` turns cloud flow logs into flow records and puts them on the pipeline bus
(the bus of role `all`, or NATS JetStream in the `api` role when a bus URL is configured; 501 otherwise). No session:
each provider has its own ingest token in OpenBao (`flowlogs#aws`, `#azure`, `#gcp`), presented as
`Authorization: Bearer <token>`, as `X-Amz-Firehose-Access-Key` (AWS), or as `?token=` (for Pub/Sub push
subscriptions, which cannot send a static header). Answers: 200 `{accepted, skipped}`, 401 `unauthorized`, 403
`flowlogs_disabled`, 400 `invalid_flowlogs`, 413 `too_large` (64 MiB after `Content-Encoding: gzip`), 503
`bus_unavailable` (retry). Records are sampled 1:1; `TimeReceived` is the flow end when within the last day.
`ForwardingStatus` 64 = accepted, 128 = rejected / denied. Metrics `flow_flowlogs_records_total{provider,result}`,
`flow_flowlogs_requests_total{provider,code}`.

Exporter: cloud logs have none, so each source gets a synthetic address in `fd75:666c::/32` (an AWS ENI or VPC id and
an Azure MAC are encoded in it and named back in any process; GCP VMs / subnets use a hash, named in the receiving
process only), `0.0.0.0` when the record names no source. `ExporterName`: `vpc-…/eni-…` (AWS), `<NSG or VNet>/<MAC>`
(Azure), `<project>/<vm>` or `<project>/<vpc>/<subnet>` (GCP). Such exporters are not listed as unknown in Inventory DB.

| Provider | `FlowType` | Body |
|---|---|---|
| `aws` | `aws-vpc` | VPC Flow Logs text lines: default version 2 format, or a custom format given by a header line (`version vpc-id … srcaddr …`, as in S3 files) or by `?fields=${version} ${srcaddr} …`; CloudWatch Logs subscription JSON (`logEvents[].message`, gzip accepted); Kinesis Data Firehose HTTP endpoint delivery (`{requestId, timestamp, records: [{data: base64}]}` with `X-Amz-Firehose-Request-Id`, answered `{requestId, timestamp, errorMessage?}`). `NODATA` / `SKIPDATA` records are skipped |
| `azure` | `azure-vnet` | `{records: [...]}` or an array of records: NSG flow logs (`properties.flows[].flows[].flowTuples`, version 2 counts; version 1 tuples and flow-begin tuples carry no volume and are skipped) and VNet flow logs (`flowLogVersion` 4, `flowRecords.flows[].flowGroups[].flowTuples`, state `D` = denied); both directions of a tuple become two flows |
| `gcp` | `gcp-vpc` | Pub/Sub push `{message: {data: base64(LogEntry)}, subscription}`, a LogEntry or an array of LogEntries; `jsonPayload.connection`, `bytes_sent`, `packets_sent`, `start_time`, `end_time`, `reporter` (`SRC` / `DEST`, `SRC_GATEWAY` / `DEST_GATEWAY`: the reporting side is the exporter), `src_instance` / `dest_instance`, `src_vpc` / `dest_vpc`. GCP samples packets but reports `bytes_sent` / `packets_sent` as totals estimated from the sampled packets and has no sampling-rate field, so they are stored as is (`SamplingRate` 1); `bytes_sent` is payload bytes. A flow between two logged VMs is reported by both ends: filter on one `ExporterName` side when summing |

| Method | Path | |
|---|---|---|
| GET | `/api/settings/flowlogs` (`settings.flowlogs:view`) | `{available, public_url, aws: {enabled, token_set, endpoint, url}, azure: {…}, gcp: {…}}` — `available`: this process can accept flow logs; `url`: `<public_url><endpoint>` (`""` without a public URL in the general settings). Console: Settings → Cloud flow logs (write-only tokens, ingest URLs and setup snippets for AWS Firehose, Azure and GCP Pub/Sub push) |
| PUT | `/api/settings/flowlogs` (`settings.flowlogs:edit`) | `{aws?: {enabled, token?}, azure?: …, gcp?: …}` — `token` (≥ 16 characters) goes to OpenBao, `""` removes it, omitted keeps it; enabling needs a token (400 `flowlogs_invalid`) |

## gNMI

Interface data read over gNMI (OpenConfig) for exporters that Inventory DB does not describe, or whose interfaces have
no name or speed there (`internal/gnmi`, runs with the enricher). Order of the enricher's interface sources: Inventory
DB, then the collector's option templates / sFlow counters, then gNMI, then SNMP — when gNMI and SNMP both answer for a
device, the gNMI name wins and SNMP only fills a missing description or speed (an Inventory DB device whose interface
lacks an `snmp_index` is matched by the gNMI / SNMP name). Each poll is a series of gNMI `Get` requests (one path each,
`name=*` / `index=*` wildcards) over gRPC: `/interfaces/interface/state/ifindex` (required: a device that refuses it
fails the poll), `/interfaces/interface/state/description`, `/interfaces/interface/ethernet/state/port-speed` and
`negotiated-port-speed`, `/interfaces/interface/aggregation/state/lag-speed`, and the subinterface
`/interfaces/interface/subinterfaces/subinterface/state/{ifindex,description}` (the others are optional). Values may
come as typed scalars or as JSON / JSON_IETF (leaves or whole containers, module prefixes stripped). Name = the
interface key (`<name>.<index>` for a subinterface, which takes its interface's speed; a subinterface sharing the
ifindex of its interface is ignored), description = `state/description`, speed = the negotiated, else the configured
port speed (OpenConfig `SPEED_10MB` … `SPEED_800GB` identities mapped to bits/s, `SPEED_UNKNOWN` = 0), else
`lag-speed` × 10⁶. Requests use JSON_IETF (a device answering `InvalidArgument` / `Unimplemented` is asked again with
JSON) or JSON per profile. Credentials: optional `username` / `password` sent as the `username` / `password` gRPC
metadata of every request (the gNMI convention), TLS on / off (TLS 1.2+; without TLS the password travels in clear
text), `skip_verify`, an optional `server_name` the device certificate must carry (default: the address) and an
optional PEM CA bundle (default: the system roots). Polled devices, profiles by prefix, interval / TTL and retries
after a failure work as for SNMP below (`timeout_seconds` default 10, per request). Secrets live in OpenBao at
`gnmi/<profile id>/{password,ca}` (key `value`); the settings hold only references. Settings key `gnmi`, permissions
`settings.gnmi:view` / `settings.gnmi:edit`. Metrics `flow_gnmi_polls_total{result}`, `flow_gnmi_devices`; status
component `gnmi`.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/gnmi` | `{enabled, poll_exporters, devices: [addr], interval_minutes, ttl_minutes, timeout_seconds (10), concurrency (8), profiles: [{id, name, prefixes, port (57400), username?, tls, skip_verify?, server_name?, encoding: "json_ietf"\|"json", password_set, ca_set}], encodings, status?: {enabled, devices: [{address, profile, interfaces, polled?, error?, configured}], failing}}` — `status` when the poller runs in this process |
| PUT | `/api/settings/gnmi` | the same fields; per profile the write-only `password` and `ca_pem` (omitted = keep, `""` = remove; a password is required with a `username`, the CA must be PEM). A profile without a user name drops its password, one without TLS its CA. A profile without a known `id` gets a new one; removed profiles' secrets are deleted. → as GET; 400 `gnmi_invalid` |
| POST | `/api/settings/gnmi/test` | `{address, profile}` (a profile as in PUT; secrets not given are taken from the saved profile of the same `id`) → `{ok, error?, details?: {interfaces, sample: [{index, name, descr, speed}]}}` |

## SNMP

Fallback interface data for exporters that Inventory DB does not describe, or whose interfaces have no name or speed
there (`internal/snmp`, runs with the enricher). It is the last interface source of the enricher: Inventory DB, then
the collector's option templates / sFlow counters, then gNMI, then SNMP (a missing description or speed is filled from
the next source; an Inventory DB device whose interface lacks an `snmp_index` is matched by the SNMP `ifName`). SNMPv2c and
SNMPv3 (USM: MD5 / SHA / SHA-224 / -256 / -384 / -512, DES / AES / AES-192 / AES-256 / AES-192C / AES-256C) with
GETBULK walks of `ifName`, `ifDescr`, `ifAlias`, `ifHighSpeed` and `ifSpeed`: name = `ifName` (else `ifDescr`),
description = `ifAlias`, speed = `ifHighSpeed` × 10⁶ (else `ifSpeed`). Polled devices: the exporters seen in flows
(`poll_exporters`; an unknown exporter is queued on its first lookup, and with a collector in the same process its
exporter list is polled too) and the `devices` list, each with the first credential profile whose `prefixes` contain
it (a profile without prefixes matches every device; addresses no profile covers are never polled). Results are
refreshed every `interval_minutes` (default 30), retried after a failure, and kept for `ttl_minutes` (default 360)
when a device stops answering. Credentials live in OpenBao at `snmp/<profile id>/{community,auth,priv}` (key
`value`); the settings hold only references. Settings key `snmp`, permissions `settings.snmp:view` /
`settings.snmp:edit`. Metrics `flow_snmp_polls_total{result}`, `flow_snmp_devices`; status component `snmp`.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/snmp` | `{enabled, poll_exporters, devices: [addr], interval_minutes, ttl_minutes, timeout_seconds (3), retries (1), concurrency (8), profiles: [{id, name, prefixes, version: "2c"\|"3", port (161), username?, security_level?: noAuthNoPriv\|authNoPriv\|authPriv, auth_protocol?, priv_protocol?, context_name?, community_set, auth_password_set, priv_password_set}], auth_protocols, priv_protocols, status?: {enabled, devices: [{address, profile, interfaces, polled?, error?, configured}], failing}}` — `status` when the poller runs in this process |
| PUT | `/api/settings/snmp` | the same fields; per profile the write-only `community`, `auth_password`, `priv_password` (omitted = keep, `""` = remove; required for a new profile / level). A profile without a known `id` gets a new one; removed profiles' secrets are deleted. → as GET; 400 `snmp_invalid` |
| POST | `/api/settings/snmp/test` | `{address, profile}` (a profile as in PUT; secrets not given are taken from the saved profile of the same `id`) → `{ok, error?, details?: {interfaces, sample: [{index, name, descr, speed}]}}` |

## BMP

BGP Monitoring Protocol receiver (RFC 7854, `internal/bmp`, runs with the enricher): routers connect to TCP 10179
(`FLOW_BMP_ADDR`; listened to only while enabled) and stream the Adj-RIB-In of their BGP peers. Route monitoring
UPDATEs (IPv4 NLRI, MP_REACH / MP_UNREACH for IPv6 unicast, 4-byte AS numbers, AS4_PATH merging for 2-byte
sessions, ADD-PATH when both OPENs of the Peer Up negotiate it, COMMUNITIES, LARGE_COMMUNITY, NEXT_HOP) feed a
per-peer RIB held in a compact longest-prefix-match table with interned attribute sets. Withdrawals remove the
peer's path; Peer Down removes the peer's routes; a closed session removes every route of that router. Loc-RIB
(RFC 9069) counts as post-policy. Lookups prefer post-policy paths (`policy: prefer-post`, or only `post` / `pre`),
then the shorter AS path. Other address families (VPN, labeled, flowspec) are ignored.

The enricher fills, from the route of `DstAddr`, the raw-table columns `DstASPath` (`Array(UInt32)`),
`DstCommunities` (`Array(UInt32)`, `as << 16 | value`) and `DstLargeCommunities` (`Array(String)`, `"a:b:c"`), and
`NextHop` when the exporter reported none. While BMP is enabled the AS provider order is `as_providers` (default
`routing, flow, geoip`): `routing` is the origin AS (last AS of the path) of the route of `SrcAddr` / `DstAddr`; a
local route (empty path) gives none, so the next provider applies. Array columns are not dimensions; in filters `=` /
`!=` test membership (`DstASPath = 15169`, `DstCommunities = 65000:100`, `DstLargeCommunities = '65000:1:2'`) and
`IN` / `NOTIN` any / none of the values (ClickHouse `has` / `hasAny`). Raw flow search returns them as JSON arrays.

Settings key `bmp`, permissions `settings.bmp:view` / `settings.bmp:edit`. Metrics `flow_bmp_messages_total{type}`,
`flow_bmp_errors_total{kind}` (`framing`, `decode`, `rejected`), `flow_bmp_sessions`, `flow_bmp_prefixes_v4`,
`flow_bmp_prefixes_v6`, `flow_bmp_routes`, `flow_bmp_peers`, `flow_bmp_attribute_sets`, `flow_bmp_rib_bytes`
(estimate); status component `bmp`. With several enricher processes each holds only the routes of its own sessions.

| Method | Path | |
|---|---|---|
| GET | `/api/settings/bmp` | `{enabled, policy: prefer-post\|post\|pre, routers: [addr or prefix] (allowed sources, empty = any), as_providers, status?: {enabled, listen, error?, rib: {prefixes_v4, prefixes_v6, routes, attribute_sets, peers, bytes}, sessions: [{router, sys_name?, sys_descr?, since, peers_up, messages, errors, last_error?}], peers: [{router, address, as, distinguisher?, post_policy, routes, since, last_update}]}}` — `status` when the receiver runs in this process |
| PUT | `/api/settings/bmp` | `{enabled, policy, routers, as_providers}` → as GET; 400 `bmp_invalid`; applied at once (same process) or within a minute |
| GET | `/api/bmp/lookup?address=` (`settings.bmp:view`) | `{prefix, origin_as, as_path, communities: ["a:b"], large_communities, next_hop, peer: {router, address, as, post_policy}}`; 404 `no_route`; 501 when the receiver runs in another process |

## Incident link

`/go/incident?ci=&ip=&ref=&from=&to=` (web route, the "Traffic" link of Umbrella incidents and CIs) opens Visualize
filtered on the CI as an end of the traffic or as the exporter that carried it (a router whose link is overloaded):
`ip` → `SrcAddr = ip OR DstAddr = ip OR ExporterAddress = ip` (`<<` for a prefix), `ref` (Inventory DB `source_ref`) →
`SrcCI = ref OR DstCI = ref OR ExporterRef = ref` (both joined with `OR` when both are given; dimensions `SrcAddr`,
`DstAddr`, `Proto` with an address, else `SrcCI`, `DstCI`, `App`); `ci` alone → `SrcCI`, `DstCI` or `ExporterName` =
`ci`; from 15 minutes before `from` to 15 minutes after `to` (or now).
