# Grafana: "CI traffic"

`flow-ci-traffic.json` is the dashboard **CI traffic** (uid `flow-ci-traffic`) of
[docs/integrations.md §3.5](../../docs/integrations.md): the traffic of one CI straight from Flow's ClickHouse, opened
from Umbrella's incident context link. The same file lives in Umbrella Monitoring's `deploy/grafana`.

| File | What |
|---|---|
| `flow-ci-traffic.json` | the dashboard |
| `provisioning/datasources/flow-clickhouse.yaml` | datasource `grafana-clickhouse-datasource`, uid `flow-clickhouse`, read-only user |
| `provisioning/dashboards/flow.yaml` | loads the dashboards from `/var/lib/grafana/flow-dashboards` into the folder "Umbrella Flow" |

## Variables

Umbrella fills the four text boxes in the link (`/d/flow-ci-traffic/ci-traffic?var-ci=…&var-ci_id=…&var-ip=…&var-ref=…&from=…&to=…`).

| Variable | Matches | |
|---|---|---|
| `ref` | `SrcCI` / `DstCI`, `ExporterRef` | Inventory DB `source_ref` (`inventory-db:dcim.device:100`) |
| `ip` | `SrcAddr` / `DstAddr`, `ExporterAddress` | an address of the CI (together with `ref`, either matches) |
| `ci` | `SrcHost` / `DstHost` (name or `name.` prefix), `ExporterName` | Umbrella CI name; used only when `ref` and `ip` are empty |
| `ci_id` | — | Umbrella CI id, kept for reference |
| `rollup` | — | aggregated table of the long-range panel: `flows_1m`, `flows_5m` (default), `flows_1h` |
| `db` | — | hidden constant: the ClickHouse database (`flow`); change it when Flow uses another one |

## Panels

- **Received by / Sent by the CI, Peers, Flows** — totals over the range (raw flows).
- **Traffic in / out** — bits/s to the CI (destination side) and from it (source side).
- **Traffic in / out by reference, long range** — the same from `${rollup}` (matched by `ref` only: the aggregates keep
  no addresses), buckets at least the aggregate's step.
- **Top talkers** — peer addresses with host and Inventory DB reference, bytes to / from the CI.
- **Top ports and applications** — protocol, the lower port of a flow, the application.
- **Top interfaces** — exporter, input and output interface the CI's traffic crosses.
- **Carried by the CI as an exporter** (bits/s per input interface, top 10) and **Interfaces of the CI as an exporter**
  (in / out bits/s, speed, utilization) — for a CI that is itself a router or a switch exporting flows, as in an
  interface utilization incident.

Raw-table panels are limited by the raw retention (15 days by default). Volumes are already multiplied by the sampling
rate. Every panel's SQL was run against a real ClickHouse filled by the demo exporter and cloud flow logs, with the
variables of a host CI (`ref` + `ip`), a router CI, `ip` only and `ci` only. The same file is in Umbrella Monitoring's
`deploy/grafana` (keep them identical).

## With the Flow stack

```sh
cd deploy/flow
# .env: CLICKHOUSE_GRAFANA_PASSWORD (also needed without Grafana) and GRAFANA_ADMIN_PASSWORD
docker compose --profile grafana up -d     # http://localhost:3000 (GRAFANA_BIND / GRAFANA_PORT)
```

The profile runs Grafana 13 with the `grafana-clickhouse-datasource` plugin (`GF_PLUGINS_PREINSTALL`), the datasource
pointing at `clickhouse:9000` as the read-only user `grafana`, and this dashboard.

## The read-only ClickHouse user

`deploy/flow/clickhouse/users.d/grafana.xml` creates the user `grafana` with `GRANT SELECT ON flow.*`, the profile
`grafana_readonly` (`readonly = 2`, 1 GiB memory, 60 s, 100 000 result rows) and the password from
`CLICKHOUSE_GRAFANA_PASSWORD`. `openbao-init` seeds the same value into OpenBao (`flow/grafana#clickhouse_password`)
when it is not there yet, like the other service passwords; rotate it in `.env` and in OpenBao together and restart
`clickhouse` and `grafana`. Upgrading an existing stack: add `CLICKHOUSE_GRAFANA_PASSWORD` to `.env` first.

## In another Grafana (Umbrella's)

1. Install the plugin: `GF_PLUGINS_PREINSTALL=grafana-clickhouse-datasource`.
2. Mount `provisioning/datasources/flow-clickhouse.yaml` into `/etc/grafana/provisioning/datasources` with
   `FLOW_CLICKHOUSE_HOST` (the ClickHouse host reachable from that Grafana, e.g. `clickhouse` when the Flow
   ClickHouse joins the shared `umbrella` network), `FLOW_CLICKHOUSE_USER=grafana` and `FLOW_CLICKHOUSE_PASSWORD`;
   or create the datasource by hand with the uid `flow-clickhouse` (native protocol, port 9000, database `flow`).
3. Import `flow-ci-traffic.json` (or provision it with `provisioning/dashboards/flow.yaml`).
4. In Umbrella, point the incident "Traffic in Grafana" link at `/d/flow-ci-traffic/ci-traffic`.
