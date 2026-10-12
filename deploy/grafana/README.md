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

All four are text boxes; Umbrella fills them in the link (`/d/flow-ci-traffic/ci-traffic?var-ci=…&var-ci_id=…&var-ip=…&var-ref=…&from=…&to=…`).

| Variable | Matches | |
|---|---|---|
| `ref` | `SrcCI` / `DstCI` | Inventory DB `source_ref` (`inventory-db:dcim.device:100`); used first |
| `ip` | `SrcAddr` / `DstAddr` | an address of the CI; used when set (together with `ref`, either side matches) |
| `ci` | `SrcCI` / `DstCI`, `SrcHost` / `DstHost` | Umbrella CI name; used only when `ref` and `ip` are empty |
| `ci_id` | — | Umbrella CI id, kept for reference |

## Panels

- **CI traffic in / out** — bits/s to the CI (destination side) and from it (source side).
- **Top talkers** — peer addresses with host and CI, in / out rates over the range, bytes.
- **Top ports / applications** — application, protocol and server port (the lower port of a flow).
- **Top interfaces** — exporter interfaces the CI's traffic crosses (input and output side).

The queries read the raw table `flow.flows` (addresses and ports are not in the aggregates), so the range is limited
by the raw retention (15 days by default). Volumes are already multiplied by the sampling rate.

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
