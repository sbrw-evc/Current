# Umbrella Flow: Docker deployment

One Compose project brings up the whole stack:

| Service | Image | What it does |
|---|---|---|
| `flow` | `umbrella-flow` (built from `app/`) | web console, API, collector, enricher (`FLOW_ROLE=all`) |
| `postgres` | `postgres:17-alpine` | configuration: users, roles, settings, saved views, audit log |
| `clickhouse` | `clickhouse/clickhouse-server:25.8` (LTS) | flows and 1m / 5m / 1h aggregates |
| `nats` | `nats:2.11-alpine` | JetStream bus between collector and enricher |
| `openbao` | `openbao/openbao:2.7.1` | every secret: service passwords, tokens, password hashes, session keys |
| `openbao-init` | same | initialises and unseals OpenBao, creates the `flow` KV v2 mount and AppRole, seeds passwords |
| `flow-demo` | `umbrella-flow` | `--profile demo`: synthetic NetFlow v9 / IPFIX / sFlow traffic |
| `geoipupdate` | `ghcr.io/maxmind/geoipupdate` | `--profile geoip`: MaxMind GeoLite2 databases |
| `grafana` | `grafana/grafana:13.2.3` | `--profile grafana`: the "CI traffic" dashboard on ClickHouse (read-only user `grafana`), see [deploy/grafana](../grafana/README.md) |

## Quick start

```sh
cd deploy/flow
cp .env.example .env        # set POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD, NATS_TOKEN
docker compose up -d
docker compose logs flow | grep setup_code
```

Open `http://<host>:8080`, enter the setup code and the SPA connection key (or set `SPA_CONNECTION_KEY` in `.env`;
sign-in and access are managed in [SPA](https://github.com/sbrw-evc/SPA-Single-point-of-authorization-)). Every other wizard field
(OpenBao, PostgreSQL, ClickHouse, NATS) is prefilled for the bundled services, so you can click through. The
wizard writes `flow.json` into the `flow-data` volume and switches to the console without a restart.

With demo traffic: `docker compose --profile demo up -d` (graphs fill within a minute).

## Secrets

- `.env` holds only bootstrap values the containers themselves need: the PostgreSQL, ClickHouse and NATS
  passwords (for the server containers) and the MaxMind key (for `geoipupdate`).
- On the first start `openbao-init` copies `POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD`, `NATS_TOKEN` and
  `CLICKHOUSE_GRAFANA_PASSWORD` into OpenBao (`flow/postgres#password`, `flow/clickhouse#password`, `flow/nats#token`,
  `flow/grafana#clickhouse_password`), only when they are not there yet.
  The `flow` container never sees these values in its environment: the wizard gets only `openbao://` references
  (`FLOW_SETUP_DEFAULTS_*_REF`) and Flow reads the secrets from OpenBao (30 s cache, so a rotation needs no restart).
- Flow signs in to OpenBao with AppRole; `openbao-init` writes `role_id` / `secret_id` into the `openbao-approle`
  volume, mounted read-only into `flow` at `/run/openbao`. `flow.json` stores only the paths.
- `secrets/openbao/init.txt` holds the unseal keys and the root token. **Back it up and keep it private**:
  without it the data in OpenBao (and so Flow's passwords) cannot be recovered.
- Rotating a service password: change it in the service (e.g. `ALTER ROLE flow PASSWORD …`), then in OpenBao
  (`bao kv patch -mount=flow postgres password=…`). Updating `.env` alone does not change a running installation.

## Ports

| Port | Protocol | What | Variable |
|---|---|---|---|
| 8080 | TCP | web console, API, `/metrics`, `/healthz` | `FLOW_HTTP_PORT`, `FLOW_HTTP_BIND` |
| 2055 | UDP | NetFlow v5 / v9, IPFIX | `FLOW_NETFLOW_PORT` |
| 6343 | UDP | sFlow v5 | `FLOW_SFLOW_PORT` |
| 10179 | TCP | BMP (BGP Monitoring Protocol), listened to only while enabled under Data collection → BMP routing | `FLOW_BMP_PORT` |
| 8123 | TCP | ClickHouse HTTP (Grafana, `clickhouse-client`), localhost only | `CLICKHOUSE_HTTP_PORT`, `CLICKHOUSE_BIND` |
| 8200 | TCP | OpenBao UI / API, localhost only | `OPENBAO_PORT`, `OPENBAO_BIND` |
| 3000 | TCP | Grafana (`--profile grafana`), localhost only | `GRAFANA_PORT`, `GRAFANA_BIND` |

PostgreSQL and NATS are not published: only the containers of the project reach them.

## Pointing routers at Flow

Send flows to the Docker host address, NetFlow / IPFIX to UDP 2055 and sFlow to UDP 6343. Keep the source address
of the exports stable (a loopback interface): Flow identifies the exporter by it and matches it to the Inventory DB
device by its primary IP. Examples:

```text
! Cisco IOS XE (Flexible NetFlow)
flow exporter FLOW
 destination 192.0.2.10
 source Loopback0
 transport udp 2055
 export-protocol ipfix
 option interface-table
 option sampler-table

# Juniper (inline J-Flow, IPFIX)
set services flow-monitoring version-ipfix template ipv4 ipv4-template
set forwarding-options sampling instance FLOW family inet output flow-server 192.0.2.10 port 2055
set forwarding-options sampling instance FLOW family inet output inline-jflow source-address 10.0.0.1

# sFlow (switches)
sflow collector 192.0.2.10 6343
```

Export interface and sampler option templates: Flow uses them for interface names and the sampling rate. A sampling
rate the exporter does not report can be set on the Exporters page.

BMP (optional, for AS paths and communities): enable it under Data collection → BMP routing, then point the routers at TCP 10179,
for example:

```text
! Cisco IOS XR
bmp server 1
 host 192.0.2.10 port 10179
 update-source Loopback0
 initial-delay 30
!
router bgp 65000
 neighbor 198.51.100.2
  bmp-activate server 1
```

```text
# Junos
set routing-options bmp station FLOW station-address 192.0.2.10 station-port 10179
set routing-options bmp station FLOW route-monitoring post-policy
set routing-options bmp station FLOW connection-mode active
```

Behind NAT or a load balancer keep the original source address (UDP with `externalTrafficPolicy: Local` / no SNAT).
Docker's default userland proxy for UDP is fine on Linux with `iptables` (the source address is kept).

## Joining Umbrella and Inventory DB

To reach Flow from Umbrella Monitoring and Inventory DB containers by name (`http://flow:8080`), join the shared
network `umbrella`:

```sh
docker network create umbrella   # if Umbrella / Inventory DB did not create it
echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.umbrella.yml' >> .env
docker compose up -d
```

Only the `flow` container joins it. The wizard defaults point at the bundled services by their `flow-postgres`,
`flow-clickhouse`, `flow-nats` and `flow-openbao` aliases, so Umbrella's own `postgres` or `openbao` containers on
the same network are never picked up by mistake. On a host that also runs Umbrella Monitoring, set
`OPENBAO_PORT=8201` in `.env`: its OpenBao already publishes 8200.

## Upgrade

```sh
git pull
docker compose up -d --build
```

Migrations run on start: PostgreSQL (goose, embedded) and ClickHouse (columns and aggregates derived from the column
registry). Back up first (below). Image tags of PostgreSQL, ClickHouse, NATS and OpenBao are pinned in `.env`;
change them one at a time and read the vendor's upgrade notes (ClickHouse: stay on LTS releases).

## Backup and restore

Back up all three stores and the OpenBao keys together: references in PostgreSQL and `flow.json` point into OpenBao.

```sh
# PostgreSQL (configuration)
docker compose exec -T postgres pg_dump -U flow -Fc flow > flow-$(date +%F).pgdump
# restore into an empty database:
docker compose exec -T postgres pg_restore -U flow -d flow --clean --if-exists < flow-2026-10-12.pgdump

# ClickHouse (flows): native BACKUP to a disk inside the container volume
docker compose exec clickhouse clickhouse-client --user flow --password "$CLICKHOUSE_PASSWORD" \
  --query "BACKUP DATABASE flow TO File('/var/lib/clickhouse/backups/flow-$(date +%F).zip')"
docker compose cp clickhouse:/var/lib/clickhouse/backups/. ./clickhouse-backups/
# restore (allowed_path is set in clickhouse/config.d/flow.xml; S3('…') works too):
#   RESTORE DATABASE flow FROM File('/var/lib/clickhouse/backups/flow-2026-10-12.zip')

# OpenBao: raft snapshot + the unseal keys
docker compose exec -e BAO_TOKEN="$(awk '/Initial Root Token/ {print $NF}' secrets/openbao/init.txt)" openbao \
  bao operator raft snapshot save /tmp/openbao.snap
docker compose cp openbao:/tmp/openbao.snap ./openbao-$(date +%F).snap
cp -a secrets/openbao ./openbao-keys-backup     # init.txt: unseal keys and root token

# Flow data volume (flow.json)
docker run --rm -v umbrella-flow_flow-data:/data -v "$PWD":/backup alpine tar czf /backup/flow-data.tgz -C /data .
```

Restoring OpenBao: start an empty `openbao`, `bao operator raft snapshot restore -force openbao.snap`, then unseal
with the keys of the backed-up `init.txt` (put it back into `secrets/openbao/`).

Flows themselves are usually not worth backing up for long: raw flows live 15 days by default, aggregates up to
2 years (set in the wizard).

## Operations

- Health: `docker compose ps` (every service has a healthcheck), `curl http://localhost:8080/healthz`.
- Metrics: `http://<host>:8080/metrics` (Prometheus).
- ClickHouse memory: `CLICKHOUSE_MEMORY_LIMIT` (container limit, default 4g); per-query limits in
  `clickhouse/users.d/flow.xml`; server settings in `clickhouse/config.d/flow.xml`.
- Logs: `docker compose logs -f flow` (JSON-file driver, 3 × 10 MB per container).
