# Umbrella Flow Helm chart

Deploys Umbrella Flow (NetFlow / IPFIX / sFlow collection, BMP, enrichment, ClickHouse storage, web console) on
Kubernetes. One image runs every role; the chart runs it as one Deployment (`roles.mode: all`, default) or one
Deployment per role (`roles.mode: split`).

Secrets live only in OpenBao. The chart takes no password as a value: the database passwords are `openbao://`
references, and the only Kubernetes Secret Flow reads is the OpenBao AppRole (`role_id`, `secret_id`) or token file.

## Prerequisites

- Kubernetes 1.27+, Helm 3.
- The `umbrella-flow` image in a registry the cluster can pull from (`make image` in `app/`, then push).
- External services (production): ClickHouse 25.8, PostgreSQL 17, OpenBao 2.x with a KV v2 mount `flow` and an
  AppRole for Flow (policy as in `deploy/flow/openbao/flow-policy.hcl`), NATS JetStream for `split` mode.
- A LoadBalancer implementation that keeps client source addresses for UDP (`externalTrafficPolicy: Local`): Flow
  identifies an exporter by the source address of its datagrams.

## Install

Put the service passwords into OpenBao and create the AppRole Secret:

```sh
bao kv put -mount=flow postgres password=...
bao kv put -mount=flow clickhouse password=...
bao kv put -mount=flow nats token=...          # when NATS is used
kubectl create secret generic flow-openbao \
  --from-literal=role_id="$(bao read -field=role_id auth/approle/role/flow/role-id)" \
  --from-literal=secret_id="$(bao write -f -field=secret_id auth/approle/role/flow/secret-id)"
```

```sh
helm install flow deploy/helm/umbrella-flow \
  --set image.repository=registry.example.com/umbrella-flow --set image.tag=1.0.0 \
  --set openbao.addr=http://openbao.vault:8200 --set openbao.existingSecret=flow-openbao \
  --set postgres.host=pg.db --set clickhouse.addr=clickhouse.db:9000
```

Then open the console (`kubectl port-forward svc/flow-umbrella-flow 8080:8080` or the ingress) and finish the setup
wizard; it is prefilled from the values, and the setup code is in the pod log (`setup_code=`). The wizard writes
`flow.json` (no secrets, only references) to the data volume.

Evaluation without external services: `--set dev.enabled=true` adds single-replica PostgreSQL, ClickHouse, NATS and
an OpenBao **dev server** (in memory, seeded with generated passwords). Everything stored in that OpenBao, including
Flow's own keys and password hashes, is lost when its pod restarts: never use it for real data.

## Roles

| `roles.mode` | Deployments | Services |
|---|---|---|
| `all` | `<release>-umbrella-flow` (collector, enricher, detector, API) | HTTP, flows (UDP), BMP (TCP) → the same pods |
| `split` | `-api`, `-collector`, `-enricher`, `-detector` | HTTP → api, flows → collector, BMP → enricher |

`split` needs NATS JetStream (`nats.url`) between the collector and the enricher, and every role needs `flow.json`:

- a shared volume: `persistence.accessModes: [ReadWriteMany]` (or `persistence.existingClaim` of such a volume), or
- `config.flowJson`: the file written by the wizard, copied into each pod by an init container. Install in `all`
  mode first, finish the wizard, then `kubectl exec deploy/<release>-umbrella-flow -- cat /data/flow.json` and
  upgrade with `--set roles.mode=split --set-file config.flowJson=flow.json`.

The BMP receiver and the gNMI / SNMP pollers run with the enricher. With several enricher replicas, each replica shares
its BMP sessions with the others over NATS JetStream (stream `FLOW_BMP`), so every replica knows every router's
routes. Configure each router with one BMP station (the BMP service address) so it has one session at a time. gNMI
profiles in `subscribe` mode open one stream per device from every enricher replica.

## Ports and services

| Port | Protocol | Service | What |
|---|---|---|---|
| 8080 | TCP | `<release>-umbrella-flow` | web console, API, `/metrics`, `/healthz` |
| 2055 | UDP | `<release>-umbrella-flow-flows` | NetFlow v5 / v9, IPFIX |
| 6343 | UDP | `<release>-umbrella-flow-flows` | sFlow v5 |
| 10179 | TCP | `<release>-umbrella-flow-bmp` | BMP, listened to only while enabled under Data collection → BMP routing |

Restrict who can reach the flow and BMP services with `service.*.loadBalancerSourceRanges` (BMP is
unauthenticated; Data collection → BMP routing also takes a list of allowed routers).

Probes use `/healthz` on the HTTP port for every role.

## Main values

| Value | Default | Meaning |
|---|---|---|
| `image.repository`, `image.tag` | `umbrella-flow`, appVersion | Flow image |
| `roles.mode` | `all` | `all` or `split` |
| `roles.<role>.replicas`, `.resources` | see `values.yaml` | per Deployment |
| `openbao.addr`, `.mount`, `.auth`, `.existingSecret` | `""`, `flow`, `approle`, `""` | OpenBao; the Secret holds `role_id` + `secret_id` (approle) or `token`, mounted at `/run/openbao` |
| `postgres.*`, `clickhouse.*`, `nats.*` | | connection prefill; `*Ref` are `openbao://` references |
| `config.language`, `.timezone`, `.publicURL` | `ru`, `UTC`, `""` | wizard prefill |
| `config.secureCookies`, `.trustedProxies` | `false`, `""` | behind an HTTPS ingress / proxy |
| `config.flowJson` | `""` | `flow.json` for split-mode pods without a shared volume |
| `config.setupTokenSecret` | `""` | Secret (key `token`) with a fixed setup code |
| `config.extraEnv`, `extraVolumes`, `extraVolumeMounts` | | e.g. GeoIP databases (`config.geoipDatabases`) |
| `service.flows.*`, `service.bmp.*` | LoadBalancer, `Local` | UDP / TCP exposure |
| `ingress.*` | disabled | HTTP ingress |
| `persistence.*` | 1 Gi RWO | data directory (`flow.json`, setup code) |
| `dev.enabled` | `false` | bundled dev services (see above) |

Pods run as the distroless `nonroot` user (65532) with a read-only root filesystem; `/data` and `/tmp` are volumes.

## Examples and checks

`ci/all-values.yaml` (all-in-one, external services) and `ci/split-values.yaml` (one Deployment per role, NATS, a
ReadWriteMany data volume, ingress with TLS) are example value files; both render cleanly:

```sh
helm lint deploy/helm/umbrella-flow
helm lint deploy/helm/umbrella-flow -f deploy/helm/umbrella-flow/ci/split-values.yaml
helm template flow deploy/helm/umbrella-flow -f deploy/helm/umbrella-flow/ci/split-values.yaml
helm template flow deploy/helm/umbrella-flow --set dev.enabled=true
```

The chart refuses to render inconsistent layouts: `roles.mode: split` without `nats.url` (or `dev.enabled`), and
`split` without a way for every role to read `flow.json` (`config.flowJson`, a ReadWriteMany volume or
`persistence.existingClaim`).
