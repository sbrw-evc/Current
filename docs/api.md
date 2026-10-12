# Umbrella Flow: REST API (контракт между backend и web)

Все пути под `/api`. Ответы JSON; ошибки — `{"error": "<код>", "message": "<текст>"}` с кодом HTTP 4xx/5xx.
Сессия — HttpOnly-cookie `flow_session`, изменяющие запросы несут `X-CSRF-Token` (значение `csrf` из
`/api/auth/login` и `/api/auth/me`), как в Umbrella. Время — RFC 3339 UTC.

## Служебное

| Метод | Путь | Ответ |
|---|---|---|
| GET | `/healthz` | `200 ok` |
| GET | `/metrics` | Prometheus |
| GET | `/api/version` | `{version, commit, built_at}` |

## Вход

| Метод | Путь | Тело / ответ |
|---|---|---|
| POST | `/api/auth/login` | `{username, password}` → `{user, csrf}` |
| POST | `/api/auth/logout` | — |
| GET | `/api/auth/me` | `{user: {id, username, name, role, permissions: ["visualize:view", …]}, csrf}` или 401 |

## Мастер настройки

| Метод | Путь | Тело / ответ |
|---|---|---|
| GET | `/api/setup` | `{required: bool}` |
| POST | `/api/setup` | `{setup_code, postgres: {dsn}, clickhouse: {addr, database, username, password}, admin: {username, password}}` → `{ok}` |

## Схема колонок

`GET /api/schema` → `{columns: [{name, kind, dimension, rollup, reverse, metric}]}` — из `internal/schema`.

## Visualize

`POST /api/visualize` (право `visualize:view`)

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

- `units`: `l3bps` (бит/с L3), `l2bps` (+ 18 байт заголовка Ethernet на пакет), `pps`, `inl2%` / `outl2%`
  (процент от скорости входного / выходного интерфейса).
- `graph`: `stacked`, `lines`, `grid` — временной ряд; `sankey` — без времени.
- `limit`: 1–50; остальные значения сводятся в строку `["Other", …]`.
- Пустой `dimensions` — один ряд «Total».

Ответ для временного ряда:

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

`axis`: 1 — прямое направление, 2 — обратное (только при `bidirectional`, ряды с осью 2 имеют
значения со знаком «+», web рисует их ниже нуля). `resolution`: таблица, по которой посчитано (`raw`, `1m`, `5m`,
`1h`). `sql` — для отладки (показывается в интерфейсе по кнопке).

Ответ для `sankey`:

```json
{
  "rows": [["AS65000", "edge-01"]],
  "xps": [123456.0],
  "nodes": ["SrcAS: AS65000", "ExporterName: edge-01"],
  "links": [{"source": "SrcAS: AS65000", "target": "ExporterName: edge-01", "xps": 123456.0}]
}
```

## Фильтр

| Метод | Путь | Тело / ответ |
|---|---|---|
| POST | `/api/filter/validate` | `{filter}` → `{valid: bool, errors: [{line, column, offset, message}], parsed: "<нормализованный текст>"}` |
| POST | `/api/filter/complete` | `{what: "column"\|"operator"\|"value", column?, prefix}` → `{completions: [{label, detail, quoted}]}` |

Язык фильтров: `Column op value`, `AND`, `OR`, `NOT`, скобки; строки в `'…'` или `"…"`; операторы для строк `=`, `!=`,
`IN (…)`, `NOTIN (…)`, `LIKE`, `UNLIKE`, `ILIKE`, `IUNLIKE`; для IP `=`, `!=`, `<<` (в префиксе, `SrcAddr << 10.0.0.0/8`),
`IN`; для чисел `=`, `!=`, `<`, `<=`, `>`, `>=`, `IN`; специальные `SrcAS = AS65000`, `Proto = tcp`. Комментарии
`-- …` и `/* … */`.

## Сохранённые виды

| Метод | Путь | |
|---|---|---|
| GET | `/api/saved-views` | `{results: [{id, name, owner, shared, request}]}` |
| POST | `/api/saved-views` | `{name, shared, request}` |
| DELETE | `/api/saved-views/{id}` | |

## Экспортёры

`GET /api/exporters` → `{results: [{address, name, ref, site, role, last_seen, flows_per_second, sampling_rates: [..], interfaces: [{index, name, description, speed, boundary, provider, in_bps, out_bps}]}]}`

## Главная (виджеты)

`GET /api/widgets/summary` → `{flows_per_second, exporters, bps_in_external, bps_out_external}`  
`GET /api/widgets/top/{what}` (`src-as`, `dst-as`, `src-country`, `dst-country`, `app`, `exporter`, `src-port`, `dst-port`) → `{top: [{name, percent}]}`  
`GET /api/widgets/graph?points=200` → `{t: [], gbps: []}` — внешний трафик за 24 ч  
`GET /api/widgets/last-flow` → последний поток как объект `{Column: value}`

## Сырые потоки

`POST /api/flows/search` `{start, end, filter, limit (≤1000), order: "time"|"bytes"}` → `{columns: [..], rows: [[..]]}`

## Inventory DB

| Метод | Путь | |
|---|---|---|
| GET | `/api/inventory-db` | `{enabled, url, token_set, interval, last_sync: {at, ok, error, devices, interfaces, prefixes, circuits}}` |
| PUT | `/api/inventory-db` | `{enabled, url, token?, interval}` — токен уходит в OpenBao |
| POST | `/api/inventory-db/test` | `{ok, error?}` |
| POST | `/api/inventory-db/sync` | `{ok, stats}` |
| GET | `/api/inventory-db/unknown` | `{exporters: [{address, last_seen}], addresses: [{address, bytes}]}` |

## Классификаторы

`GET|PUT /api/classifiers` → `{exporter: [CEL…], interface: [CEL…]}`; `POST /api/classifiers/preview` `{kind, rules, sample}` → результат.
