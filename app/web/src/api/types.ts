// Types of the REST API (docs/api.md). Keep in sync with the contract.

export type Theme = 'light' | 'dark'
export type Locale = 'en' | 'ru'

export type Permission =
  | 'visualize:view'
  | 'flows:view'
  | 'exporters:view'
  | 'exporters:edit'
  | 'detector:view'
  | 'detector:edit'
  | 'settings.inventory:view'
  | 'settings.inventory:edit'
  | 'settings.classifiers:view'
  | 'settings.classifiers:edit'
  | 'settings.openbao:view'
  | 'settings.openbao:test'

export type User = { id: string; username: string; name: string; role: string; permissions: string[] }
export type Me = { user: User; csrf: string }


export type ColumnKind = 'string' | 'ip' | 'prefix' | 'uint' | 'time' | 'uint[]' | 'string[]'
export type Column = { name: string; kind: ColumnKind; dimension: boolean; rollup: boolean; reverse: string; metric: boolean }
export type Schema = { columns: Column[] }

export type Units = 'l3bps' | 'l2bps' | 'pps' | 'inl2%' | 'outl2%'
export type GraphType = 'stacked' | 'lines' | 'grid' | 'sankey'

export type VisualizeRequest = {
  start: string
  end: string
  points: number
  dimensions: string[]
  limit: number
  filter: string
  units: Units
  bidirectional: boolean
  graph: GraphType
}

export type TimeSeriesResult = {
  t: string[]
  rows: string[][]
  points: number[][]
  axis: number[]
  average: number[]
  min: number[]
  max: number[]
  p95: number[]
  resolution: string
  sql: string
}

export type SankeyResult = {
  rows: string[][]
  xps: number[]
  nodes: string[]
  links: { source: string; target: string; xps: number }[]
  sql?: string
}

export type FilterError = { line: number; column: number; offset: number; message: string }
export type ValidateResult = { valid: boolean; errors: FilterError[]; parsed: string }
export type CompleteRequest = { what: 'column' | 'operator' | 'value'; column?: string; prefix: string }
export type Completion = { label: string; detail?: string; quoted?: boolean }
export type CompleteResult = { completions: Completion[] }

export type SavedView = { id: string; name: string; owner: string; shared: boolean; request: unknown }

export type Interface = {
  index: number
  name: string
  description: string
  speed: number
  boundary: string
  provider: string
  in_bps: number
  out_bps: number
}
export type Exporter = {
  address: string
  name: string
  ref: string
  site: string
  role: string
  last_seen: string
  flows_per_second: number
  sampling_rates: number[]
  interfaces: Interface[]
}

export type Summary = { flows_per_second: number; exporters: number; bps_in_external: number; bps_out_external: number }
export type TopWhat = 'src-as' | 'dst-as' | 'src-country' | 'dst-country' | 'app' | 'exporter' | 'src-port' | 'dst-port'
export type Top = { top: { name: string; percent: number }[] }
export type Graph24 = { t: string[]; gbps: number[] }
export type LastFlow = Record<string, string | number>

export type FlowsRequest = { start: string; end: string; filter: string; limit: number; order: 'time' | 'bytes' }
export type FlowsResult = { columns: string[]; rows: (string | number)[][] }

export type SyncStats = { devices: number; interfaces: number; prefixes: number; circuits: number }
export type InventoryDB = {
  enabled: boolean
  url: string
  token_set: boolean
  interval: string
  last_sync: ({ at: string; ok: boolean; error?: string } & SyncStats) | null
}
export type InventoryDBUpdate = { enabled: boolean; url: string; token?: string; interval: string }
export type Unknown = { exporters: { address: string; last_seen: string }[]; addresses: { address: string; bytes: number }[] }

export type ClassifierKind = 'exporter' | 'interface'
export type Classifiers = { exporter: string[]; interface: string[] }
export type ClassifierPreview = { kind: ClassifierKind; rules: string[]; sample: unknown }
