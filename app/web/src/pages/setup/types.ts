// The first-run wizard (docs/api.md, "Мастер первичной настройки").

export type SetupTheme = 'light' | 'dark' | 'system'
export type TestStep = 'openbao' | 'postgres' | 'clickhouse' | 'nats' | 'inventory' | 'umbrella' | 'geoip' | 'spa'

export type OpenBao = { addr: string; mount: string; auth: 'token' | 'approle'; token: string; role_id: string; secret_id: string }
export type Postgres = { host: string; port: number; database: string; username: string; password: string; sslmode: string; attach_existing: boolean }
export type ClickHouse = { addr: string; database: string; username: string; password: string; secure: boolean }
export type Retention = { raw_days: number; d1m: number; d5m: number; d1h: number }
export type Nats = { url: string }
export type Collector = { netflow_addr: string; sflow_addr: string; default_sampling_rate: number }
export type Inventory = { enabled: boolean; url: string; token: string; interval: string }
export type Umbrella = { enabled: boolean; ingest_url: string; token: string }
export type GeoIP = { databases: string[] }
// Spa: the connection key SPA shows (spa1.…); optional when the deployment gives SPA_CONNECTION_KEY.
export type Spa = { connection_key: string }

export type SetupDefaults = {
  language?: 'ru' | 'en'
  theme?: SetupTheme
  timezone?: string
  public_url?: string
  openbao?: Partial<Omit<OpenBao, 'token' | 'secret_id'>> & { token_set?: boolean; role_id_set?: boolean; secret_id_set?: boolean }
  postgres?: Partial<Omit<Postgres, 'password' | 'attach_existing'>> & { password_set?: boolean }
  clickhouse?: Partial<Omit<ClickHouse, 'password'>> & { password_set?: boolean; retention?: Partial<Retention> }
  nats?: Partial<Nats>
  collector?: Partial<Collector>
  spa?: { from_env?: boolean }
}

export type SetupInfo = { required: boolean; defaults?: SetupDefaults }

export type SetupBody = {
  setup_code: string
  language: 'ru' | 'en'
  theme: SetupTheme
  timezone: string
  public_url: string
  openbao: Partial<OpenBao>
  postgres: Partial<Postgres>
  clickhouse: Partial<ClickHouse>
  retention: Retention
  nats: Nats
  collector: Collector
  inventory: Partial<Inventory>
  umbrella: Partial<Umbrella>
  geoip: GeoIP
  spa?: Spa
}

export type TestResult = { ok: boolean; error?: string; details?: Record<string, unknown> }
