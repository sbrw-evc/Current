import type { Catalog, RoleRecord } from '../pages/settings/RolesModel'
import { normalize } from '../pages/settings/RolesModel'

// Mock (VITE_MOCK=1) of the permission catalogue (GET /api/access/catalog, a copy of
// internal/access) and of the roles (/api/roles): built-in roles are read-only, a custom role gets
// its ident from the name once, a role given to people cannot be deleted. The real server
// republishes the role catalogue to Keystone after each change.

type Reply = { status: number; body?: unknown }
const ok = (body: unknown, status = 200): Reply => ({ status, body })
const fail = (status: number, error: string, message?: string): Reply => ({ status, body: { error, message } })
const now = () => new Date().toISOString()

export const catalog: Catalog = {
  groups: [
    { id: 'traffic', title: { en: 'Traffic', ru: 'Трафик' } },
    { id: 'network', title: { en: 'Network', ru: 'Сеть' } },
    { id: 'org', title: { en: 'Organization', ru: 'Организация' } },
    { id: 'settings', title: { en: 'Settings', ru: 'Настройки' } },
  ],
  pages: [
    { id: 'visualize', group: 'traffic', title: { en: 'Visualize', ru: 'Визуализация' }, features: [{ id: 'view', title: { en: 'Build traffic graphs, use the home widgets and saved views', ru: 'Графики трафика, виджеты главной и сохранённые виды' } }] },
    { id: 'flows', group: 'traffic', title: { en: 'Flows', ru: 'Потоки' }, features: [{ id: 'view', title: { en: 'Search raw flow records', ru: 'Поиск по сырым потокам' } }] },
    { id: 'exporters', group: 'traffic', title: { en: 'Exporters', ru: 'Экспортёры' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change sampling rate overrides', ru: 'Изменение переопределений частоты сэмплирования' } }] },
    { id: 'detector', group: 'traffic', title: { en: 'Detector', ru: 'Детектор' }, features: [{ id: 'view', title: { en: 'See detection rules, active alerts and the Beacon outbox', ru: 'Правила обнаружения, активные оповещения и очередь в Beacon' } }, { id: 'edit', title: { en: 'Change detection rules', ru: 'Изменение правил обнаружения' } }] },
    { id: 'devices', group: 'network', title: { en: 'Network devices', ru: 'Сетевые устройства' }, features: [{ id: 'view', title: { en: 'See managed devices, their clients and the network map', ru: 'Управляемые устройства, их клиенты и карта сети' } }, { id: 'edit', title: { en: 'Add, change and delete devices and their credentials, test connections, run discovery, name clients, arrange the map', ru: 'Добавление, изменение и удаление устройств и их учётных данных, проверка подключения, поиск устройств, имена клиентов, раскладка карты' } }, { id: 'operate', title: { en: 'Poll now, change the device name, interfaces, DNS, NTP and flow export, block clients', ru: 'Опрос, изменение имени устройства, интерфейсов, DNS, NTP и экспорта потоков, блокировка клиентов' } }, { id: 'admin', title: { en: 'Reboot devices, run CLI commands and download configuration backups', ru: 'Перезагрузка, произвольные команды CLI и выгрузка резервных копий конфигурации' } }] },
    { id: 'users', group: 'org', title: { en: 'Users', ru: 'Пользователи' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Synchronize users with Keystone now and manage the saved views of others (people and their roles are managed in Keystone)', ru: 'Синхронизация пользователей с Keystone и управление чужими сохранёнными видами (люди и их роли управляются в Keystone)' } }] },
    { id: 'roles', group: 'org', title: { en: 'Roles', ru: 'Роли' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Create, change and delete', ru: 'Создание, изменение и удаление' } }] },
    { id: 'settings.inventory', group: 'settings', title: { en: 'Ledger', ru: 'Ledger' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change and check the connection', ru: 'Изменение и проверка подключения' } }, { id: 'sync', title: { en: 'Run synchronization', ru: 'Запуск синхронизации' } }] },
    { id: 'settings.classifiers', group: 'settings', title: { en: 'Classifiers', ru: 'Классификаторы' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change exporter and interface classification rules', ru: 'Изменение правил классификации экспортёров и интерфейсов' } }] },
    { id: 'settings.general', group: 'settings', title: { en: 'General', ru: 'Общие' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change language, theme, time zone, Current address, password policy and GeoIP databases', ru: 'Изменение языка, темы, часового пояса, адреса Current, парольной политики и баз GeoIP' } }] },
    { id: 'settings.umbrella', group: 'settings', title: { en: 'Beacon', ru: 'Beacon' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change and check the connection to Beacon', ru: 'Изменение и проверка подключения к Beacon' } }] },
    { id: 'settings.openbao', group: 'settings', title: { en: 'OpenBao', ru: 'OpenBao' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'test', title: { en: 'Check the connection', ru: 'Проверка подключения' } }, { id: 'migrate', title: { en: 'Move the secrets to another OpenBao', ru: 'Перенос секретов в другой OpenBao' } }] },
    { id: 'tokens', group: 'settings', title: { en: 'API tokens', ru: 'API-токены' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Create service accounts, issue and revoke tokens', ru: 'Создание сервисных учётных записей, выпуск и отзыв токенов' } }] },
    { id: 'integrations.inventory', group: 'settings', title: { en: 'Ledger integration', ru: 'Интеграция с Ledger' }, features: [{ id: 'read', title: { en: 'Traffic of DCIM objects and prefixes for Ledger', ru: 'Трафик объектов DCIM и префиксов для Ledger' } }] },
    { id: 'dependencies', group: 'traffic', title: { en: 'Dependencies', ru: 'Зависимости' }, features: [{ id: 'view', title: { en: 'See the CI dependencies discovered from traffic and the runs', ru: 'Зависимости КЕ, найденные по трафику, и запуски' } }, { id: 'run', title: { en: 'Run discovery and send the proposals to Beacon', ru: 'Запуск поиска и отправка предложений в Beacon' } }] },
    { id: 'scope', group: 'traffic', title: { en: 'Visibility scope', ru: 'Область видимости' }, features: [{ id: 'umbrella', title: { en: 'Restrict traffic to the CIs and services visible in Beacon', ru: 'Ограничить трафик КЕ и сервисами, видимыми в Beacon' } }] },
    { id: 'settings.snmp', group: 'settings', title: { en: 'SNMP', ru: 'SNMP' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change SNMP credentials and polled devices, poll a device', ru: 'Изменение учётных данных SNMP и опрашиваемых устройств, проверочный опрос' } }] },
    { id: 'settings.gnmi', group: 'settings', title: { en: 'gNMI', ru: 'gNMI' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change gNMI credentials and polled devices, poll a device', ru: 'Изменение учётных данных gNMI и опрашиваемых устройств, проверочный опрос' } }] },
    { id: 'settings.bmp', group: 'settings', title: { en: 'BMP routing', ru: 'Маршруты BMP' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change the BMP receiver settings', ru: 'Изменение настроек приёма BMP' } }] },
    { id: 'settings.rdns', group: 'settings', title: { en: 'Reverse DNS', ru: 'Обратный DNS' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change the reverse DNS resolution settings', ru: 'Изменение настроек обратного разрешения имён' } }] },
    { id: 'settings.threat', group: 'settings', title: { en: 'Threat intelligence', ru: 'Списки угроз' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Change the threat lists and refresh them', ru: 'Изменение списков угроз и их обновление' } }] },
    { id: 'settings.flowlogs', group: 'settings', title: { en: 'Cloud flow logs', ru: 'Облачные журналы потоков' }, features: [{ id: 'view', title: { en: 'View the page', ru: 'Просмотр страницы' } }, { id: 'edit', title: { en: 'Enable AWS / Azure / GCP flow log ingestion and set the tokens', ru: 'Включение приёма журналов потоков AWS / Azure / GCP и токены' } }] },
    { id: 'status', group: 'settings', title: { en: 'System status', ru: 'Состояние системы' }, features: [{ id: 'view', title: { en: 'See component status and the audit log', ru: 'Состояние компонентов и журнал аудита' } }] },
  ],
}

const all = (): string[] => catalog.pages.flatMap((p) => p.features.map((f) => `${p.id}:${f.id}`))

export const roles: RoleRecord[] = [
  { id: 1, ident: 'admin', name: 'Administrator', description: 'All permissions', builtin: true, permissions: all().filter((p) => p !== 'scope:umbrella'), users: 1 },
  { id: 2, ident: 'viewer', name: 'Viewer', description: 'Traffic pages: visualize, flows, exporters', builtin: true, permissions: ['visualize:view', 'flows:view', 'exporters:view'], users: 1 },
  { id: 3, ident: 'inventory-db-integration', name: 'Ledger integration', description: '', builtin: false, permissions: ['integrations.inventory:read'], users: 0 },
  {
    id: 4, ident: 'noc-umbrella-scope', name: 'NOC (Beacon scope)', description: 'Traffic of the CIs visible in Beacon', builtin: false,
    permissions: ['visualize:view', 'flows:view', 'exporters:view', 'detector:view', 'scope:umbrella'], users: 1,
  },
]

// The ident Keystone knows the role by, as store.identFor makes it.
export function identFor(name: string, taken: (s: string) => boolean): string {
  let base = name.toLowerCase().replace(/[^a-z0-9_.:]+/g, '-').replace(/^-+|-+$/g, '')
  if (base.length > 56) base = base.slice(0, 56).replace(/-+$/, '')
  if (!base || base === 'admin' || base === 'viewer') base = 'role'
  let ident = base
  for (let n = 2; taken(ident) || ident === 'role'; n++) ident = `${base}-${n}`
  return ident
}

function input(b: Record<string, unknown>): { name: string; description: string; permissions: string[] } | Reply {
  const name = String(b.name ?? '').trim()
  if (!name || name.length > 64) return fail(400, 'invalid_name', 'the role name must have 1-64 characters')
  const perms = Array.isArray(b.permissions) ? b.permissions.map(String) : []
  const bad = perms.find((p) => !all().includes(p))
  if (bad) return fail(400, 'invalid_permission', 'unknown permission ' + bad)
  return { name, description: String(b.description ?? '').trim(), permissions: normalize(catalog, perms) }
}

// rolesMock answers the paths it knows, null otherwise.
export function rolesMock(method: string, p: string, body: unknown): Reply | null {
  const b = (body ?? {}) as Record<string, unknown>
  if (p === '/api/access/catalog' && method === 'GET') return ok(catalog)
  if (p === '/api/roles' && method === 'GET') return ok({ results: roles })
  if (p === '/api/roles' && method === 'POST') {
    const v = input(b)
    if ('status' in v) return v
    if (roles.some((r) => r.name === v.name)) return fail(409, 'conflict', 'the name is taken')
    const r: RoleRecord = { id: Math.max(0, ...roles.map((x) => x.id)) + 1, ident: identFor(v.name, (s) => roles.some((x) => x.ident === s)), builtin: false, users: 0, created_at: now(), updated_at: now(), ...v }
    roles.push(r)
    return ok(r, 201)
  }
  const m = /^\/api\/roles\/(\d+)$/.exec(p)
  if (!m) return null
  const i = roles.findIndex((r) => r.id === Number(m[1]))
  if (i < 0) return fail(404, 'not_found', 'not found')
  const role = roles[i]
  if ((method === 'PUT' || method === 'DELETE') && role.builtin) return fail(409, 'builtin_role', 'built-in roles cannot be changed or deleted')
  if (method === 'PUT') {
    const v = input(b)
    if ('status' in v) return v
    if (roles.some((r) => r.name === v.name && r.id !== role.id)) return fail(409, 'conflict', 'the name is taken')
    Object.assign(role, v, { updated_at: now() })
    return ok(role)
  }
  if (method === 'DELETE') {
    if (role.users > 0) return fail(409, 'role_in_use', 'the role is assigned to users')
    roles.splice(i, 1)
    return ok({ ok: true })
  }
  return null
}
