// Package access is the permission catalog: permissions are "<page>:<function>",
// as in Umbrella Monitoring, and roles are sets of them.
package access

import (
	"slices"
	"strings"
)

type Text struct {
	EN string `json:"en"`
	RU string `json:"ru"`
}

type Feature struct {
	ID    string `json:"id"`
	Title Text   `json:"title"`
}

type Page struct {
	ID       string    `json:"id"`
	Group    string    `json:"group"`
	Title    Text      `json:"title"`
	Features []Feature `json:"features"`
}

type Group struct {
	ID    string `json:"id"`
	Title Text   `json:"title"`
}

const (
	View = "view"

	GroupTraffic  = "traffic"
	GroupOrg      = "org"
	GroupSettings = "settings"
)

// Permissions used by the handlers.
const (
	VisualizeView          = "visualize:view"
	FlowsView              = "flows:view"
	ExportersView          = "exporters:view"
	ExportersEdit          = "exporters:edit"
	DetectorView           = "detector:view"
	DetectorEdit           = "detector:edit"
	InventoryView          = "settings.inventory:view"
	InventoryEdit          = "settings.inventory:edit"
	InventorySync          = "settings.inventory:sync"
	ClassifiersView        = "settings.classifiers:view"
	ClassifiersEdit        = "settings.classifiers:edit"
	UsersView              = "users:view"
	UsersEdit              = "users:edit"
	RolesView              = "roles:view"
	RolesEdit              = "roles:edit"
	StatusView             = "status:view"
	GeneralView            = "settings.general:view"
	GeneralEdit            = "settings.general:edit"
	UmbrellaView           = "settings.umbrella:view"
	UmbrellaEdit           = "settings.umbrella:edit"
	OpenBaoView            = "settings.openbao:view"
	OpenBaoTest            = "settings.openbao:test"
	RoleAdministrator      = "Administrator"
	RoleViewer             = "Viewer"
	roleAdministratorDescr = "All permissions"
)

// Permissions of API tokens, integrations and visibility scopes.
const (
	OpenBaoMigrate = "settings.openbao:migrate"
	TokensView     = "tokens:view"
	TokensEdit     = "tokens:edit"
	// IntegrationsInventoryRead: the Inventory DB integration calls
	// /api/integrations/inventory-db/* with a token of this role.
	IntegrationsInventoryRead = "integrations.inventory:read"
	// ScopeUmbrella restricts every traffic query of the user to the
	// visibility scope Umbrella gives for their login (a restriction, not a
	// right: the Administrator role does not get it).
	ScopeUmbrella = "scope:umbrella"
	// Dependency discovery for Umbrella's CMDB (docs/integrations.md §3.3).
	DependenciesView = "dependencies:view"
	DependenciesRun  = "dependencies:run"
)

// Permissions of the SNMP poller and BMP receiver settings.
const (
	SNMPView = "settings.snmp:view"
	SNMPEdit = "settings.snmp:edit"
	BMPView  = "settings.bmp:view"
	BMPEdit  = "settings.bmp:edit"
)

// Permissions of the enrichment extensions and cloud flow log ingestion.
const (
	RDNSView     = "settings.rdns:view"
	RDNSEdit     = "settings.rdns:edit"
	ThreatView   = "settings.threat:view"
	ThreatEdit   = "settings.threat:edit"
	FlowLogsView = "settings.flowlogs:view"
	FlowLogsEdit = "settings.flowlogs:edit"
)

var (
	view = Feature{View, Text{"View the page", "Просмотр страницы"}}
	edit = Feature{"edit", Text{"Create, change and delete", "Создание, изменение и удаление"}}
)

var groups = []Group{
	{GroupTraffic, Text{"Traffic", "Трафик"}},
	{GroupOrg, Text{"Organization", "Организация"}},
	{GroupSettings, Text{"Settings", "Настройки"}},
}

var pages = []Page{
	{"visualize", GroupTraffic, Text{"Visualize", "Визуализация"}, []Feature{
		{View, Text{"Build traffic graphs, use the home widgets and saved views", "Графики трафика, виджеты главной и сохранённые виды"}},
	}},
	{"flows", GroupTraffic, Text{"Flows", "Потоки"}, []Feature{
		{View, Text{"Search raw flow records", "Поиск по сырым потокам"}},
	}},
	{"exporters", GroupTraffic, Text{"Exporters", "Экспортёры"}, []Feature{
		view,
		{"edit", Text{"Change sampling rate overrides", "Изменение переопределений частоты сэмплирования"}},
	}},
	{"detector", GroupTraffic, Text{"Detector", "Детектор"}, []Feature{
		{View, Text{"See detection rules, active alerts and the Umbrella outbox", "Правила обнаружения, активные оповещения и очередь в Umbrella"}},
		{"edit", Text{"Change detection rules", "Изменение правил обнаружения"}},
	}},
	{"users", GroupOrg, Text{"Users", "Пользователи"}, []Feature{
		view,
		{"edit", Text{"Create, change, lock and delete users, set passwords, configure LDAP / AD", "Создание, изменение, блокировка и удаление пользователей, пароли, настройка LDAP / AD"}},
	}},
	{"roles", GroupOrg, Text{"Roles", "Роли"}, []Feature{view, edit}},
	{"settings.inventory", GroupSettings, Text{"Inventory DB", "Inventory DB"}, []Feature{
		view,
		{"edit", Text{"Change and check the connection", "Изменение и проверка подключения"}},
		{"sync", Text{"Run synchronization", "Запуск синхронизации"}},
	}},
	{"settings.classifiers", GroupSettings, Text{"Classifiers", "Классификаторы"}, []Feature{
		view,
		{"edit", Text{"Change exporter and interface classification rules", "Изменение правил классификации экспортёров и интерфейсов"}},
	}},
	{"settings.general", GroupSettings, Text{"General", "Общие"}, []Feature{
		view,
		{"edit", Text{"Change language, theme, time zone, Flow address, password policy and GeoIP databases", "Изменение языка, темы, часового пояса, адреса Flow, парольной политики и баз GeoIP"}},
	}},
	{"settings.umbrella", GroupSettings, Text{"Umbrella", "Umbrella"}, []Feature{
		view,
		{"edit", Text{"Change and check the connection to Umbrella", "Изменение и проверка подключения к Umbrella"}},
	}},
	{"settings.openbao", GroupSettings, Text{"OpenBao", "OpenBao"}, []Feature{
		view,
		{"test", Text{"Check the connection", "Проверка подключения"}},
		{"migrate", Text{"Move the secrets to another OpenBao", "Перенос секретов в другой OpenBao"}},
	}},
	{"tokens", GroupSettings, Text{"API tokens", "API-токены"}, []Feature{
		view,
		{"edit", Text{"Create service accounts, issue and revoke tokens", "Создание сервисных учётных записей, выпуск и отзыв токенов"}},
	}},
	{"integrations.inventory", GroupSettings, Text{"Inventory DB integration", "Интеграция с Inventory DB"}, []Feature{
		{"read", Text{"Traffic of DCIM objects and prefixes for Inventory DB", "Трафик объектов DCIM и префиксов для Inventory DB"}},
	}},
	{"dependencies", GroupTraffic, Text{"Dependencies", "Зависимости"}, []Feature{
		{View, Text{"See the CI dependencies discovered from traffic and the runs", "Зависимости КЕ, найденные по трафику, и запуски"}},
		{"run", Text{"Run discovery and send the proposals to Umbrella", "Запуск поиска и отправка предложений в Umbrella"}},
	}},
	{"scope", GroupTraffic, Text{"Visibility scope", "Область видимости"}, []Feature{
		{"umbrella", Text{"Restrict traffic to the CIs and services visible in Umbrella", "Ограничить трафик КЕ и сервисами, видимыми в Umbrella"}},
	}},
	{"settings.snmp", GroupSettings, Text{"SNMP", "SNMP"}, []Feature{
		view,
		{"edit", Text{"Change SNMP credentials and polled devices, poll a device", "Изменение учётных данных SNMP и опрашиваемых устройств, проверочный опрос"}},
	}},
	{"settings.bmp", GroupSettings, Text{"BMP routing", "Маршруты BMP"}, []Feature{
		view,
		{"edit", Text{"Change the BMP receiver settings", "Изменение настроек приёма BMP"}},
	}},
	{"settings.rdns", GroupSettings, Text{"Reverse DNS", "Обратный DNS"}, []Feature{
		view,
		{"edit", Text{"Change the reverse DNS resolution settings", "Изменение настроек обратного разрешения имён"}},
	}},
	{"settings.threat", GroupSettings, Text{"Threat intelligence", "Списки угроз"}, []Feature{
		view,
		{"edit", Text{"Change the threat lists and refresh them", "Изменение списков угроз и их обновление"}},
	}},
	{"settings.flowlogs", GroupSettings, Text{"Cloud flow logs", "Облачные журналы потоков"}, []Feature{
		view,
		{"edit", Text{"Enable AWS / Azure / GCP flow log ingestion and set the tokens", "Включение приёма журналов потоков AWS / Azure / GCP и токены"}},
	}},
	{"status", GroupSettings, Text{"System status", "Состояние системы"}, []Feature{
		{View, Text{"See component status and the audit log", "Состояние компонентов и журнал аудита"}},
	}},
}

// BuiltinRole is a role created by the setup wizard and kept in sync on start.
type BuiltinRole struct {
	Name        string
	Description string
	Permissions []string
}

// BuiltinRoles are Administrator (everything) and Viewer (traffic pages).
func BuiltinRoles() []BuiltinRole {
	return []BuiltinRole{
		{RoleAdministrator, roleAdministratorDescr, slices.DeleteFunc(All(), func(p string) bool { return p == ScopeUmbrella })},
		{RoleViewer, "Traffic pages: visualize, flows, exporters", []string{VisualizeView, FlowsView, ExportersView}},
	}
}

func Groups() []Group { return slices.Clone(groups) }

func Pages() []Page { return slices.Clone(pages) }

func Perm(page, feature string) string { return page + ":" + feature }

var all, valid = func() ([]string, map[string]bool) {
	var out []string
	set := map[string]bool{}
	for _, p := range pages {
		for _, f := range p.Features {
			out = append(out, Perm(p.ID, f.ID))
			set[Perm(p.ID, f.ID)] = true
		}
	}
	return out, set
}()

// All lists every permission in catalog order.
func All() []string { return slices.Clone(all) }

// Valid reports whether perm is in the catalog.
func Valid(perm string) bool { return valid[perm] }

// Normalize drops unknown permissions, adds "<page>:view" for every page that
// has another function, and returns them in catalog order.
func Normalize(perms []string) []string {
	set := map[string]bool{}
	for _, p := range perms {
		p = strings.TrimSpace(p)
		if !Valid(p) {
			continue
		}
		set[p] = true
		page, _, _ := strings.Cut(p, ":")
		set[Perm(page, View)] = true
	}
	out := make([]string, 0, len(set))
	for _, p := range all {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}

// Set is a set of permissions.
type Set map[string]bool

func NewSet(perms []string) Set {
	s := Set{}
	for _, p := range perms {
		s[p] = true
	}
	return s
}

func (s Set) Has(perm string) bool { return s[perm] }

// Any reports whether s has at least one of perms.
func (s Set) Any(perms ...string) bool {
	for _, p := range perms {
		if s[p] {
			return true
		}
	}
	return false
}

// List returns the permissions in catalog order.
func (s Set) List() []string {
	out := []string{}
	for _, p := range all {
		if s[p] {
			out = append(out, p)
		}
	}
	return out
}
