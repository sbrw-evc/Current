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
		{RoleAdministrator, roleAdministratorDescr, All()},
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
