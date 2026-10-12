package setup

import (
	"os"
	"strconv"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

// Defaults prefill the wizard. They come from FLOW_SETUP_DEFAULTS_*
// variables (the Docker stack sets them for the bundled services). Secrets
// are never given as values: passwords are openbao:// references (the
// openbao-init container seeds them), OpenBao credentials are file paths.
//
//	FLOW_SETUP_DEFAULTS_LANGUAGE, _THEME, _TIMEZONE, _PUBLIC_URL
//	FLOW_SETUP_DEFAULTS_OPENBAO_ADDR, _OPENBAO_MOUNT, _OPENBAO_AUTH, _OPENBAO_TOKEN_FILE,
//	  _OPENBAO_ROLE_ID_FILE, _OPENBAO_SECRET_ID_FILE
//	FLOW_SETUP_DEFAULTS_POSTGRES_HOST, _PORT, _DATABASE, _USERNAME, _SSLMODE, _PASSWORD_REF
//	FLOW_SETUP_DEFAULTS_CLICKHOUSE_ADDR, _DATABASE, _USERNAME, _SECURE, _PASSWORD_REF
//	FLOW_SETUP_DEFAULTS_NATS_URL, _NATS_TOKEN_REF
//	FLOW_SETUP_DEFAULTS_NETFLOW_ADDR, _SFLOW_ADDR (else FLOW_NETFLOW_ADDR / FLOW_SFLOW_ADDR)
//	FLOW_SETUP_DEFAULTS_GEOIP_DATABASES (comma-separated paths)
//	FLOW_SETUP_DEFAULTS_INVENTORY_URL, FLOW_SETUP_DEFAULTS_UMBRELLA_INGEST_URL
type Defaults struct {
	Language   string
	Theme      string
	Timezone   string
	PublicURL  string
	OpenBao    config.OpenBao
	Postgres   config.Postgres   // Password: openbao:// reference
	ClickHouse config.ClickHouse // Password: openbao:// reference
	NATS       config.NATS       // Token: openbao:// reference
	Collector  Collector
	GeoIP      []string
	Inventory  string
	Umbrella   string
}

// DefaultsFromEnv reads the defaults (getenv nil = os.Getenv).
func DefaultsFromEnv(getenv func(string) string) Defaults {
	if getenv == nil {
		getenv = os.Getenv
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv("FLOW_SETUP_DEFAULTS_" + k)); v != "" {
			return v
		}
		return def
	}
	ref := func(k string) string {
		v := get(k, "")
		if !secrets.IsRef(v) {
			return "" // never a plain secret from the environment
		}
		return v
	}
	port, _ := strconv.Atoi(get("POSTGRES_PORT", "5432"))
	d := Defaults{
		Language:  get("LANGUAGE", "ru"),
		Theme:     get("THEME", "system"),
		Timezone:  get("TIMEZONE", "UTC"),
		PublicURL: get("PUBLIC_URL", ""),
		OpenBao: config.OpenBao{Addr: get("OPENBAO_ADDR", ""), Mount: get("OPENBAO_MOUNT", secrets.DefaultMount), Auth: get("OPENBAO_AUTH", ""),
			TokenFile: get("OPENBAO_TOKEN_FILE", ""), RoleIDFile: get("OPENBAO_ROLE_ID_FILE", ""), SecretIDFile: get("OPENBAO_SECRET_ID_FILE", "")},
		Postgres: config.Postgres{Host: get("POSTGRES_HOST", ""), Port: port, Database: get("POSTGRES_DATABASE", "flow"),
			Username: get("POSTGRES_USERNAME", "flow"), SSLMode: get("POSTGRES_SSLMODE", "prefer"), Password: ref("POSTGRES_PASSWORD_REF")},
		ClickHouse: config.ClickHouse{Addr: get("CLICKHOUSE_ADDR", ""), Database: get("CLICKHOUSE_DATABASE", "flow"),
			Username: get("CLICKHOUSE_USERNAME", "default"), Secure: get("CLICKHOUSE_SECURE", "") == "true",
			Password: ref("CLICKHOUSE_PASSWORD_REF"), Retention: config.DefaultRetention},
		NATS: config.NATS{URL: get("NATS_URL", ""), Token: ref("NATS_TOKEN_REF")},
		Collector: Collector{NetFlowAddr: get("NETFLOW_ADDR", firstNonEmpty(getenv("FLOW_NETFLOW_ADDR"), ":2055")),
			SFlowAddr: get("SFLOW_ADDR", firstNonEmpty(getenv("FLOW_SFLOW_ADDR"), ":6343")), DefaultSamplingRate: 1},
		Inventory: get("INVENTORY_URL", ""),
		Umbrella:  get("UMBRELLA_INGEST_URL", ""),
	}
	for _, p := range strings.Split(get("GEOIP_DATABASES", ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			d.GeoIP = append(d.GeoIP, p)
		}
	}
	if d.OpenBao.Auth == "" && d.OpenBao.Addr != "" {
		if d.OpenBao.RoleIDFile != "" {
			d.OpenBao.Auth = config.AuthAppRole
		} else {
			d.OpenBao.Auth = config.AuthToken
		}
	}
	return d
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// view is GET /api/setup "defaults": no secret values, only *_set flags.
func (d Defaults) view() map[string]any {
	return map[string]any{
		"language": d.Language, "theme": d.Theme, "timezone": d.Timezone, "public_url": d.PublicURL,
		"openbao": map[string]any{"addr": d.OpenBao.Addr, "mount": d.OpenBao.Mount, "auth": d.OpenBao.Auth,
			"token_set": d.OpenBao.TokenFile != "", "role_id_set": d.OpenBao.RoleIDFile != "", "secret_id_set": d.OpenBao.SecretIDFile != ""},
		"postgres": map[string]any{"host": d.Postgres.Host, "port": d.Postgres.Port, "database": d.Postgres.Database,
			"username": d.Postgres.Username, "sslmode": d.Postgres.SSLMode, "password_set": d.Postgres.Password != ""},
		"clickhouse": map[string]any{"addr": d.ClickHouse.Addr, "database": d.ClickHouse.Database, "username": d.ClickHouse.Username,
			"secure": d.ClickHouse.Secure, "password_set": d.ClickHouse.Password != "", "retention": d.ClickHouse.Retention},
		"nats":      map[string]any{"url": d.NATS.URL, "token_set": d.NATS.Token != ""},
		"collector": d.Collector,
		"inventory": map[string]any{"enabled": false, "url": d.Inventory, "interval": "15m"},
		"umbrella":  map[string]any{"enabled": false, "ingest_url": d.Umbrella},
		"geoip":     map[string]any{"databases": nonNil(d.GeoIP)},
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
