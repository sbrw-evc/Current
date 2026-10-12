package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Extension points. Other packages (query, filter, enrich, inventory,
// classifier, collector) implement these small interfaces and cmd/flow wires
// them into Deps. A nil dependency makes its endpoints answer
// 501 {"error": "not_implemented"}.
//
// Errors: return an error with HTTPStatus() int (and optionally
// ErrorCode() string), e.g. httpx.BadRequest("invalid_filter", "…"), to
// answer 4xx; any other error is a 500 "internal". The returned value is
// written as JSON as is, so it must follow docs/api.md.

// Visualizer answers POST /api/visualize. req is the request body as sent by
// the console (see docs/api.md, "Visualize").
type Visualizer interface {
	Visualize(ctx context.Context, req json.RawMessage) (any, error)
}

// FilterService answers POST /api/filter/validate ({filter} →
// {valid, errors, parsed}) and POST /api/filter/complete ({what, column?,
// prefix} → {completions}).
type FilterService interface {
	Validate(ctx context.Context, req json.RawMessage) (any, error)
	Complete(ctx context.Context, req json.RawMessage) (any, error)
}

// FlowSearcher answers POST /api/flows/search.
type FlowSearcher interface {
	SearchFlows(ctx context.Context, req json.RawMessage) (any, error)
}

// ExporterLister answers GET /api/exporters → {results: [...]}.
type ExporterLister interface {
	Exporters(ctx context.Context) (any, error)
}

// Widgets answers GET /api/widgets/*.
type Widgets interface {
	Summary(ctx context.Context) (any, error)
	// Top: what is src-as, dst-as, src-country, dst-country, app, exporter, src-port or dst-port.
	Top(ctx context.Context, what string) (any, error)
	// Graph: external traffic for the last 24 h in points points.
	Graph(ctx context.Context, points int) (any, error)
	LastFlow(ctx context.Context) (any, error)
}

// InventoryConfig is the Inventory DB connection with the token resolved.
type InventoryConfig struct {
	URL      string
	Token    string
	Interval time.Duration
}

// InventorySyncer talks to Inventory DB. Sync loads devices, interfaces,
// prefixes and circuits into the enrichment dictionaries; the App records
// the result (store.RecordInventorySync) and runs it on schedule.
type InventorySyncer interface {
	Test(ctx context.Context, cfg InventoryConfig) error
	Sync(ctx context.Context, cfg InventoryConfig) (store.SyncStats, error)
	// Unknown → {exporters: [{address, last_seen}], addresses: [{address, bytes}]}.
	Unknown(ctx context.Context) (any, error)
}

// ClassifierService checks and previews CEL classification rules.
type ClassifierService interface {
	// Validate compiles the rules of a kind (exporter, interface); an error
	// should say which rule is wrong.
	Validate(kind string, rules []string) error
	// Preview runs rules against sample (an exporter or interface object) and
	// returns what they set.
	Preview(ctx context.Context, kind string, rules []string, sample json.RawMessage) (any, error)
}

// What changed, for Reloader.
const (
	ReloadClassifiers = "classifiers"
	ReloadInventory   = "inventory"
	ReloadSampling    = "sampling"
	ReloadGeoIP       = "geoip"    // settings key geoip: {databases}
	ReloadUmbrella    = "umbrella" // settings key umbrella: {enabled, ingest_url, token_ref}
	ReloadDetector    = "detector" // detection rules (table detector_rules)
)

// DetectorService is the traffic detector (internal/detector) as seen by the
// API: rule validation, the default rule set, the live status and the
// Umbrella test event.
type DetectorService interface {
	// DefaultRules returns the built-in rules, used while none were saved.
	DefaultRules() []json.RawMessage
	// ValidateRule checks one rule (detector.Rule as JSON) and returns its id;
	// errors should be 400s.
	ValidateRule(rule json.RawMessage) (id string, err error)
	// Status → the rules with their last evaluation, active alerts and the
	// Umbrella outbox (GET /api/detector/status).
	Status(ctx context.Context) (any, error)
	// SendTest posts a test event to an Umbrella ingest URL with the token.
	SendTest(ctx context.Context, url, token string) (any, error)
}

// Reloader is told when configuration it depends on has changed in
// PostgreSQL (the enricher re-reads classifiers, sampling overrides, the
// Inventory DB connection). Errors are logged, not returned to the client.
type Reloader interface {
	Reload(ctx context.Context, what string) error
}

// StatusReporter adds a component (collector, enricher, writer, bus…) to
// GET /api/status. The value is written as JSON.
type StatusReporter interface {
	Status(ctx context.Context) any
}

// Pinger checks a connection (the ClickHouse driver.Conn implements it).
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the HTTP application.
type Deps struct {
	Config config.File
	Store  *store.Store
	Vault  *secrets.Client // required: every secret lives in OpenBao

	ClickHouse  Pinger
	Visualizer  Visualizer
	Filter      FilterService
	Flows       FlowSearcher
	Exporters   ExporterLister
	Widgets     Widgets
	Inventory   InventorySyncer
	Classifiers ClassifierService
	Detector    DetectorService
	Reloaders   []Reloader
	Components  map[string]StatusReporter

	// Gatherer serves /metrics; nil = prometheus.DefaultGatherer.
	Gatherer prometheus.Gatherer
}
