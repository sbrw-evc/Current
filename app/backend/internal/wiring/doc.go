// Package wiring connects the pipeline and traffic packages to each other and
// to the HTTP application (internal/app): it builds the bus, the collector,
// the enricher with its reloadable sources (Ledger, classifiers, GeoIP),
// the ClickHouse writer, the detector, and the adapters that implement the
// app.Deps interfaces over internal/query, internal/filter,
// internal/inventory, internal/classifier and internal/detector.
//
// Process layout (FLOW_ROLE):
//
//   - all: collector → in-process bus (or NATS JetStream when configured) →
//     enricher → writer, plus the detector and the API, in one process. The
//     enricher reads interface names learned by the collector, and the
//     exporters API merges the collector registry (sampling rates, last seen,
//     flows/s, interface names) into the ClickHouse aggregates.
//   - collector: UDP → NATS JetStream (FLOW_NATS_URL is required). Without
//     flow.json it uses the exporters' own sampling rates (overrides are
//     applied only where the collector shares a process with the API).
//   - enricher: NATS JetStream → enricher → ClickHouse. Interface names
//     learned by a collector in another process are not available (IfNames
//     is nil); Ledger interfaces still name them.
//   - api, detector: no bus.
//
// Settings changed through the API reach components of the same process
// through app.Reloader; components in other processes poll PostgreSQL every
// minute.
package wiring
