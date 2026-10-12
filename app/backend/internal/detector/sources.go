package detector

import (
	"net/netip"
	"time"
)

// ExporterSeen is one exporter known to the collector registry.
type ExporterSeen struct {
	Address  netip.Addr
	Name     string // optional; filled from the flows when empty
	Ref      string // Inventory DB source_ref; optional
	LastSeen time.Time
}

// ExporterSource lists the exporters with their last-seen time (the
// collector registry). Without it the detector uses the flows in ClickHouse.
type ExporterSource interface {
	Exporters() []ExporterSeen
}

// ExporterFunc adapts a function to ExporterSource.
type ExporterFunc func() []ExporterSeen

func (f ExporterFunc) Exporters() []ExporterSeen { return f() }

// IfaceKey identifies an interface for the commit lookup.
type IfaceKey struct {
	Exporter     netip.Addr
	ExporterName string
	ExporterRef  string // Inventory DB source_ref of the device
	Interface    string // interface name
	Circuit      string // circuit ID (InIfCircuit / OutIfCircuit), may be empty
}

// CommitSource returns the commit rate (bits per second) of the circuit on
// an interface; ok false (or 0) when there is none. The coordinator wires
// the Inventory DB snapshot (circuits.commit_rate).
type CommitSource interface {
	Commit(k IfaceKey) (bps uint64, ok bool)
}

// CommitFunc adapts a function to CommitSource.
type CommitFunc func(k IfaceKey) (uint64, bool)

func (f CommitFunc) Commit(k IfaceKey) (uint64, bool) { return f(k) }
