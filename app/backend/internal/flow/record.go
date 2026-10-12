// Package flow holds the canonical flow record shared by the collector, the
// enricher, the bus and the ClickHouse writer.
package flow

import (
	"context"
	"net/netip"
	"time"
)

// Boundary of an interface: does traffic cross the edge of our network there.
const (
	BoundaryUndefined = ""
	BoundaryInternal  = "internal"
	BoundaryExternal  = "external"
)

// Flow is one flow record. The collector fills the "decoded" fields; the
// enricher fills the "enriched" ones. Bytes and Packets are as reported by
// the exporter; multiply by SamplingRate to get the real volume.
type Flow struct {
	// decoded
	TimeReceived    time.Time
	TimeFlowStart   time.Time
	TimeFlowEnd     time.Time
	SamplingRate    uint64
	ExporterAddress netip.Addr // source address of the UDP datagram (or agent address in sFlow)
	SequenceNum     uint32
	FlowType        string // "netflow5", "netflow9", "ipfix", "sflow"

	InIf, OutIf      uint32 // ifIndex
	SrcAddr          netip.Addr
	DstAddr          netip.Addr
	SrcNetMask       uint8
	DstNetMask       uint8
	NextHop          netip.Addr
	SrcAS, DstAS     uint32 // as reported by the exporter (0 = unknown)
	SrcPort          uint16
	DstPort          uint16
	Proto            uint8
	EType            uint16 // 0x0800 IPv4, 0x86dd IPv6
	TCPFlags         uint8
	IPTos            uint8
	ICMPType         uint8
	ICMPCode         uint8
	SrcVlan          uint16
	DstVlan          uint16
	ForwardingStatus uint8
	Bytes            uint64
	Packets          uint64

	// enriched: exporter (from Inventory DB device, classifiers)
	ExporterName   string
	ExporterRef    string // Inventory DB source_ref, e.g. "inventory-db:dcim.device:100"
	ExporterSite   string
	ExporterRegion string
	ExporterRole   string
	ExporterGroup  string
	ExporterTenant string

	// enriched: interfaces (from Inventory DB interfaces, circuits, cables, classifiers)
	InIfName          string
	InIfDescription   string
	InIfSpeed         uint64 // bits per second
	InIfBoundary      string // Boundary*
	InIfConnectivity  string // "transit", "peering", "ix", "pni", "customer", …
	InIfProvider      string
	InIfCircuit       string
	OutIfName         string
	OutIfDescription  string
	OutIfSpeed        uint64
	OutIfBoundary     string
	OutIfConnectivity string
	OutIfProvider     string
	OutIfCircuit      string

	// enriched: networks (from Inventory DB IPAM prefixes / addresses, GeoIP)
	SrcNetPrefix netip.Prefix
	SrcNetName   string
	SrcNetRole   string
	SrcNetSite   string
	SrcNetTenant string
	SrcNetVRF    string
	SrcHost      string // DNS name / device of the IPAM address
	SrcCI        string // Inventory DB source_ref of the device / VM owning SrcAddr
	SrcCountry   string // ISO 3166-1 alpha-2
	SrcCity      string
	DstNetPrefix netip.Prefix
	DstNetName   string
	DstNetRole   string
	DstNetSite   string
	DstNetTenant string
	DstNetVRF    string
	DstHost      string
	DstCI        string
	DstCountry   string
	DstCity      string

	// enriched: classification
	App string // application name ("https", "dns", vendor App-ID, …)

	// enriched: reverse DNS (PTR) of addresses without an Inventory DB host name
	SrcHostPTR string
	DstHostPTR string
	// enriched: threat intelligence, name of the blocklist holding the address
	SrcThreat string
	DstThreat string

	// enriched: BGP attributes of the route to DstAddr (BMP). The slices may
	// be shared with the routing table and must not be modified.
	DstASPath           []uint32
	DstCommunities      []uint32 // standard communities, high 16 bits = AS
	DstLargeCommunities []string // "global:local1:local2"
}

// Sink receives batches of flows. Implementations must not retain the slice
// after Put returns, but may retain the pointed-to records.
type Sink interface {
	Put(ctx context.Context, flows []*Flow) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, flows []*Flow) error

func (f SinkFunc) Put(ctx context.Context, flows []*Flow) error { return f(ctx, flows) }
