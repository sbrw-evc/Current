package clickhouse

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
	"github.com/sbrw-evc/current/app/backend/internal/schema"
)

// builder turns a batch of flows into the typed slice of one column.
type builder func(fs []*flow.Flow) any

func col[T any](get func(*flow.Flow) T) builder {
	return func(fs []*flow.Flow) any {
		out := make([]T, len(fs))
		for i, f := range fs {
			out[i] = get(f)
		}
		return out
	}
}

// samplingRate is the effective rate: 0 (unknown) counts as 1.
func samplingRate(f *flow.Flow) uint64 {
	if f.SamplingRate == 0 {
		return 1
	}
	return f.SamplingRate
}

// ipv6 returns the address as IPv6, IPv4 being IPv4-mapped; invalid is ::.
func ipv6(a netip.Addr) netip.Addr {
	if !a.IsValid() {
		return netip.IPv6Unspecified()
	}
	return netip.AddrFrom16(a.As16())
}

func prefixText(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.Masked().String()
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

// builders maps every registry column to its value in flow.Flow. A registry
// column without an entry here makes NewWriter fail, so adding a column to
// the registry forces wiring it here.
var builders = map[string]builder{
	"TimeReceived":    col(func(f *flow.Flow) time.Time { return utc(f.TimeReceived) }),
	"SamplingRate":    col(samplingRate),
	"FlowType":        col(func(f *flow.Flow) string { return f.FlowType }),
	"ExporterAddress": col(func(f *flow.Flow) netip.Addr { return ipv6(f.ExporterAddress) }),
	"ExporterName":    col(func(f *flow.Flow) string { return f.ExporterName }),
	"ExporterRef":     col(func(f *flow.Flow) string { return f.ExporterRef }),
	"ExporterSite":    col(func(f *flow.Flow) string { return f.ExporterSite }),
	"ExporterRegion":  col(func(f *flow.Flow) string { return f.ExporterRegion }),
	"ExporterRole":    col(func(f *flow.Flow) string { return f.ExporterRole }),
	"ExporterGroup":   col(func(f *flow.Flow) string { return f.ExporterGroup }),
	"ExporterTenant":  col(func(f *flow.Flow) string { return f.ExporterTenant }),

	"InIfIndex":         col(func(f *flow.Flow) uint32 { return f.InIf }),
	"InIfName":          col(func(f *flow.Flow) string { return f.InIfName }),
	"InIfDescription":   col(func(f *flow.Flow) string { return f.InIfDescription }),
	"InIfSpeed":         col(func(f *flow.Flow) uint64 { return f.InIfSpeed }),
	"InIfBoundary":      col(func(f *flow.Flow) string { return f.InIfBoundary }),
	"InIfConnectivity":  col(func(f *flow.Flow) string { return f.InIfConnectivity }),
	"InIfProvider":      col(func(f *flow.Flow) string { return f.InIfProvider }),
	"InIfCircuit":       col(func(f *flow.Flow) string { return f.InIfCircuit }),
	"OutIfIndex":        col(func(f *flow.Flow) uint32 { return f.OutIf }),
	"OutIfName":         col(func(f *flow.Flow) string { return f.OutIfName }),
	"OutIfDescription":  col(func(f *flow.Flow) string { return f.OutIfDescription }),
	"OutIfSpeed":        col(func(f *flow.Flow) uint64 { return f.OutIfSpeed }),
	"OutIfBoundary":     col(func(f *flow.Flow) string { return f.OutIfBoundary }),
	"OutIfConnectivity": col(func(f *flow.Flow) string { return f.OutIfConnectivity }),
	"OutIfProvider":     col(func(f *flow.Flow) string { return f.OutIfProvider }),
	"OutIfCircuit":      col(func(f *flow.Flow) string { return f.OutIfCircuit }),

	"SrcAddr":      col(func(f *flow.Flow) netip.Addr { return ipv6(f.SrcAddr) }),
	"DstAddr":      col(func(f *flow.Flow) netip.Addr { return ipv6(f.DstAddr) }),
	"SrcNetMask":   col(func(f *flow.Flow) uint8 { return f.SrcNetMask }),
	"DstNetMask":   col(func(f *flow.Flow) uint8 { return f.DstNetMask }),
	"NextHop":      col(func(f *flow.Flow) netip.Addr { return ipv6(f.NextHop) }),
	"SrcAS":        col(func(f *flow.Flow) uint32 { return f.SrcAS }),
	"DstAS":        col(func(f *flow.Flow) uint32 { return f.DstAS }),
	"SrcNetPrefix": col(func(f *flow.Flow) string { return prefixText(f.SrcNetPrefix) }),
	"SrcNetName":   col(func(f *flow.Flow) string { return f.SrcNetName }),
	"SrcNetRole":   col(func(f *flow.Flow) string { return f.SrcNetRole }),
	"SrcNetSite":   col(func(f *flow.Flow) string { return f.SrcNetSite }),
	"SrcNetTenant": col(func(f *flow.Flow) string { return f.SrcNetTenant }),
	"SrcNetVRF":    col(func(f *flow.Flow) string { return f.SrcNetVRF }),
	"SrcHost":      col(func(f *flow.Flow) string { return f.SrcHost }),
	"SrcCI":        col(func(f *flow.Flow) string { return f.SrcCI }),
	"SrcCountry":   col(func(f *flow.Flow) string { return f.SrcCountry }),
	"SrcCity":      col(func(f *flow.Flow) string { return f.SrcCity }),
	"DstNetPrefix": col(func(f *flow.Flow) string { return prefixText(f.DstNetPrefix) }),
	"DstNetName":   col(func(f *flow.Flow) string { return f.DstNetName }),
	"DstNetRole":   col(func(f *flow.Flow) string { return f.DstNetRole }),
	"DstNetSite":   col(func(f *flow.Flow) string { return f.DstNetSite }),
	"DstNetTenant": col(func(f *flow.Flow) string { return f.DstNetTenant }),
	"DstNetVRF":    col(func(f *flow.Flow) string { return f.DstNetVRF }),
	"DstHost":      col(func(f *flow.Flow) string { return f.DstHost }),
	"DstCI":        col(func(f *flow.Flow) string { return f.DstCI }),
	"DstCountry":   col(func(f *flow.Flow) string { return f.DstCountry }),
	"DstCity":      col(func(f *flow.Flow) string { return f.DstCity }),

	"SrcPort":          col(func(f *flow.Flow) uint16 { return f.SrcPort }),
	"DstPort":          col(func(f *flow.Flow) uint16 { return f.DstPort }),
	"Proto":            col(func(f *flow.Flow) uint8 { return f.Proto }),
	"EType":            col(func(f *flow.Flow) uint16 { return f.EType }),
	"TCPFlags":         col(func(f *flow.Flow) uint8 { return f.TCPFlags }),
	"IPTos":            col(func(f *flow.Flow) uint8 { return f.IPTos }),
	"ICMPType":         col(func(f *flow.Flow) uint8 { return f.ICMPType }),
	"ICMPCode":         col(func(f *flow.Flow) uint8 { return f.ICMPCode }),
	"SrcVlan":          col(func(f *flow.Flow) uint16 { return f.SrcVlan }),
	"DstVlan":          col(func(f *flow.Flow) uint16 { return f.DstVlan }),
	"ForwardingStatus": col(func(f *flow.Flow) uint8 { return f.ForwardingStatus }),
	"App":              col(func(f *flow.Flow) string { return f.App }),

	// Stored scaled by the sampling rate: the tables hold real volumes.
	"Bytes":   col(func(f *flow.Flow) uint64 { return f.Bytes * samplingRate(f) }),
	"Packets": col(func(f *flow.Flow) uint64 { return f.Packets * samplingRate(f) }),

	"SrcHostPTR": col(func(f *flow.Flow) string { return f.SrcHostPTR }),
	"DstHostPTR": col(func(f *flow.Flow) string { return f.DstHostPTR }),
	"SrcThreat":  col(func(f *flow.Flow) string { return f.SrcThreat }),
	"DstThreat":  col(func(f *flow.Flow) string { return f.DstThreat }),

	"DstASPath":           col(func(f *flow.Flow) []uint32 { return f.DstASPath }),
	"DstCommunities":      col(func(f *flow.Flow) []uint32 { return f.DstCommunities }),
	"DstLargeCommunities": col(func(f *flow.Flow) []string { return f.DstLargeCommunities }),
}

// insertColumns returns the registry columns with their builders, or an
// error naming the columns the writer does not know how to fill.
func insertColumns() ([]string, []builder, error) {
	names := make([]string, 0, len(schema.Columns))
	bs := make([]builder, 0, len(schema.Columns))
	var missing []string
	for _, c := range schema.Columns {
		b, ok := builders[c.Name]
		if !ok {
			missing = append(missing, c.Name)
			continue
		}
		names = append(names, c.Name)
		bs = append(bs, b)
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("clickhouse writer: no flow field for registry columns %v", missing)
	}
	return names, bs, nil
}
