package enrich

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

type mapLookup map[netip.Addr]string

func (m mapLookup) Lookup(a netip.Addr) string { return m[a] }

func TestPTRThreatAndCloudExporters(t *testing.T) {
	bad := netip.MustParseAddr("45.0.7.1")
	cloud := netip.MustParseAddr("fd75:666c:100::1")
	ptr := mapLookup{google: "dns.google", vmAddr: "must-not-be-used.example", bad: "bad.example"}
	e, _ := newTestEnricher(t, Config{
		PTR:     ptr,
		Threats: mapLookup{bad: "firehol_level1"},
		ExporterNames: func(a netip.Addr) (string, bool) {
			if a == cloud {
				return "vpc-1/eni-2", true
			}
			return "", false
		},
	})
	// 8.8.8.8 → 10.1.0.50: the destination has a Ledger host name,
	// so no PTR is used for it.
	f := &flow.Flow{ExporterAddress: edge, SrcAddr: google, DstAddr: vmAddr, Bytes: 1}
	g := &flow.Flow{ExporterAddress: cloud, SrcAddr: vmAddr, DstAddr: netip.AddrFrom16(bad.As16()), Bytes: 1}
	if err := e.Put(context.Background(), []*flow.Flow{f, g}); err != nil {
		t.Fatal(err)
	}
	if f.SrcHostPTR != "dns.google" || f.DstHostPTR != "" || f.DstHost != "app.example.net" {
		t.Fatalf("ptr: %q %q", f.SrcHostPTR, f.DstHostPTR)
	}
	if f.SrcThreat != "" || f.DstThreat != "" {
		t.Fatalf("threat on clean flow: %+v", f)
	}
	if g.DstThreat != "firehol_level1" || g.SrcThreat != "" || g.DstHostPTR != "bad.example" {
		t.Fatalf("threat flow: %q %q %q", g.SrcThreat, g.DstThreat, g.DstHostPTR)
	}
	if g.ExporterName != "vpc-1/eni-2" {
		t.Fatalf("cloud exporter name %q", g.ExporterName)
	}
	for _, x := range e.Unknown().Exporters {
		if x.Address == cloud {
			t.Fatal("cloud exporter listed as unknown")
		}
	}
}
