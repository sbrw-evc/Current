package wiring

import (
	"context"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/enrich"
)

func TestRoutingComponents(t *testing.T) {
	r, err := NewRouting(nil, nil, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(context.Background(), "bmp"); err != nil {
		t.Fatal(err)
	}
	var ec enrich.Config
	r.configure(&ec)
	if ec.Routing == nil || ec.IfNames == nil {
		t.Fatal("routing / SNMP not configured in the enricher")
	}
	// Disabled BMP gives no routes; SNMP disabled gives no names.
	if _, ok := ec.Routing.LookupRoute(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("route while BMP is disabled")
	}
	if _, _, _, ok := ec.IfNames.Lookup(netip.MustParseAddr("192.0.2.1"), 1); ok {
		t.Fatal("SNMP name while disabled")
	}
	if _, ok := r.BMPLookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("lookup in an empty RIB")
	}
	st, ok := r.BMPStatus().(map[string]any)
	if !ok || st["enabled"] != false || st["listen"] == "" {
		t.Fatalf("bmp status %+v", st)
	}
	if s, ok := r.SNMPStatus().(map[string]any); !ok || s["enabled"] != false {
		t.Fatalf("snmp status %+v", s)
	}
	if formatCommunity(65000<<16|100) != "65000:100" {
		t.Fatal(formatCommunity(65000<<16 | 100))
	}
	// A second process-wide registration of the BMP metrics is tolerated.
	if _, err := NewRouting(nil, nil, prometheus.NewRegistry(), nil); err != nil {
		t.Fatal(err)
	}
}
