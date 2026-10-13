package wiring

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/enrich"
	"github.com/sbrw-evc/network/app/backend/internal/gnmi"
	"github.com/sbrw-evc/network/app/backend/internal/snmp"
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
		t.Fatal("routing / gNMI / SNMP not configured in the enricher")
	}
	// Disabled BMP gives no routes; gNMI and SNMP disabled give no names.
	if _, ok := ec.Routing.LookupRoute("", netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("route while BMP is disabled")
	}
	if _, _, _, ok := ec.IfNames.Lookup(netip.MustParseAddr("192.0.2.1"), 1); ok {
		t.Fatal("gNMI / SNMP name while disabled")
	}
	if _, ok := r.BMPLookup(0, netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("lookup in an empty RIB")
	}
	st, ok := r.BMPStatus().(map[string]any)
	if !ok || st["enabled"] != false || st["listen"] == "" {
		t.Fatalf("bmp status %+v", st)
	}
	if s, ok := r.SNMPStatus().(map[string]any); !ok || s["enabled"] != false {
		t.Fatalf("snmp status %+v", s)
	}
	if s, ok := r.GNMIStatus().(map[string]any); !ok || s["enabled"] != false {
		t.Fatalf("gnmi status %+v", s)
	}
	if err := r.Reload(context.Background(), "gnmi"); err != nil {
		t.Fatal(err)
	}
	if formatCommunity(65000<<16|100) != "65000:100" {
		t.Fatal(formatCommunity(65000<<16 | 100))
	}
	// A second process-wide registration of the BMP metrics is tolerated.
	if _, err := NewRouting(nil, nil, prometheus.NewRegistry(), nil); err != nil {
		t.Fatal(err)
	}
}

// When gNMI and SNMP both know an interface, gNMI gives the name and SNMP
// only fills what gNMI lacks.
func TestInterfaceSourceOrder(t *testing.T) {
	r, err := NewRouting(nil, nil, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := netip.MustParseAddr("192.0.2.1")
	r.GNMI.P.SetGetter(func(context.Context, netip.Addr, gnmi.Profile, gnmi.Credentials, gnmi.Settings) (map[uint32]gnmi.Interface, error) {
		return map[uint32]gnmi.Interface{5: {Name: "Ethernet5", Speed: 100e9}}, nil
	})
	r.SNMP.P.SetWalker(func(context.Context, netip.Addr, snmp.Profile, snmp.Credentials, snmp.Settings) (map[uint32]snmp.Interface, error) {
		return map[uint32]snmp.Interface{5: {Name: "Et5", Descr: "from SNMP", Speed: 1e9}}, nil
	})
	if err := r.GNMI.P.Apply(gnmi.Settings{Enabled: true, Devices: []string{dev.String()}, Profiles: []gnmi.Profile{{ID: "a", Name: "a"}}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.SNMP.P.Apply(snmp.Settings{Enabled: true, Devices: []string{dev.String()},
		Profiles: []snmp.Profile{{ID: "a", Name: "a", Version: snmp.Version2c, CommunityRef: "c"}}}, func(string) (string, error) { return "public", nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.GNMI.P.Run(ctx)
	go r.SNMP.P.Run(ctx)
	var ec enrich.Config
	r.configure(&ec)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, _, g := r.GNMI.P.Lookup(dev, 5)
		_, _, _, s := r.SNMP.P.Lookup(dev, 5)
		if g && s {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no data after polls")
		}
		time.Sleep(10 * time.Millisecond)
	}
	name, descr, speed, ok := ec.IfNames.Lookup(dev, 5)
	if !ok || name != "Ethernet5" || descr != "from SNMP" || speed != 100e9 {
		t.Fatalf("lookup = %q %q %d %v", name, descr, speed, ok)
	}
}
