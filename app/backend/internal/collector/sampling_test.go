package collector

import (
	"net/netip"
	"testing"
	"time"
)

func TestPerInterfaceOverride(t *testing.T) {
	c := newTestCollector(t, Config{
		SamplingOverrides: []SamplingOverride{
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Rate: 4000},
			// the v5 test record has input 3, output 4
			{Prefix: netip.MustParsePrefix("10.1.0.0/16"), IfIndex: 3, Rate: 300},
			{Prefix: netip.MustParsePrefix("10.2.0.1/32"), IfIndex: 4, Rate: 400},
			{Prefix: netip.MustParsePrefix("10.3.0.1/32"), IfName: "hu0/0/0/3", Rate: 333},
		},
	}, &captureSink{})
	now := time.Now()
	rate := func(src string) uint64 {
		t.Helper()
		out := c.decode(packet{kind: kindNetFlow, src: netip.MustParseAddr(src), received: now, data: netflowV5(100)}, nil)
		if len(out) != 1 {
			t.Fatalf("%s: %d flows", src, len(out))
		}
		return out[0].SamplingRate
	}
	if r := rate("10.1.2.3"); r != 300 {
		t.Errorf("input interface override: %d", r)
	}
	if r := rate("10.2.0.1"); r != 400 {
		t.Errorf("output interface override: %d", r)
	}
	if r := rate("10.9.9.9"); r != 4000 {
		t.Errorf("exporter-wide override: %d", r)
	}
	if r := rate("192.0.2.1"); r != 100 {
		t.Errorf("no override: %d", r)
	}
	// by name: unknown until the exporter reports its interface names
	if r := rate("10.3.0.1"); r != 4000 {
		t.Errorf("name override before names are known: %d", r)
	}
	c.ifc.setNames(netip.MustParseAddr("10.3.0.1"), 3, "Hu0/0/0/3", "Transit", now)
	if r := rate("10.3.0.1"); r != 333 {
		t.Errorf("name override: %d", r)
	}

	// replaced at run time
	c.SetSamplingOverrides([]SamplingOverride{{Prefix: netip.MustParsePrefix("10.1.2.3/32"), IfIndex: 4, Rate: 44}})
	if r := rate("10.1.2.3"); r != 44 {
		t.Errorf("after SetSamplingOverrides: %d", r)
	}
	if r := rate("10.2.0.1"); r != 100 {
		t.Errorf("removed override still applied: %d", r)
	}
	exps := c.Exporters()
	found := false
	for _, e := range exps {
		if e.Address == netip.MustParseAddr("10.1.2.3") {
			for _, r := range e.SamplingRates {
				found = found || r == 44
			}
		}
	}
	if !found {
		t.Errorf("forced rate not in the exporter's sampling rates: %+v", exps)
	}
}

func TestParseSamplingOverridesInterface(t *testing.T) {
	ov, err := ParseSamplingOverrides("192.0.2.1@17=4000; 192.0.2.0/24@Hu0/0/0/1=8000\n2001:db8::1@5=10")
	if err != nil {
		t.Fatal(err)
	}
	if len(ov) != 3 || ov[0].IfIndex != 17 || ov[0].Rate != 4000 || ov[0].Prefix.Bits() != 32 ||
		ov[1].IfName != "Hu0/0/0/1" || ov[1].IfIndex != 0 || ov[1].Prefix.Bits() != 24 ||
		ov[2].IfIndex != 5 || ov[2].Prefix.Bits() != 128 {
		t.Fatalf("%+v", ov)
	}
	if s := ov[0].String(); s != "192.0.2.1@17=4000" {
		t.Errorf("String: %s", s)
	}
	if s := ov[1].String(); s != "192.0.2.0/24@Hu0/0/0/1=8000" {
		t.Errorf("String: %s", s)
	}
	for _, bad := range []string{"192.0.2.1@=10", "192.0.2.1@0=10", "x@3=10", "192.0.2.1@3=0"} {
		if _, err := ParseSamplingOverrides(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
