package detector

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

func TestThreatRuleDefaults(t *testing.T) {
	var r Rule
	for _, d := range DefaultRules() {
		if d.Kind == KindThreatContact {
			r = d
		}
	}
	if !r.Enabled || r.Severity != "error" || r.ID != "threat-contact" {
		t.Fatalf("default threat rule %+v", r)
	}
	if err := ValidateRule(r); err != nil {
		t.Fatal(err)
	}
	if s, m := r.SignalMethod(); s != "sec.threat.contact" || m != "RED" {
		t.Fatalf("%s %s", s, m)
	}
	q := threatSQL("db.flows", 0, 60, "", 0, 100)
	for _, want := range []string{"(SrcThreat != '') != (DstThreat != '')", "GROUP BY h", "HAVING bps >= 0"} {
		if !strings.Contains(q, want) {
			t.Errorf("SQL lacks %q:\n%s", want, q)
		}
	}
}

func TestThreatContact(t *testing.T) {
	e := newEnv(t)
	H := e.base
	bad := netip.MustParseAddr("45.0.7.1")
	var fs []*flow.Flow
	for s := 0; s < 20*60; s += 10 {
		at := H.Add(time.Duration(s) * time.Second)
		// Clean background.
		fs = append(fs, edgeFlow(at, 1000, 1))
		if s >= 300 && s < 600 {
			// 5..10 min: app-01 (10.1.0.10) talks to a threat list address.
			out := edgeFlow(at, 5000, 5)
			out.SrcAddr, out.DstAddr, out.DstPort, out.Proto = netip.MustParseAddr("10.1.0.10"), bad, 443, 6
			out.SrcHost, out.SrcCI, out.DstThreat = "app-01", "inventory-db:virtualization.virtualmachine:7", "firehol_level1"
			in := edgeFlow(at, 8000, 6)
			in.SrcAddr, in.DstAddr, in.SrcPort, in.Proto = bad, netip.MustParseAddr("10.1.0.10"), 443, 6
			in.DstHost, in.DstCI, in.SrcThreat = "app-01", "inventory-db:virtualization.virtualmachine:7", "firehol_level1"
			// Both sides listed: not an internal host, ignored.
			both := edgeFlow(at, 1000, 1)
			both.SrcAddr, both.DstAddr, both.SrcThreat, both.DstThreat = bad, netip.MustParseAddr("62.0.0.1"), "feodo", "spamhaus_drop"
			// Unnamed host, PTR only.
			ptr := edgeFlow(at, 100, 1)
			ptr.SrcAddr, ptr.DstAddr, ptr.SrcHostPTR, ptr.DstThreat = netip.MustParseAddr("10.1.0.20"), netip.MustParseAddr("91.0.0.5"), "pc-20.corp.example", "feodo"
			fs = append(fs, out, in, both, ptr)
		}
	}
	e.insert(fs)
	r := defaultThreatRule()
	r.Hysteresis = 0
	d := e.detector([]Rule{r}, nil)

	only(t, e.tick(d, H.Add(4*time.Minute+30*time.Second)), 0)
	evs := e.tick(d, H.Add(7*time.Minute+30*time.Second))
	only(t, evs, 2)
	got := map[string]map[string]any{}
	for _, ev := range evs {
		got[ev["ip"].(string)] = ev
	}
	app := got["10.1.0.10"]
	labels := checkEvent(t, app, StatusFiring, "sec.threat.contact", "RED")
	if app["ci"] != "app-01" || app["source_ref"] != "inventory-db:virtualization.virtualmachine:7" || app["severity"] != "error" {
		t.Fatalf("%v", app)
	}
	if labels["threat_list"] != "firehol_level1" || labels["threat_ip"] != "45.0.7.1" || labels["direction"] != "both" {
		t.Fatalf("labels %v", labels)
	}
	if !strings.Contains(app["title"].(string), "firehol_level1") {
		t.Fatalf("title %v", app["title"])
	}
	pc := got["10.1.0.20"]
	if pc["ci"] != "pc-20.corp.example" {
		t.Fatalf("ptr host %v", pc)
	}
	if l := pc["labels"].(map[string]any); l["direction"] != "outbound" || l["threat_list"] != "feodo" {
		t.Fatalf("ptr labels %v", l)
	}
	// Contact over: resolved.
	evs = e.tick(d, H.Add(16*time.Minute+30*time.Second))
	only(t, evs, 2)
	for _, ev := range evs {
		checkEvent(t, ev, StatusResolved, "sec.threat.contact", "RED")
	}
}
