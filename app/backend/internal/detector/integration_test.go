package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

const publicURL = "https://flow.example.com"

var (
	edgeAddr = netip.MustParseAddr("192.0.2.1")
	edgeRef  = "inventory-db:dcim.device:100"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

type env struct {
	t     *testing.T
	conn  driver.Conn
	cfg   chstore.Config
	clock *clock
	in    *ingest
	store *MemoryStore
	base  time.Time // an hour start, 3 hours ago
}

func newEnv(t *testing.T) *env {
	t.Helper()
	conn, db := chtest.Conn(t)
	cfg := chstore.Config{Database: db}
	if err := chstore.Migrate(context.Background(), conn, cfg); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, conn: conn, cfg: cfg, clock: &clock{}, in: newIngest(t), store: &MemoryStore{},
		base: time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)}
}

func (e *env) insert(fs []*flow.Flow) {
	e.t.Helper()
	w, err := chstore.NewWriter(e.conn, e.cfg, chstore.WriterConfig{BatchSize: 5000, MaxDelay: 50 * time.Millisecond}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Put(ctx, fs); err != nil {
		e.t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := w.Close(cctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) detector(rules []Rule, mod func(*Config)) *Detector {
	e.t.Helper()
	cfg := Config{
		Conn: e.conn, Storage: e.cfg, Rules: rules, PublicURL: publicURL, Now: e.clock.Now, State: e.store,
		Sender: NewSender(SenderConfig{URL: e.in.srv.URL, Token: token, MinBackoff: time.Millisecond}),
	}
	if mod != nil {
		mod(&cfg)
	}
	d, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

// tick sets the clock and runs one tick, returning the delivered events.
func (e *env) tick(d *Detector, at time.Time) []map[string]any {
	e.t.Helper()
	e.clock.Set(at)
	if err := d.Tick(context.Background()); err != nil {
		e.t.Fatalf("tick at %s: %v", at, err)
	}
	return e.in.take()
}

// edgeFlow is a flow through edge-01 xe-0/0/1 (in, 1 Gbps, external) →
// ae0 (out, 10 Gbps, internal).
func edgeFlow(at time.Time, bytes, packets uint64) *flow.Flow {
	return &flow.Flow{
		TimeReceived: at, SamplingRate: 1, ExporterAddress: edgeAddr, ExporterName: "edge-01", ExporterRef: edgeRef,
		InIf: 1, InIfName: "xe-0/0/1", InIfSpeed: 1e9, InIfBoundary: "external", InIfCircuit: "CID-1",
		OutIf: 2, OutIfName: "ae0", OutIfSpeed: 10e9, OutIfBoundary: "internal",
		SrcAddr: netip.MustParseAddr("198.51.100.7"), DstAddr: netip.MustParseAddr("10.1.0.10"),
		SrcAS: 64500, DstAS: 65000, Proto: 17, Bytes: bytes, Packets: packets,
	}
}

var presetFields = map[string]bool{"id": true, "status": true, "signal": true, "method": true, "severity": true,
	"title": true, "ci": true, "source_ref": true, "ip": true, "value": true, "labels": true, "links": true,
	"starts_at": true, "ends_at": true}

// checkEvent asserts the network-flow preset format and returns the labels.
func checkEvent(t *testing.T, ev map[string]any, status, signal, method string) map[string]any {
	t.Helper()
	for k := range ev {
		if !presetFields[k] {
			t.Errorf("unexpected field %q", k)
		}
	}
	if ev["status"] != status || ev["signal"] != signal || ev["method"] != method {
		t.Fatalf("event %v: want %s %s %s", ev, status, signal, method)
	}
	for _, k := range []string{"id", "severity", "title", "starts_at"} {
		if s, _ := ev[k].(string); s == "" {
			t.Fatalf("event %v: %s empty", ev, k)
		}
	}
	if !strings.HasPrefix(ev["id"].(string), "flow-") {
		t.Fatalf("id %v", ev["id"])
	}
	if _, err := time.Parse(time.RFC3339, ev["starts_at"].(string)); err != nil {
		t.Fatal(err)
	}
	if status == StatusResolved {
		if _, err := time.Parse(time.RFC3339, ev["ends_at"].(string)); err != nil {
			t.Fatalf("ends_at: %v", ev["ends_at"])
		}
	}
	if _, ok := ev["value"].(float64); !ok {
		t.Fatalf("value %v", ev["value"])
	}
	labels, _ := ev["labels"].(map[string]any)
	for k, v := range labels {
		if _, ok := v.(string); !ok {
			t.Fatalf("label %s not a string", k)
		}
	}
	if ev["ci"] == nil && ev["source_ref"] == nil && ev["ip"] == nil {
		t.Fatal("no CI, source_ref or ip")
	}
	links, _ := ev["links"].(map[string]any)
	link, _ := links["flow"].(string)
	if !strings.HasPrefix(link, publicURL+"/visualize?q=") {
		t.Fatalf("link %q", link)
	}
	u, _ := url.Parse(link)
	raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("q"))
	if err != nil {
		t.Fatal(err)
	}
	var v view
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if _, err := filter.Compile(v.F); err != nil {
		t.Fatalf("link filter %q: %v", v.F, err)
	}
	return labels
}

func only(t *testing.T, evs []map[string]any, n int) {
	t.Helper()
	if len(evs) != n {
		t.Fatalf("want %d events, got %d: %v", n, len(evs), evs)
	}
}

func TestLinkUtilization(t *testing.T) {
	e := newEnv(t)
	H := e.base
	var fs []*flow.Flow
	for m := 0; m < 20; m++ {
		pct := 0.9
		if m >= 10 {
			pct = 0.1
		}
		fs = append(fs, edgeFlow(H.Add(time.Duration(m)*time.Minute+10*time.Second), uint64(pct*1e9*60/8), 1000))
	}
	e.insert(fs)
	rule := Rule{ID: "util", Name: "util", Enabled: true, Kind: KindLinkUtilization, Thresholds: Thresholds{Percent: 85},
		For: Duration(2 * time.Minute), Hysteresis: Duration(2 * time.Minute), Severity: "warning"}
	reg := prometheus.NewRegistry()
	d := e.detector([]Rule{rule}, func(c *Config) { c.Metrics = reg })
	at := func(m int) time.Time { return H.Add(time.Duration(m)*time.Minute + 30*time.Second) }

	only(t, e.tick(d, at(1)), 0) // pending
	if st := d.Status(); len(st.Alerts) != 1 || st.Alerts[0].State != StatePending || st.Rules[0].Pending != 1 {
		t.Fatalf("%+v", st)
	}
	only(t, e.tick(d, at(2)), 0)
	evs := e.tick(d, at(3))
	only(t, evs, 1)
	labels := checkEvent(t, evs[0], StatusFiring, "use.link.utilization", "USE")
	ev := evs[0]
	if v := ev["value"].(float64); v < 89.9 || v > 90.1 {
		t.Fatalf("value %v", v)
	}
	if ev["ci"] != "edge-01" || ev["source_ref"] != edgeRef || ev["ip"] != "192.0.2.1" || ev["severity"] != "warning" {
		t.Fatalf("%v", ev)
	}
	if labels["interface"] != "xe-0/0/1" || labels["direction"] != "in" || labels["rule_id"] != "util" || labels["kind"] != "link_utilization" {
		t.Fatalf("%v", labels)
	}
	if !strings.Contains(ev["title"].(string), "xe-0/0/1") || !strings.Contains(ev["title"].(string), "90 %") {
		t.Fatalf("title %v", ev["title"])
	}
	if ev["starts_at"] != rfc3339(at(1)) {
		t.Fatalf("starts_at %v", ev["starts_at"])
	}
	firingID := ev["id"]

	// Prometheus gauges.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "flow_interface_utilization_ratio" {
			continue
		}
		for _, m := range mf.GetMetric() {
			lbl := map[string]string{}
			for _, l := range m.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			if lbl["exporter"] == "edge-01" && lbl["ifname"] == "xe-0/0/1" && lbl["direction"] == "in" {
				found = m.GetGauge().GetValue() > 0.89
			}
		}
	}
	if !found {
		t.Fatal("flow_interface_utilization_ratio for edge-01 xe-0/0/1 in not found")
	}

	// A restart with the persisted state does not repeat the event.
	d2 := e.detector([]Rule{rule}, nil)
	only(t, e.tick(d2, at(4)), 0)
	if st := d2.Status(); len(st.Alerts) != 1 || st.Alerts[0].State != StateFiring {
		t.Fatalf("%+v", st.Alerts)
	}

	only(t, e.tick(d2, at(11)), 0) // resolving
	only(t, e.tick(d2, at(12)), 0)
	evs = e.tick(d2, at(13))
	only(t, evs, 1)
	checkEvent(t, evs[0], StatusResolved, "use.link.utilization", "USE")
	if evs[0]["id"] != firingID {
		t.Fatal("resolved must reuse the firing id")
	}
	if v := evs[0]["value"].(float64); v > 11 {
		t.Fatalf("resolved value %v", v)
	}
	if st := d2.Status(); len(st.Alerts) != 0 {
		t.Fatalf("%+v", st.Alerts)
	}
}

func TestLinkCommit(t *testing.T) {
	e := newEnv(t)
	H := e.base
	var fs []*flow.Flow
	for m := 0; m < 60; m++ { // 200 Mbps for an hour
		fs = append(fs, edgeFlow(H.Add(time.Duration(m)*time.Minute), uint64(200e6*60/8), 1000))
	}
	e.insert(fs)
	commit := CommitFunc(func(k IfaceKey) (uint64, bool) {
		if k.Exporter == edgeAddr && k.Interface == "xe-0/0/1" && k.Circuit == "CID-1" && k.ExporterRef == edgeRef {
			return 100e6, true
		}
		return 0, false
	})
	rule := Rule{ID: "commit", Enabled: true, Kind: KindLinkCommit, Window: Duration(time.Hour), Severity: "warning"}
	d := e.detector([]Rule{rule}, func(c *Config) { c.Commit = commit })
	evs := e.tick(d, H.Add(time.Hour+30*time.Second))
	only(t, evs, 1)
	labels := checkEvent(t, evs[0], StatusFiring, "use.link.commit", "USE")
	if v := evs[0]["value"].(float64); v < 199 || v > 201 {
		t.Fatalf("value %v", v)
	}
	if labels["commit_bps"] != "100000000" || labels["circuit"] != "CID-1" || evs[0]["ci"] != "edge-01" {
		t.Fatalf("%v", evs[0])
	}
	// Disabling the rule resolves its alert.
	rule.Enabled = false
	if err := d.SetRules([]Rule{rule}); err != nil {
		t.Fatal(err)
	}
	evs = e.tick(d, H.Add(time.Hour+time.Minute))
	only(t, evs, 1)
	checkEvent(t, evs[0], StatusResolved, "use.link.commit", "USE")
}

func TestDDoS(t *testing.T) {
	e := newEnv(t)
	H := e.base
	victim := netip.MustParseAddr("203.0.113.10")
	web := netip.MustParseAddr("203.0.113.11")
	var fs []*flow.Flow
	for s := 0; s < 20*60; s += 10 {
		at := H.Add(time.Duration(s) * time.Second)
		// Background to the victim: 1 Mbps.
		f := edgeFlow(at, uint64(1e6*10/8), 100)
		f.DstAddr = victim
		fs = append(fs, f)
		if s >= 600 && s < 900 { // 10..15 min: 500 Mbps UDP flood, 50k pps SYN flood on web-01
			f := edgeFlow(at, uint64(500e6*10/8), 400_000)
			f.DstAddr = victim
			fs = append(fs, f)
			syn := edgeFlow(at, 50_000*10*60, 50_000*10)
			syn.DstAddr, syn.Proto, syn.TCPFlags, syn.DstPort = web, 6, 0x02, 443
			syn.DstHost, syn.DstCI = "web-01", "inventory-db:dcim.device:42"
			ack := edgeFlow(at, 1000*10*500, 1000*10)
			ack.DstAddr, ack.Proto, ack.TCPFlags, ack.DstPort = web, 6, 0x18, 443
			ack.DstHost, ack.DstCI = "web-01", "inventory-db:dcim.device:42"
			fs = append(fs, syn, ack)
		}
	}
	e.insert(fs)
	rules := DefaultRules()
	var use []Rule
	for _, r := range rules {
		if r.Kind == KindDDoSVolumetric {
			r.Thresholds = Thresholds{BPS: 100e6}
			r.Baseline = &Baseline{Window: Duration(10 * time.Minute), K: 3}
			r.For, r.Hysteresis = 0, 0
			use = append(use, r)
		}
		if r.Kind == KindDDoSSyn {
			r.Thresholds = Thresholds{Ratio: 0.5, PPS: 1000}
			r.For, r.Hysteresis = 0, 0
			use = append(use, r)
		}
	}
	d := e.detector(use, nil)

	only(t, e.tick(d, H.Add(5*time.Minute+30*time.Second)), 0) // background only
	evs := e.tick(d, H.Add(11*time.Minute+30*time.Second))
	only(t, evs, 2)
	got := map[string]map[string]any{}
	for _, ev := range evs {
		got[ev["signal"].(string)] = ev
	}
	vol := got["red.ddos.volumetric"]
	labels := checkEvent(t, vol, StatusFiring, "red.ddos.volumetric", "RED")
	if v := vol["value"].(float64); v < 499e6 || v > 503e6 {
		t.Fatalf("bps %v", v)
	}
	// No IPAM host: the edge router is the CI, the target is the IP.
	if vol["ip"] != "203.0.113.10" || vol["ci"] != "edge-01" || vol["source_ref"] != edgeRef || vol["severity"] != "critical" {
		t.Fatalf("%v", vol)
	}
	if labels["dst_ip"] != "203.0.113.10" || labels["proto"] != "udp" {
		t.Fatalf("%v", labels)
	}
	syn := got["red.ddos.syn"]
	checkEvent(t, syn, StatusFiring, "red.ddos.syn", "RED")
	if syn["ci"] != "web-01" || syn["source_ref"] != "inventory-db:dcim.device:42" || syn["ip"] != "203.0.113.11" {
		t.Fatalf("%v", syn)
	}
	if v := syn["value"].(float64); v < 97 || v > 99 {
		t.Fatalf("syn ratio %v", v)
	}
	// Still under attack: nothing new.
	only(t, e.tick(d, H.Add(13*time.Minute+30*time.Second)), 0)
	// Over.
	evs = e.tick(d, H.Add(16*time.Minute+30*time.Second))
	only(t, evs, 2)
	for _, ev := range evs {
		checkEvent(t, ev, StatusResolved, ev["signal"].(string), "RED")
	}
}

func TestTrafficAnomalyAndDrop(t *testing.T) {
	e := newEnv(t)
	H := e.base
	const svc = "inventory-db:dcim.device:7"
	week := 7 * 24 * time.Hour
	var fs []*flow.Flow
	perMin := func(bps float64) uint64 { return uint64(bps * 60 / 8) }
	for w := 1; w <= 2; w++ {
		for m := 0; m < 60; m++ {
			at := H.Add(-time.Duration(w)*week + time.Duration(m)*time.Minute)
			f := edgeFlow(at, perMin(10e6), 1000) // edge-01 xe-0/0/1: 10 Mbps
			f.DstCI = svc
			fs = append(fs, f)
		}
	}
	for m := 0; m < 60; m++ {
		at := H.Add(time.Duration(m) * time.Minute)
		if m < 30 { // 100 Mbps to elsewhere: anomaly on the interface
			fs = append(fs, edgeFlow(at, perMin(100e6), 1000))
		}
		if m < 30 || m >= 51 { // service traffic, missing 30..50
			f := edgeFlow(at, perMin(10e6), 1000)
			f.InIfName = "xe-0/0/2"
			f.DstCI = svc
			fs = append(fs, f)
		}
	}
	e.insert(fs)
	var use []Rule
	for _, r := range DefaultRules() {
		switch r.Kind {
		case KindTrafficAnomaly:
			r.Baseline.Weeks, r.For, r.Hysteresis = 2, 0, 0
			use = append(use, r)
		case KindTrafficDrop:
			r.Baseline.Weeks, r.For, r.Hysteresis = 2, 0, 0
			use = append(use, r)
		}
	}
	d := e.detector(use, nil)

	evs := e.tick(d, H.Add(29*time.Minute+30*time.Second))
	only(t, evs, 1)
	labels := checkEvent(t, evs[0], StatusFiring, "red.traffic.anomaly", "RED")
	if evs[0]["ci"] != "edge-01" || evs[0]["source_ref"] != edgeRef || labels["InIfName"] != "xe-0/0/1" || labels["expected_bps"] != "10000000" {
		t.Fatalf("%v", evs[0])
	}

	// 15-minute window 35..50: anomaly over (resolved), service traffic gone (drop).
	evs = e.tick(d, H.Add(50*time.Minute+30*time.Second))
	only(t, evs, 2)
	got := map[string]map[string]any{}
	for _, ev := range evs {
		got[ev["status"].(string)] = ev
	}
	checkEvent(t, got[StatusResolved], StatusResolved, "red.traffic.anomaly", "RED")
	drop := got[StatusFiring]
	labels = checkEvent(t, drop, StatusFiring, "red.traffic.drop", "RED")
	if drop["source_ref"] != svc || drop["value"].(float64) != 0 || labels["DstCI"] != svc || drop["severity"] != "error" {
		t.Fatalf("%v", drop)
	}
	// Window 45..60 has 9 minutes of service traffic: 6 Mbps > 10% of 10 Mbps.
	evs = e.tick(d, H.Add(60*time.Minute+30*time.Second))
	only(t, evs, 1)
	checkEvent(t, evs[0], StatusResolved, "red.traffic.drop", "RED")
}

func TestExporterSilent(t *testing.T) {
	e := newEnv(t)
	H := e.base
	core := netip.MustParseAddr("192.0.2.2")
	var fs []*flow.Flow
	for m := 0; m < 5; m++ {
		fs = append(fs, edgeFlow(H.Add(time.Duration(m)*time.Minute), 1000, 1))
		f := edgeFlow(H.Add(time.Duration(m)*time.Minute), 1000, 1)
		f.ExporterAddress, f.ExporterName, f.ExporterRef = core, "core-02", "inventory-db:dcim.device:200"
		fs = append(fs, f)
	}
	e.insert(fs)
	rule := Rule{ID: "silent", Enabled: true, Kind: KindExporterSilent, Thresholds: Thresholds{Silence: Duration(10 * time.Minute)}, Severity: "low"}

	t.Run("registry", func(t *testing.T) {
		var mu sync.Mutex
		coreSeen := H.Add(4 * time.Minute)
		src := ExporterFunc(func() []ExporterSeen {
			mu.Lock()
			defer mu.Unlock()
			return []ExporterSeen{{Address: edgeAddr, LastSeen: e.clock.Now()}, {Address: core, LastSeen: coreSeen}}
		})
		d := e.detector([]Rule{rule}, func(c *Config) { c.Exporters = src; c.State = &MemoryStore{} })
		only(t, e.tick(d, H.Add(10*time.Minute)), 0)
		evs := e.tick(d, H.Add(20*time.Minute))
		only(t, evs, 1)
		labels := checkEvent(t, evs[0], StatusFiring, "use.exporter.silent", "USE")
		if evs[0]["ci"] != "core-02" || evs[0]["source_ref"] != "inventory-db:dcim.device:200" || evs[0]["ip"] != "192.0.2.2" ||
			evs[0]["value"].(float64) != 16 || labels["exporter"] != "core-02" {
			t.Fatalf("%v", evs[0])
		}
		mu.Lock()
		coreSeen = H.Add(21 * time.Minute)
		mu.Unlock()
		evs = e.tick(d, H.Add(21*time.Minute))
		only(t, evs, 1)
		checkEvent(t, evs[0], StatusResolved, "use.exporter.silent", "USE")
	})
	t.Run("flows", func(t *testing.T) {
		d := e.detector([]Rule{rule}, func(c *Config) { c.State = &MemoryStore{} })
		evs := e.tick(d, H.Add(20*time.Minute))
		only(t, evs, 2) // both exporters stopped at minute 4
		for _, ev := range evs {
			checkEvent(t, ev, StatusFiring, "use.exporter.silent", "USE")
		}
	})
}

func TestCustomRuleAndOutbox(t *testing.T) {
	e := newEnv(t)
	H := e.base
	var fs []*flow.Flow
	for m := 0; m < 10; m++ {
		fs = append(fs, edgeFlow(H.Add(time.Duration(m)*time.Minute), uint64(80e6*60/8), 1000))
	}
	e.insert(fs)
	rule := Rule{ID: "as64500", Enabled: true, Kind: KindCustom, Signal: "red.traffic.as", Dimensions: []string{"SrcAS"},
		Filter: "SrcAS = 64500", Thresholds: Thresholds{BPS: 50e6}, Window: Duration(5 * time.Minute), Severity: "info",
		Title: "AS${SrcAS}: ${value_text}"}
	d := e.detector([]Rule{rule}, nil)
	e.in.fail.Store(1000) // Umbrella down
	if err := func() error { e.clock.Set(H.Add(6*time.Minute + 30*time.Second)); return d.Tick(context.Background()) }(); err == nil {
		t.Fatal("want delivery error")
	}
	if st := d.Status(); st.Sender == nil || st.Sender.Outbox != 1 || len(st.Alerts) != 1 {
		t.Fatalf("%+v", st)
	}
	snap, _ := UnmarshalSnapshot(e.store.Bytes())
	if snap == nil || len(snap.Outbox) != 1 {
		t.Fatal("outbox not persisted")
	}
	// Restart while Umbrella is still down, then it comes back.
	d2 := e.detector([]Rule{rule}, nil)
	e.in.fail.Store(0)
	evs := e.tick(d2, H.Add(7*time.Minute+30*time.Second))
	only(t, evs, 1)
	checkEvent(t, evs[0], StatusFiring, "red.traffic.as", "RED")
	if evs[0]["title"] != "AS64500: 80 Мбит/с" || evs[0]["severity"] != "info" {
		t.Fatalf("%v", evs[0])
	}
}
