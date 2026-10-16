package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/filter"
)

func TestAdvance(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	forD, hyst := 2*time.Minute, 2*time.Minute

	st, act := advance(nil, false, false, at(0), forD, hyst)
	if st != nil || act != actNone {
		t.Fatal("no breach must create no state")
	}
	st, act = advance(nil, true, true, at(0), forD, hyst)
	if st.State != StatePending || act != actNone {
		t.Fatalf("want pending, got %v %v", st.State, act)
	}
	st, act = advance(st, true, true, at(1), forD, hyst)
	if st.State != StatePending || act != actNone {
		t.Fatal("still pending after 1m")
	}
	st, act = advance(st, true, true, at(2), forD, hyst)
	if st.State != StateFiring || act != actFire || !st.Since.Equal(at(0)) {
		t.Fatalf("want firing since t0, got %+v %v", st, act)
	}
	st, act = advance(st, false, false, at(3), forD, hyst)
	if st.State != StateResolving || act != actNone {
		t.Fatal("want resolving")
	}
	// Flapping back keeps the alert firing without a new event.
	st, act = advance(st, false, true, at(4), forD, hyst)
	if st.State != StateFiring || act != actNone || !st.Clear.IsZero() {
		t.Fatal("hold must return to firing")
	}
	st, _ = advance(st, false, false, at(5), forD, hyst)
	st, act = advance(st, false, false, at(6), forD, hyst)
	if act != actNone || st == nil {
		t.Fatal("hysteresis not elapsed")
	}
	st, act = advance(st, false, false, at(7), forD, hyst)
	if st != nil || act != actResolve {
		t.Fatal("want resolve after hysteresis")
	}

	// Pending that clears before `for` disappears silently.
	st, _ = advance(nil, true, true, at(0), forD, hyst)
	st, act = advance(st, false, false, at(1), forD, hyst)
	if st != nil || act != actNone {
		t.Fatal("pending must vanish")
	}
	// for = 0 fires at once, hysteresis 0 resolves at once.
	st, act = advance(nil, true, true, at(0), 0, 0)
	if act != actFire {
		t.Fatal("for 0 must fire")
	}
	if _, act = advance(st, false, false, at(1), 0, 0); act != actResolve {
		t.Fatal("hysteresis 0 must resolve")
	}
}

func TestBaselineMath(t *testing.T) {
	if m := median([]float64{5, 1, 3}); m != 3 {
		t.Fatal(m)
	}
	if m := median([]float64{4, 1, 3, 2}); m != 2.5 {
		t.Fatal(m)
	}
	if m := mad([]float64{1, 1, 2, 2, 4, 6, 9}); m != 1 {
		t.Fatal(m)
	}
	if p := percentile([]float64{10, 20, 30}, 0, 95); p != 30 {
		t.Fatal(p)
	}
	// 20 samples of which 18 are missing (zero): p95 = rank 19 = 50.
	if p := percentile([]float64{50, 100}, 20, 95); p != 50 {
		t.Fatal(p)
	}
	b := Baseline{K: 3, Ratio: 0.5, MinVolume: 10, MinSamples: 2, Direction: "up"}
	samples := []float64{100, 110, 90, 105}
	if r := anomaly(300, samples, b); !r.Breach || r.Direction != "up" || r.Expected != 102.5 {
		t.Fatalf("%+v", r)
	}
	if r := anomaly(140, samples, b); r.Breach {
		t.Fatalf("below ratio: %+v", r)
	}
	if r := anomaly(10, samples, b); r.Breach {
		t.Fatal("down not watched")
	}
	b.Direction = "both"
	if r := anomaly(10, samples, b); !r.Breach || r.Direction != "down" {
		t.Fatalf("%+v", r)
	}
	if r := anomaly(300, []float64{100}, b); r.Breach {
		t.Fatal("too few samples")
	}
	b.MinVolume = 1000
	if r := anomaly(300, samples, b); r.Breach {
		t.Fatal("min volume")
	}
	if r := anomaly(5, []float64{0, 0}, Baseline{K: 3}); !math.IsInf(r.Deviation, 1) {
		t.Fatal("zero sigma deviation")
	}
	if e, br := drop(0.5, []float64{10, 10, 12}, 0.1, 1, 2); !br || e != 10 {
		t.Fatal("drop")
	}
	if _, br := drop(5, []float64{10, 10}, 0.1, 1, 2); br {
		t.Fatal("no drop")
	}
	if _, br := drop(0, []float64{0.5, 0.5}, 0.1, 1, 2); br {
		t.Fatal("below min volume")
	}
}

func TestRules(t *testing.T) {
	for _, r := range DefaultRules() {
		if err := ValidateRule(r); err != nil {
			t.Errorf("default %s: %v", r.ID, err)
		}
		if s, m := r.SignalMethod(); s == "" || (m != "RED" && m != "USE") {
			t.Errorf("%s: signal %q method %q", r.ID, s, m)
		}
		b, _ := json.Marshal(r)
		var back Rule
		if err := json.Unmarshal(b, &back); err != nil || back.For != r.For || back.Interval != r.Interval {
			t.Errorf("%s: JSON round trip %s: %v", r.ID, b, err)
		}
	}
	bad := []Rule{
		{ID: "X", Kind: KindLinkUtilization, Thresholds: Thresholds{Percent: 80}},
		{ID: "a", Kind: "nope"},
		{ID: "a", Kind: KindLinkUtilization},
		{ID: "a", Kind: KindTrafficAnomaly, Dimensions: []string{"SrcAddr"}},
		{ID: "a", Kind: KindTrafficAnomaly, Filter: "DstPort = 80"},
		{ID: "a", Kind: KindCustom, Thresholds: Thresholds{BPS: 1}},
		{ID: "a", Kind: KindDDoSSyn, Thresholds: Thresholds{Ratio: 2}},
		{ID: "a", Kind: KindLinkUtilization, Thresholds: Thresholds{Percent: 80}, Filter: "Foo = 1"},
		{ID: "a", Kind: KindLinkUtilization, Thresholds: Thresholds{Percent: 80}, Severity: "urgent"},
	}
	for i, r := range bad {
		if ValidateRule(r) == nil {
			t.Errorf("bad rule %d accepted", i)
		}
	}
	c := Rule{ID: "dns", Kind: KindCustom, Signal: "red.traffic.dns", Dimensions: []string{"DstAddr"}, Thresholds: Thresholds{BPS: 1}}
	if err := ValidateRule(c); err != nil {
		t.Fatal(err)
	}
	if s, m := c.SignalMethod(); s != "red.traffic.dns" || m != "RED" {
		t.Fatal(s, m)
	}
	var d Duration
	if err := json.Unmarshal([]byte(`"7d"`), &d); err != nil || d.D() != 7*24*time.Hour {
		t.Fatal(d, err)
	}
	if err := json.Unmarshal([]byte(`90`), &d); err != nil || d.D() != 90*time.Second {
		t.Fatal(d, err)
	}
	if Duration(5*time.Minute).String() != "5m" || Duration(time.Hour).String() != "1h" {
		t.Fatal(Duration(time.Hour).String())
	}
}

func TestTitleLanguage(t *testing.T) {
	for _, c := range []struct {
		v                float64
		unit, lang, want string
	}{
		{4.2e9, "bps", LangEN, "4.2 Gbit/s"},
		{1500, "pps", LangEN, "1.5 kpps"},
		{1500, "pps", "", "1.5 тыс. пак/с"},
		{10, "min", LangEN, "10 min"},
		{10, "min", "de", "10 мин"},
	} {
		if s := formatRate(c.v, c.unit, c.lang); s != c.want {
			t.Errorf("formatRate(%v, %s, %s) = %q, want %q", c.v, c.unit, c.lang, s, c.want)
		}
	}
	if s := groupText(nil, nil, LangEN); s != "all traffic" {
		t.Error(s)
	}
	ru := defaultTitles[KindDDoSVolumetric].ru
	for _, c := range []struct{ title, lang, want string }{
		{"", LangEN, "Volumetric attack on ${dst_ip}: ${value_text}"},
		{"", LangRU, ru},
		{ru, LangEN, "Volumetric attack on ${dst_ip}: ${value_text}"}, // saved by earlier versions
		{"Attack on ${dst_ip}", LangRU, "Attack on ${dst_ip}"},
	} {
		r := Rule{Kind: KindDDoSVolumetric, Title: c.title}
		if got := titleTemplate(r.WithDefaults(), c.lang); got != c.want {
			t.Errorf("title %q in %s = %q, want %q", c.title, c.lang, got, c.want)
		}
	}
	for _, k := range Kinds {
		if d := defaultTitles[k]; d.ru == "" || d.en == "" {
			t.Errorf("kind %s: default title missing", k)
		}
	}
}

func TestTitleAndLinks(t *testing.T) {
	got := renderTitle("Load ${interface} on ${exporter} — ${value_text} ${missing}", map[string]string{"interface": "xe-0/0/1", "exporter": "edge-01", "value_text": formatRate(93.5, "%", LangRU)})
	if got != "Load xe-0/0/1 on edge-01 — 93.5 %" {
		t.Fatal(got)
	}
	if s := formatRate(4.2e9, "bps", LangRU); s != "4.2 Гбит/с" {
		t.Fatal(s)
	}
	from := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	f := andFilters("InIfBoundary = 'external' OR InIfBoundary = 'internal'", ifaceFilter("::ffff:10.0.0.1", "it's", "in"), "DstAddr = "+filterValue("DstAddr", "2001:db8::1"))
	link := visualizeLink("https://flow.example.com/", f, []string{"SrcAS"}, "", from, from.Add(time.Hour))
	u, err := url.Parse(link)
	if err != nil || u.Path != "/visualize" || u.Host != "flow.example.com" {
		t.Fatal(link)
	}
	raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("q"))
	if err != nil {
		t.Fatal(err)
	}
	var v view
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.R[0] != "2026-10-12T09:00:00Z" || v.U != "l3bps" || v.G != "stacked" || v.F != f {
		t.Fatalf("%s", raw)
	}
	if _, err := filter.Compile(v.F); err != nil {
		t.Fatalf("link filter %q: %v", v.F, err)
	}
	if _, err := filter.Compile("DstCI = " + filterValue("DstCI", `a'b\c`) + " AND Proto = " + filterValue("Proto", "6")); err != nil {
		t.Fatal(err)
	}
	if l := incidentLink("https://f", "edge 1", "10.0.0.1", from, from); !strings.HasPrefix(l, "https://f/go/incident?ci=edge+1&ip=10.0.0.1&from=") {
		t.Fatal(l)
	}
	if visualizeLink("", "", nil, "", from, from) != "" {
		t.Fatal("no public URL, no link")
	}
}

type ingest struct {
	mu     sync.Mutex
	srv    *httptest.Server
	events []map[string]any
	auth   []string
	fail   atomic.Int32 // respond 503 to this many requests
	status atomic.Int32 // when non-zero, respond with it
}

func newIngest(t *testing.T) *ingest {
	in := &ingest{}
	in.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in.fail.Load() > 0 {
			in.fail.Add(-1)
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if s := in.status.Load(); s != 0 {
			http.Error(w, "nope", int(s))
			return
		}
		body, _ := io.ReadAll(r.Body)
		var evs []map[string]any
		if err := json.Unmarshal(body, &evs); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		in.mu.Lock()
		in.events = append(in.events, evs...)
		in.auth = append(in.auth, r.Header.Get("Authorization"))
		in.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(in.srv.Close)
	return in
}

func (in *ingest) take() []map[string]any {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := in.events
	in.events = nil
	return out
}

func token(context.Context) (string, error) { return "s3cret", nil }

func TestSender(t *testing.T) {
	in := newIngest(t)
	s := NewSender(SenderConfig{URL: in.srv.URL, Token: token, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond, Attempts: 3, BatchSize: 2})
	ctx := context.Background()
	ev := func(id string) Event {
		return Event{ID: id, Status: StatusFiring, Signal: "use.link.utilization", Severity: "warning", Title: id}
	}

	// Retried on 503 within one delivery.
	in.fail.Store(2)
	if err := s.Deliver(ctx, []Event{ev("a"), ev("b"), ev("c")}); err != nil {
		t.Fatal(err)
	}
	got := in.take()
	if len(got) != 3 || got[0]["id"] != "a" || got[2]["id"] != "c" {
		t.Fatalf("%v", got)
	}
	if in.auth[0] != "Bearer s3cret" {
		t.Fatal(in.auth)
	}
	// Down: events stay in the outbox, in order, and go out later.
	in.fail.Store(100)
	if err := s.Deliver(ctx, []Event{ev("d")}); err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(s.Status().LastError, "s3cret") {
		t.Fatal("token leaked")
	}
	_ = s.Deliver(ctx, []Event{ev("e")})
	if n := len(s.Pending()); n != 2 {
		t.Fatalf("outbox %d", n)
	}
	in.fail.Store(0)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := in.take(); len(got) != 2 || got[0]["id"] != "d" || got[1]["id"] != "e" {
		t.Fatalf("%v", got)
	}
	// 401: kept; 400: dropped.
	in.status.Store(401)
	_ = s.Deliver(ctx, []Event{ev("f")})
	if len(s.Pending()) != 1 {
		t.Fatal("401 must keep the event")
	}
	in.status.Store(400)
	_ = s.Flush(ctx)
	if len(s.Pending()) != 0 || s.Status().Dropped != 1 {
		t.Fatalf("%+v", s.Status())
	}
	in.status.Store(0)
	// Bounded outbox.
	small := NewSender(SenderConfig{URL: "http://127.0.0.1:1", OutboxSize: 2, Attempts: 1})
	_ = small.Deliver(ctx, []Event{ev("1"), ev("2"), ev("3")})
	if p := small.Pending(); len(p) != 2 || p[0].ID != "2" {
		t.Fatalf("%v", p)
	}

	// Test event as in the preset quick test.
	te, err := s.SendTest(ctx, "", LangEN)
	if err != nil {
		t.Fatal(err)
	}
	if te.Title != "Current test event" {
		t.Fatal(te.Title)
	}
	got = in.take()
	if len(got) != 1 || got[0]["id"] != te.ID || got[0]["signal"] != "umbrella_test" || got[0]["status"] != "firing" ||
		got[0]["labels"].(map[string]any)["umbrella_test"] != "true" || !strings.HasPrefix(te.ID, "umbrella-test-") {
		t.Fatalf("%v", got)
	}
	in.status.Store(403)
	if _, err := SendTest(ctx, nil, in.srv.URL, token, "x", ""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatal(err)
	}
}

func TestSnapshotJSON(t *testing.T) {
	m := &MemoryStore{}
	v := 1.5
	snap := &Snapshot{Version: 1, Alerts: []AlertState{{RuleID: "r", Key: "k", State: StateFiring, Since: time.Unix(100, 0).UTC(),
		Event: &Event{ID: "flow-1", Value: &v}}}, Outbox: []Event{{ID: "x"}}}
	if err := m.Save(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalSnapshot(m.Bytes())
	if err != nil || len(back.Alerts) != 1 || *back.Alerts[0].Event.Value != 1.5 || back.Outbox[0].ID != "x" {
		t.Fatalf("%+v %v", back, err)
	}
	if eventID("r", "k", time.Unix(1, 0)) != eventID("r", "k", time.Unix(1, 0)) || eventID("r", "k", time.Unix(1, 0)) == eventID("r", "k2", time.Unix(1, 0)) {
		t.Fatal("event id")
	}
}
