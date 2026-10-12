package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Synthetic lists in the formats of the public ones (no real list content).
const (
	netsetList = `#
# synthetic FireHOL-style netset
#
10.0.0.0/8
192.168.0.0/16
198.51.100.0/24
45.0.0.0/16
45.0.7.0/24
2a0a:bad::/32
`
	dropJSON = `{"cidr":"45.0.7.0/24","sblid":"SBL000001","rir":"ripencc"}
{"cidr":"62.0.0.0/22","sblid":"SBL000002","rir":"arin"}
{"type":"metadata","timestamp":1700000000,"size":2,"records":2,"copyright":"synthetic"}
`
	dropText = `; synthetic DROP-style list
; Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT
77.0.0.0/20 ; SBL000003
`
	feodoList = `################################################################
# synthetic Feodo-style IP blocklist                           #
################################################################
91.0.0.5
not-an-address
91.0.0.6 # comment
`
)

type listServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	bodies   map[string]string
	status   map[string]int
	requests atomic.Int64
	notMod   atomic.Int64
}

func newListServer(t *testing.T) *listServer {
	ls := &listServer{bodies: map[string]string{
		"/firehol_level1.netset": netsetList, "/drop_v4.json": dropJSON, "/drop.txt": dropText, "/ipblocklist.txt": feodoList,
	}, status: map[string]int{}}
	ls.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.requests.Add(1)
		ls.mu.Lock()
		body, ok := ls.bodies[r.URL.Path]
		code := ls.status[r.URL.Path]
		ls.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := `"` + r.URL.Path + "-" + strconv.Itoa(len(body)) + `"`
		if r.Header.Get("If-None-Match") == etag {
			ls.notMod.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "umbrella-flow") {
			t.Errorf("User-Agent %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ls.srv.Close)
	return ls
}

func (ls *listServer) set(path, body string, code int) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if body != "" {
		ls.bodies[path] = body
	}
	ls.status[path] = code
}

func testSettings(base string) Settings {
	return Settings{Enabled: true, RefreshMinutes: 60, Lists: []List{
		{Name: "firehol_level1", URL: base + "/firehol_level1.netset", Enabled: true},
		{Name: "spamhaus_drop", URL: base + "/drop_v4.json", Enabled: true},
		{Name: "spamhaus_edrop", URL: base + "/drop.txt", Enabled: true},
		{Name: "feodo", URL: base + "/ipblocklist.txt", Enabled: true},
	}}
}

func TestParse(t *testing.T) {
	ps, bad, err := Parse(strings.NewReader(feodoList))
	if err != nil || bad != 1 || len(ps) != 2 || ps[1] != netip.MustParsePrefix("91.0.0.6/32") {
		t.Fatalf("feodo: %v %d %v", ps, bad, err)
	}
	ps, bad, err = Parse(strings.NewReader(dropJSON))
	if err != nil || bad != 0 || len(ps) != 2 {
		t.Fatalf("drop json: %v %d %v", ps, bad, err)
	}
	ps, _, _ = Parse(strings.NewReader(dropText))
	if len(ps) != 1 || ps[0] != netip.MustParsePrefix("77.0.0.0/20") {
		t.Fatalf("drop text: %v", ps)
	}
	ps, _, _ = Parse(strings.NewReader("::ffff:1.2.3.0/120\n1.2.3.4/16\n"))
	if ps[0] != netip.MustParsePrefix("1.2.3.0/24") || ps[1] != netip.MustParsePrefix("1.2.0.0/16") {
		t.Fatalf("mapped / unmasked: %v", ps)
	}
}

func TestTrie(t *testing.T) {
	b := NewBuilder()
	b.Insert(netip.MustParsePrefix("45.0.0.0/16"), 1)
	b.Insert(netip.MustParsePrefix("45.0.7.0/24"), 2)
	b.Insert(netip.MustParsePrefix("45.0.7.0/24"), 0)
	b.Insert(netip.MustParsePrefix("2a0a:bad::/32"), 3)
	b.Insert(netip.MustParsePrefix("91.0.0.5/32"), 4)
	tr := b.Trie()
	for addr, want := range map[string]int{
		"45.0.1.1": 1, "45.0.7.9": 0, "45.1.0.0": -1, "::ffff:45.0.7.1": 0, "2a0a:bad:1::1": 3, "2a0a:bae::": -1,
		"91.0.0.5": 4, "91.0.0.4": -1,
	} {
		if got := tr.Lookup(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %d, want %d", addr, got, want)
		}
	}
	if tr.Len() != 4 {
		t.Errorf("len %d", tr.Len())
	}
}

func TestUpdater(t *testing.T) {
	ls := newListServer(t)
	reg := prometheus.NewRegistry()
	var stored atomic.Pointer[Status]
	u, err := New(testSettings(ls.srv.URL), Config{Metrics: reg, OnStatus: func(_ context.Context, s Status) { stored.Store(&s) }})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Lookup(netip.MustParseAddr("45.0.1.1")); got != "" {
		t.Fatalf("before the first download: %q", got)
	}
	ctx := context.Background()
	st := u.Refresh(ctx)
	if stored.Load() == nil || len(st.Lists) != 4 {
		t.Fatalf("status %+v", st)
	}
	for _, l := range st.Lists {
		if l.Error != "" || l.UpdatedAt == nil {
			t.Fatalf("list %+v", l)
		}
	}
	// FireHOL: 10/8 and 192.168/16 (bogons), 198.51.100/24 (documentation) skipped.
	if l := st.Lists[0]; l.Prefixes != 3 || l.Skipped != 3 {
		t.Fatalf("firehol %+v", l)
	}
	cases := map[string]string{
		"45.0.1.1":        "firehol_level1",
		"45.0.7.1":        "firehol_level1", // same /24 in two lists: the first configured wins
		"62.0.1.1":        "spamhaus_drop",
		"77.0.15.1":       "spamhaus_edrop",
		"91.0.0.6":        "feodo",
		"2a0a:bad::5":     "firehol_level1",
		"10.1.2.3":        "",
		"192.168.1.1":     "",
		"8.8.8.8":         "",
		"::ffff:91.0.0.5": "feodo",
	}
	for addr, want := range cases {
		if got := u.Lookup(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}

	// Second refresh: not modified, content kept.
	u.Refresh(ctx)
	if ls.notMod.Load() != 4 {
		t.Fatalf("not-modified answers %d", ls.notMod.Load())
	}
	if u.Lookup(netip.MustParseAddr("91.0.0.6")) != "feodo" {
		t.Fatal("content lost after 304")
	}

	// A failing list keeps its previous content and reports the error.
	ls.set("/ipblocklist.txt", "", http.StatusServiceUnavailable)
	st = u.Refresh(ctx)
	if st.Lists[3].Error != "HTTP 503" || u.Lookup(netip.MustParseAddr("91.0.0.6")) != "feodo" {
		t.Fatalf("failing list: %+v", st.Lists[3])
	}

	// Exclusions and disabled lists apply at once, without a download.
	s := testSettings(ls.srv.URL)
	s.Exclude = []string{"45.0.0.0/16"}
	s.Lists[3].Enabled = false
	before := ls.requests.Load()
	if err := u.Configure(s); err != nil {
		t.Fatal(err)
	}
	if ls.requests.Load() != before {
		t.Fatal("Configure downloaded synchronously")
	}
	if got := u.Lookup(netip.MustParseAddr("45.0.1.1")); got != "" {
		t.Errorf("excluded prefix still flagged: %q", got)
	}
	if got := u.Lookup(netip.MustParseAddr("91.0.0.6")); got != "" {
		t.Errorf("disabled list still flagged: %q", got)
	}
	if got := u.Lookup(netip.MustParseAddr("62.0.1.1")); got != "spamhaus_drop" {
		t.Errorf("other list lost: %q", got)
	}

	// Disabled entirely.
	s.Enabled = false
	_ = u.Configure(s)
	if got := u.Lookup(netip.MustParseAddr("62.0.1.1")); got != "" {
		t.Errorf("disabled: %q", got)
	}

	mfs, _ := reg.Gather()
	found := map[string]bool{}
	for _, mf := range mfs {
		found[mf.GetName()] = true
	}
	for _, n := range []string{"flow_threat_lookups_total", "flow_threat_list_prefixes", "flow_threat_list_error", "flow_threat_prefixes"} {
		if !found[n] {
			t.Errorf("metric %s missing", n)
		}
	}
}

func TestUpdaterRunKick(t *testing.T) {
	ls := newListServer(t)
	s := testSettings(ls.srv.URL)
	s.Enabled = false
	u, err := New(s, Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	if ls.requests.Load() != 0 {
		t.Fatal("disabled updater downloaded")
	}
	s.Enabled = true
	if err := u.Configure(s); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for u.Lookup(netip.MustParseAddr("91.0.0.5")) != "feodo" {
		if time.Now().After(deadline) {
			t.Fatal("enabling did not trigger a download")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A refresh requested from the API.
	n := ls.requests.Load()
	now := time.Now()
	s.RefreshRequestedAt = &now
	_ = u.Configure(s)
	for ls.requests.Load() < n+4 {
		if time.Now().After(deadline) {
			t.Fatal("refresh request ignored")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSettingsValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Settings{
		{RefreshMinutes: 5},
		{Lists: []List{{Name: "a b", URL: "https://x"}}},
		{Lists: []List{{Name: "a", URL: "ftp://x"}}},
		{Lists: []List{{Name: "a", URL: "https://x"}, {Name: "a", URL: "https://y"}}},
		{Exclude: []string{"nope"}},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%d accepted", i)
		}
	}
}
