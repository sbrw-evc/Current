// Package threat downloads public IP blocklists (FireHOL level1, Spamhaus
// DROP / EDROP, abuse.ch Feodo Tracker by default; any URL list can be
// configured) at run time, keeps them in a longest-prefix-match trie and
// names the list an address belongs to. The lists are never stored in the
// repository or the image: each installation fetches them under the lists'
// own terms of use.
package threat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// SettingKey and StatusKey are the PostgreSQL settings keys of the settings
// and of the last update status (written by the process that downloads, read
// by the API of any process).
const (
	SettingKey = "threat"
	StatusKey  = "threat_status"
)

// List is one blocklist.
type List struct {
	// Name is what the SrcThreat / DstThreat columns hold.
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// Terms: where the list's terms of use are (shown in the console).
	Terms string `json:"terms,omitempty"`
}

// Settings of threat intelligence.
type Settings struct {
	Enabled bool   `json:"enabled"`
	Lists   []List `json:"lists"`
	// RefreshMinutes between downloads (default 360, minimum 60: the list
	// owners ask not to poll more often).
	RefreshMinutes int `json:"refresh_minutes"`
	// Exclude: prefixes never flagged (own networks); special-purpose
	// ranges (RFC 1918, CGNAT, loopback, link-local, multicast, ULA,
	// reserved) are always excluded.
	Exclude []string `json:"exclude"`
	// RefreshRequestedAt: a download requested from the API, picked up by
	// the downloading process within a minute.
	RefreshRequestedAt *time.Time `json:"refresh_requested_at,omitempty"`
}

// DefaultLists are the free public lists enabled by default.
func DefaultLists() []List {
	return []List{
		{Name: "firehol_level1", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", Enabled: true,
			Terms: "https://iplists.firehol.org/?ipset=firehol_level1"},
		{Name: "spamhaus_drop", URL: "https://www.spamhaus.org/drop/drop_v4.json", Enabled: true,
			Terms: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
		{Name: "spamhaus_drop_v6", URL: "https://www.spamhaus.org/drop/drop_v6.json", Enabled: true,
			Terms: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
		{Name: "spamhaus_edrop", URL: "https://www.spamhaus.org/drop/edrop.txt", Enabled: false,
			Terms: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/ (EDROP is merged into DROP since 2024)"},
		{Name: "feodo", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Enabled: true,
			Terms: "https://feodotracker.abuse.ch/ (CC0)"},
	}
}

// Default returns the settings used until some are saved.
func Default() Settings {
	return Settings{Enabled: true, Lists: DefaultLists(), RefreshMinutes: 360, Exclude: []string{}}
}

// WithDefaults fills zero values.
func (s Settings) WithDefaults() Settings {
	if s.RefreshMinutes <= 0 {
		s.RefreshMinutes = 360
	}
	if s.Lists == nil {
		s.Lists = []List{}
	}
	if s.Exclude == nil {
		s.Exclude = []string{}
	}
	return s
}

var listNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Validate checks the settings.
func (s Settings) Validate() error {
	var errs []error
	if s.RefreshMinutes != 0 && s.RefreshMinutes < 60 {
		errs = append(errs, errors.New("refresh_minutes: at least 60"))
	}
	if len(s.Lists) > 64 {
		errs = append(errs, errors.New("at most 64 lists"))
	}
	seen := map[string]bool{}
	for _, l := range s.Lists {
		if !listNameRe.MatchString(l.Name) {
			errs = append(errs, fmt.Errorf("list name %q: letters, digits, '.', '_', '-' (max 64)", l.Name))
		}
		if seen[l.Name] {
			errs = append(errs, fmt.Errorf("list name %q is repeated", l.Name))
		}
		seen[l.Name] = true
		u, err := url.Parse(l.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("list %s: url must be http(s)://…", l.Name))
		}
	}
	for _, e := range s.Exclude {
		if _, err := parsePrefix(e); err != nil {
			errs = append(errs, fmt.Errorf("exclude %q: not an address or prefix", e))
		}
	}
	return errors.Join(errs...)
}

// special-purpose ranges never flagged: a listed prefix overlapping one of
// them is skipped (FireHOL level1 includes the bogons, which would mark
// every internal host).
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		"::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "64:ff9b::/96",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// SpecialRanges are the always-excluded prefixes.
func SpecialRanges() []netip.Prefix { return slices.Clone(special) }

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// maxPrefixes bounds one list; maxBody bounds one download.
const (
	maxPrefixes = 2_000_000
	maxBody     = 64 << 20
)

// Parse reads a blocklist: one address or prefix per line, comments after
// '#' or ';' (FireHOL netset, Spamhaus drop.txt / edrop.txt, abuse.ch),
// or JSON lines with a "cidr" field (Spamhaus drop_v4.json / drop_v6.json).
// It returns the prefixes and the number of lines that were not
// understood.
func Parse(r io.Reader) ([]netip.Prefix, int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []netip.Prefix
	bad := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		var field string
		if line[0] == '{' {
			var v struct {
				CIDR string `json:"cidr"`
			}
			if err := json.Unmarshal(line, &v); err != nil || v.CIDR == "" {
				// Spamhaus' trailing metadata line has no cidr.
				if err != nil {
					bad++
				}
				continue
			}
			field = v.CIDR
		} else {
			s := string(line)
			if i := strings.IndexAny(s, "#;"); i >= 0 {
				s = s[:i]
			}
			fs := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
			if len(fs) == 0 {
				continue
			}
			field = fs[0]
		}
		p, err := parsePrefix(field)
		if err != nil {
			bad++
			continue
		}
		if len(out) >= maxPrefixes {
			return out, bad, fmt.Errorf("more than %d entries", maxPrefixes)
		}
		out = append(out, p)
	}
	return out, bad, sc.Err()
}

// ListStatus is the state of one list.
type ListStatus struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	Prefixes int    `json:"prefixes"`
	// Skipped: entries ignored (special-purpose or excluded ranges, lines
	// not understood).
	Skipped   int        `json:"skipped"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"` // last successful download (or not-modified answer)
	CheckedAt *time.Time `json:"checked_at,omitempty"` // last attempt
	Error     string     `json:"error,omitempty"`
}

// Status is the result of the last refresh.
type Status struct {
	UpdatedAt *time.Time   `json:"updated_at,omitempty"`
	Prefixes  int          `json:"prefixes"`
	Lists     []ListStatus `json:"lists"`
}

type listState struct {
	prefixes      []netip.Prefix
	etag, lastMod string
	url           string
	status        ListStatus
}

type table struct {
	trie    *Trie
	names   []string
	matches []atomic.Uint64
}

// Config of an Updater.
type Config struct {
	Client *http.Client // default: 60 s timeout
	// UserAgent of the downloads.
	UserAgent string
	// OnStatus is called after every refresh (e.g. to store the status in
	// PostgreSQL for the API).
	OnStatus func(context.Context, Status)
	Metrics  prometheus.Registerer
	Now      func() time.Time
}

// Updater downloads the lists and answers lookups.
type Updater struct {
	cfg Config
	set atomic.Pointer[Settings]
	cur atomic.Pointer[table]

	refreshMu sync.Mutex // one refresh at a time
	mu        sync.Mutex // lists, last, table rebuilds
	lists     map[string]*listState
	status    atomic.Pointer[Status]
	last      time.Time // last refresh start
	kick      chan struct{}

	lookups, hits atomic.Uint64
}

// New returns an updater with settings s; call Run (or Refresh).
func New(s Settings, cfg Config) (*Updater, error) {
	s = s.WithDefaults()
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "current-threat/1"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	u := &Updater{cfg: cfg, lists: map[string]*listState{}, kick: make(chan struct{}, 1)}
	u.set.Store(&s)
	u.cur.Store(&table{trie: NewBuilder().Trie()})
	u.status.Store(&Status{Lists: []ListStatus{}})
	if cfg.Metrics != nil {
		if err := u.register(cfg.Metrics); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// Settings returns the settings in effect.
func (u *Updater) Settings() Settings { return *u.set.Load() }

// Configure applies new settings. The table is rebuilt from the lists
// already downloaded at once (disabled lists drop out, exclusions apply);
// new or changed lists are downloaded by Run right away.
func (u *Updater) Configure(s Settings) error {
	s = s.WithDefaults()
	if err := s.Validate(); err != nil {
		return err
	}
	old := u.set.Swap(&s)
	u.mu.Lock()
	u.rebuildLocked()
	u.mu.Unlock()
	if needsDownload(old, &s) {
		u.Kick()
	}
	return nil
}

func needsDownload(old, s *Settings) bool {
	if !s.Enabled {
		return false
	}
	if !old.Enabled {
		return true
	}
	have := map[string]string{}
	for _, l := range old.Lists {
		if l.Enabled {
			have[l.Name] = l.URL
		}
	}
	for _, l := range s.Lists {
		if l.Enabled && have[l.Name] != l.URL {
			return true
		}
	}
	return s.RefreshRequestedAt != nil && (old.RefreshRequestedAt == nil || s.RefreshRequestedAt.After(*old.RefreshRequestedAt))
}

// Kick asks Run to refresh now.
func (u *Updater) Kick() {
	select {
	case u.kick <- struct{}{}:
	default:
	}
}

// Lookup returns the name of the list holding a ("" when none or disabled).
func (u *Updater) Lookup(a netip.Addr) string {
	t := u.cur.Load()
	if t.trie.Len() == 0 {
		return ""
	}
	u.lookups.Add(1)
	i := t.trie.Lookup(a)
	if i < 0 {
		return ""
	}
	u.hits.Add(1)
	t.matches[i].Add(1)
	return t.names[i]
}

// Status returns the result of the last refresh.
func (u *Updater) Status() Status { return *u.status.Load() }

// Run refreshes at start, every RefreshMinutes and when kicked, until ctx
// is done.
func (u *Updater) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	if u.set.Load().Enabled {
		u.Refresh(ctx)
		select { // a Configure before Run is covered by this refresh
		case <-u.kick:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.kick:
			u.Refresh(ctx)
		case <-t.C:
			s := u.set.Load()
			u.mu.Lock()
			due := u.cfg.Now().Sub(u.last) >= time.Duration(s.RefreshMinutes)*time.Minute
			u.mu.Unlock()
			if s.Enabled && due {
				u.Refresh(ctx)
			}
		}
	}
}

// Refresh downloads every enabled list now and rebuilds the table. A list
// that fails keeps its previous content. Lookups and Configure are not
// blocked by the downloads.
func (u *Updater) Refresh(ctx context.Context) Status {
	u.refreshMu.Lock()
	defer u.refreshMu.Unlock()
	s := u.set.Load()
	type job struct {
		list List
		prev listState
		res  fetchResult
	}
	var jobs []*job
	u.mu.Lock()
	u.last = u.cfg.Now()
	for _, l := range s.Lists {
		if !s.Enabled || !l.Enabled {
			continue
		}
		st := u.lists[l.Name]
		if st == nil || st.url != l.URL {
			st = &listState{url: l.URL}
			u.lists[l.Name] = st
		}
		jobs = append(jobs, &job{list: l, prev: *st})
	}
	u.mu.Unlock()

	for _, j := range jobs {
		j.res = u.fetch(ctx, j.list, j.prev)
	}

	u.mu.Lock()
	for _, j := range jobs {
		st := u.lists[j.list.Name]
		if st == nil || st.url != j.list.URL {
			continue // changed meanwhile
		}
		r := j.res
		st.status.CheckedAt = &r.at
		switch {
		case r.err != nil:
			st.status.Error = r.err.Error()
		case r.notModified:
			st.status.UpdatedAt, st.status.Error = &r.at, ""
		default:
			st.prefixes, st.status.Skipped = r.prefixes, r.bad
			st.etag, st.lastMod = r.etag, r.lastMod
			st.status.UpdatedAt, st.status.Error = &r.at, ""
		}
	}
	cur := u.set.Load()
	for name := range u.lists {
		if !slices.ContainsFunc(cur.Lists, func(l List) bool { return l.Name == name }) {
			delete(u.lists, name)
		}
	}
	u.rebuildLocked()
	status := *u.status.Load()
	u.mu.Unlock()
	if u.cfg.OnStatus != nil {
		u.cfg.OnStatus(ctx, status)
	}
	return status
}

type fetchResult struct {
	at            time.Time
	err           error
	notModified   bool
	prefixes      []netip.Prefix
	bad           int
	etag, lastMod string
}

func (u *Updater) fetch(ctx context.Context, l List, prev listState) fetchResult {
	res := fetchResult{at: u.cfg.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		res.err = err
		return res
	}
	req.Header.Set("User-Agent", u.cfg.UserAgent)
	if prev.status.UpdatedAt != nil {
		if prev.etag != "" {
			req.Header.Set("If-None-Match", prev.etag)
		}
		if prev.lastMod != "" {
			req.Header.Set("If-Modified-Since", prev.lastMod)
		}
	}
	resp, err := u.cfg.Client.Do(req)
	if err != nil {
		res.err = err
		return res
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && prev.status.UpdatedAt != nil:
		res.notModified = true
		return res
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		res.err = fmt.Errorf("HTTP %d", resp.StatusCode)
		return res
	}
	cr := &countReader{r: io.LimitReader(resp.Body, maxBody+1)}
	prefixes, bad, err := Parse(cr)
	if err == nil && cr.n > maxBody {
		err = fmt.Errorf("larger than %d MiB", maxBody>>20)
	}
	if err != nil {
		res.err = err
		return res
	}
	res.prefixes, res.bad = prefixes, bad
	res.etag, res.lastMod = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	return res
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func excluded(p netip.Prefix, extra []netip.Prefix) bool {
	for _, q := range special {
		if q.Overlaps(p) {
			return true
		}
	}
	for _, q := range extra {
		if q.Overlaps(p) {
			return true
		}
	}
	return false
}

// rebuildLocked builds the table from the downloaded lists and the current
// settings and publishes the status.
func (u *Updater) rebuildLocked() {
	s := u.set.Load()
	var extra []netip.Prefix
	for _, e := range s.Exclude {
		if p, err := parsePrefix(e); err == nil {
			extra = append(extra, p)
		}
	}
	b := NewBuilder()
	var names []string
	status := Status{Lists: []ListStatus{}}
	if old := u.status.Load(); old != nil {
		status.UpdatedAt = old.UpdatedAt
	}
	for _, l := range s.Lists {
		ls := ListStatus{Name: l.Name, URL: l.URL, Enabled: l.Enabled}
		st := u.lists[l.Name]
		if st != nil && st.url == l.URL {
			ls = st.status
			ls.Name, ls.URL, ls.Enabled = l.Name, l.URL, l.Enabled
			ls.Prefixes = 0
			skipped := 0
			if s.Enabled && l.Enabled {
				idx := len(names)
				names = append(names, l.Name)
				for _, p := range st.prefixes {
					if excluded(p, extra) {
						skipped++
						continue
					}
					b.Insert(p, idx)
					ls.Prefixes++
				}
			}
			ls.Skipped = st.status.Skipped + skipped
		}
		status.Lists = append(status.Lists, ls)
	}
	t := &table{trie: b.Trie(), names: names, matches: make([]atomic.Uint64, len(names))}
	if !s.Enabled {
		t = &table{trie: NewBuilder().Trie()}
	}
	// Keep the match counters of lists that stay.
	if old := u.cur.Load(); old != nil {
		for i, n := range old.names {
			if j := slices.Index(t.names, n); j >= 0 {
				t.matches[j].Store(old.matches[i].Load())
			}
		}
	}
	u.cur.Store(t)
	status.Prefixes = t.trie.Len()
	if !u.last.IsZero() {
		at := u.last.UTC()
		status.UpdatedAt = &at
	}
	u.status.Store(&status)
}

func (u *Updater) register(reg prometheus.Registerer) error {
	matches := prometheus.NewDesc("flow_threat_matches_total", "Flow addresses found in a threat list, by list.", []string{"list"}, nil)
	prefixes := prometheus.NewDesc("flow_threat_list_prefixes", "Prefixes loaded per threat list.", []string{"list"}, nil)
	updated := prometheus.NewDesc("flow_threat_list_updated_timestamp_seconds", "Last successful download of a threat list.", []string{"list"}, nil)
	failing := prometheus.NewDesc("flow_threat_list_error", "1 when the last download of a threat list failed.", []string{"list"}, nil)
	cs := []prometheus.Collector{
		prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "flow_threat_lookups_total", Help: "Addresses looked up in the threat lists."},
			func() float64 { return float64(u.lookups.Load()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "flow_threat_prefixes", Help: "Distinct prefixes in the threat table."},
			func() float64 { return float64(u.cur.Load().trie.Len()) }),
		collectorFunc{descs: []*prometheus.Desc{matches, prefixes, updated, failing}, collect: func(ch chan<- prometheus.Metric) {
			t := u.cur.Load()
			for i, n := range t.names {
				ch <- prometheus.MustNewConstMetric(matches, prometheus.CounterValue, float64(t.matches[i].Load()), n)
			}
			for _, l := range u.status.Load().Lists {
				ch <- prometheus.MustNewConstMetric(prefixes, prometheus.GaugeValue, float64(l.Prefixes), l.Name)
				if l.UpdatedAt != nil {
					ch <- prometheus.MustNewConstMetric(updated, prometheus.GaugeValue, float64(l.UpdatedAt.Unix()), l.Name)
				}
				e := 0.0
				if l.Error != "" {
					e = 1
				}
				ch <- prometheus.MustNewConstMetric(failing, prometheus.GaugeValue, e, l.Name)
			}
		}},
	}
	for _, c := range cs {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

type collectorFunc struct {
	descs   []*prometheus.Desc
	collect func(chan<- prometheus.Metric)
}

func (c collectorFunc) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c collectorFunc) Collect(ch chan<- prometheus.Metric) { c.collect(ch) }
