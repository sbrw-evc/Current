package beacon_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/beacon"
	"github.com/sbrw-evc/current/app/backend/internal/query"
)

func TestClientScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer umb_x" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Query().Get("username") {
		case "ivanov@corp":
			_, _ = w.Write([]byte(`{"username":"ivanov","known":true,"mode":"teams","cis":[{"id":"ci_1","name":"app-01","source_refs":["inventory-db:dcim.device:100"],"ips":["10.0.0.5"]}],"services":[]}`))
		case "weird":
			_, _ = w.Write([]byte(`{"known":true,"mode":"nobody"}`))
		case "broken":
			_, _ = w.Write([]byte(`<html>`))
		default:
			_, _ = w.Write([]byte(`{"known":false}`))
		}
	}))
	defer srv.Close()
	c := &beacon.Client{BaseURL: srv.URL + "/", Token: "umb_x"}
	ctx := context.Background()
	r, err := c.Scope(ctx, "ivanov@corp")
	if err != nil || r.Mode != beacon.ModeTeams || len(r.CIs) != 1 || r.CIs[0].SourceRefs[0] != "inventory-db:dcim.device:100" {
		t.Fatal(r, err)
	}
	if r, err := c.Scope(ctx, "nobody"); err != nil || r.Known {
		t.Fatal(r, err)
	}
	if _, err := c.Scope(ctx, "weird"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := c.Scope(ctx, "broken"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	bad := &beacon.Client{BaseURL: srv.URL, Token: "umb_wrong"}
	var he *beacon.HTTPError
	if _, err := bad.Scope(ctx, "x"); !errors.As(err, &he) || he.Status != 401 {
		t.Fatal(err)
	}
	if _, err := (&beacon.Client{}).Scope(ctx, "x"); !errors.Is(err, beacon.ErrNotConfigured) {
		t.Fatal(err)
	}
	down := &beacon.Client{BaseURL: "http://127.0.0.1:1", Token: "t", HTTP: &http.Client{Timeout: time.Second}}
	if _, err := down.Scope(ctx, "x"); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatal(err)
	}
}

func TestScopeCache(t *testing.T) {
	var calls atomic.Int32
	fail := atomic.Bool{}
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	c := beacon.NewScopeCache(func(_ context.Context, u string) (*beacon.ScopeReply, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("down")
		}
		return &beacon.ScopeReply{Username: u, Known: true, Mode: beacon.ModeAll}, nil
	})
	c.Now = func() time.Time { return now }
	ctx := context.Background()
	for _, u := range []string{"Ivanov", "ivanov", " IVANOV "} {
		if _, _, err := c.Get(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d: the login is case-insensitive and cached", calls.Load())
	}
	now = now.Add(59 * time.Second)
	_, _, _ = c.Get(ctx, "ivanov")
	if calls.Load() != 1 {
		t.Fatal("refetched before 60 s")
	}
	now = now.Add(2 * time.Second)
	fail.Store(true)
	if _, _, err := c.Get(ctx, "ivanov"); err == nil {
		t.Fatal("expired entry must be refetched and fail")
	}
	// Errors are kept only a few seconds.
	_, _, _ = c.Get(ctx, "ivanov")
	if calls.Load() != 2 {
		t.Fatalf("calls %d", calls.Load())
	}
	now = now.Add(6 * time.Second)
	fail.Store(false)
	if _, _, err := c.Get(ctx, "ivanov"); err != nil || calls.Load() != 3 {
		t.Fatal(err, calls.Load())
	}
	c.Invalidate()
	_, _, _ = c.Get(ctx, "ivanov")
	if calls.Load() != 4 {
		t.Fatal("Invalidate kept the entry")
	}
}

func TestQueryScope(t *testing.T) {
	if beacon.QueryScope(&beacon.ScopeReply{Known: true, Mode: beacon.ModeAll}) != nil {
		t.Fatal("mode all is unrestricted")
	}
	if s := beacon.QueryScope(&beacon.ScopeReply{Known: false}); s == nil || !s.Empty() {
		t.Fatal("unknown user sees nothing")
	}
	s := beacon.QueryScope(&beacon.ScopeReply{Known: true, Mode: beacon.ModeSelected, CIs: []beacon.ScopeCI{
		{SourceRefs: []string{"a", "b"}, IPs: []string{"10.0.0.1"}}, {SourceRefs: []string{"a"}, IPs: []string{"2001:db8::1"}}}})
	if len(s.Refs) != 2 || len(s.Prefixes) != 2 {
		t.Fatalf("%+v", s)
	}
	if s := beacon.QueryScope(&beacon.ScopeReply{Known: true, Mode: beacon.ModeTeams}); !s.Empty() {
		t.Fatal("teams without CIs sees nothing")
	}
}

func TestProposals(t *testing.T) {
	from := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	to := from.Add(7 * 24 * time.Hour)
	pairs := []query.DependencyPair{
		{ClientRef: "inventory-db:dcim.device:100", ClientName: "app-01", ClientIP: "10.0.0.5", ServerRef: "inventory-db:dcim.device:200",
			ServerName: "db-01", ServerIP: "10.0.1.9", Proto: 6, Port: 5432, App: "postgres", Bytes: 123456789, Flows: 4200, DaysSeen: 7},
		{ClientRef: "inventory-db:dcim.device:100", ServerRef: "inventory-db:dcim.device:200", Proto: 6, Port: 5432}, // duplicate key
	}
	props := beacon.BuildProposals(pairs, "https://flow.corp/", from, to)
	if len(props) != 1 {
		t.Fatal(props)
	}
	p := props[0]
	if p.Key != "flow:inventory-db:dcim.device:100->inventory-db:dcim.device:200:tcp/5432" || p.Type != "depends_on" ||
		p.From.Name != "app-01" || p.To.IP != "10.0.1.9" || p.Evidence.Bytes7d != 123456789 || p.Evidence.DaysSeen != 7 {
		t.Fatalf("%+v", p)
	}
	u := p.Evidence.FlowURL
	if !strings.HasPrefix(u, "https://flow.corp/visualize?q=") {
		t.Fatal(u)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(u, "https://flow.corp/visualize?q="))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		R [2]string
		F string
	}
	_ = json.Unmarshal(raw, &v)
	if v.R[0] != "2026-10-05T10:00:00Z" || v.F != "SrcCI = 'inventory-db:dcim.device:100' AND DstCI = 'inventory-db:dcim.device:200' AND Proto = 6 AND DstPort = 5432" {
		t.Fatalf("%+v", v)
	}
	if beacon.BuildProposals(pairs, "", from, to)[0].Evidence.FlowURL != "" {
		t.Fatal("no public URL → no link")
	}
	// The wire format of §3.3.
	b, _ := json.Marshal(beacon.Batch{Source: beacon.Source, GeneratedAt: to, Proposals: props})
	for _, k := range []string{`"source":"umbrella-flow"`, `"generated_at":"2026-10-12T10:00:00Z"`, `"from":{"source_ref":`, `"bytes_7d":123456789`, `"flows_7d":4200`, `"days_seen":7`, `"first_seen":`, `"flow_url":`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("batch lacks %s: %s", k, b)
		}
	}
}

func TestSendProposals(t *testing.T) {
	var got beacon.Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/cmdb/proposals" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"accepted":1,"updated":2,"ignored":3}`))
	}))
	defer srv.Close()
	c := &beacon.Client{BaseURL: srv.URL, Token: "t"}
	out, err := c.SendProposals(context.Background(), beacon.Batch{Proposals: []beacon.Proposal{{Key: "k"}}})
	if err != nil || out.Accepted != 1 || out.Updated != 2 || out.Ignored != 3 || got.Source != "umbrella-flow" || got.Proposals[0].Key != "k" {
		t.Fatal(out, err, got)
	}
}
