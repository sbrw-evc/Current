package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/flowlogs"
	"github.com/sbrw-evc/current/app/backend/internal/rdns"
	"github.com/sbrw-evc/current/app/backend/internal/threat"
)

type memSettings struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memSettings) Setting(_ context.Context, key string, out any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

func (s *memSettings) PutSetting(_ context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[key] = b
	return err
}

type fakeResolver map[string]string

func (f fakeResolver) Resolve(ref string) (string, error) {
	if v, ok := f[ref]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

func TestFlowLogTokens(t *testing.T) {
	st := &memSettings{}
	now := time.Unix(0, 0)
	tk := &flowLogTokens{st: st, vault: fakeResolver{"openbao://flow/flowlogs#aws": "k1"}, ttl: 30 * time.Second, now: func() time.Time { return now }}
	ctx := context.Background()
	if _, err := tk.Token(ctx, flowlogs.AWS); !errors.Is(err, flowlogs.ErrDisabled) {
		t.Fatal(err)
	}
	_ = st.PutSetting(ctx, flowlogs.SettingKey, flowlogs.Settings{AWS: flowlogs.ProviderSettings{Enabled: true, TokenRef: "openbao://flow/flowlogs#aws"}})
	// Cached for 30 s, unless reloaded.
	if _, err := tk.Token(ctx, flowlogs.AWS); !errors.Is(err, flowlogs.ErrDisabled) {
		t.Fatal("not cached", err)
	}
	_ = tk.Reload(ctx, flowlogs.SettingKey)
	if v, err := tk.Token(ctx, flowlogs.AWS); err != nil || v != "k1" {
		t.Fatal(v, err)
	}
	_ = st.PutSetting(ctx, flowlogs.SettingKey, flowlogs.Settings{Azure: flowlogs.ProviderSettings{Enabled: true, TokenRef: "plain"}})
	now = now.Add(31 * time.Second)
	if _, err := tk.Token(ctx, flowlogs.Azure); err == nil || errors.Is(err, flowlogs.ErrDisabled) {
		t.Fatal("plain token accepted", err)
	}
}

func TestExtensionSettingsLoad(t *testing.T) {
	st := &memSettings{}
	ctx := context.Background()
	ts, err := LoadThreatSettings(ctx, st)
	if err != nil || !ts.Enabled || len(ts.Lists) != len(threat.DefaultLists()) {
		t.Fatal(ts, err)
	}
	_ = st.PutSetting(ctx, threat.SettingKey, threat.Settings{Enabled: false})
	if ts, _ = LoadThreatSettings(ctx, st); ts.Enabled || ts.RefreshMinutes != 360 {
		t.Fatal(ts)
	}
	rs, _ := LoadRDNSSettings(ctx, st)
	if rs.Enabled || rs.Workers != 8 {
		t.Fatal(rs)
	}
	r, err := NewRDNS(st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.PutSetting(ctx, rdns.SettingKey, rdns.Settings{Enabled: true, Scope: rdns.ScopePrivate})
	_ = r.Reload(ctx, rdns.SettingKey)
	if s := r.R.Settings(); !s.Enabled || s.Scope != rdns.ScopePrivate {
		t.Fatal(s)
	}
	th, err := NewThreat(st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	th.store(ctx, threat.Status{Prefixes: 7})
	if s, _ := LoadThreatStatus(ctx, st); s.Prefixes != 7 || s.Lists == nil {
		t.Fatal(s)
	}
}
