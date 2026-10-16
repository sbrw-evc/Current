package wiring

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
	"github.com/sbrw-evc/current/app/backend/internal/flowlogs"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
)

// LoadFlowLogsSettings returns the stored cloud flow log settings (all
// providers disabled when none were saved).
func LoadFlowLogsSettings(ctx context.Context, st SettingStore) (flowlogs.Settings, error) {
	var s flowlogs.Settings
	if st == nil {
		return s, nil
	}
	_, err := st.Setting(ctx, flowlogs.SettingKey, &s)
	return s, err
}

// flowLogTokens resolves the ingest tokens: settings from PostgreSQL cached
// for 30 s (OpenBao reads are cached by the client), so a change made by the
// API of another process applies within half a minute.
type flowLogTokens struct {
	st    SettingStore
	vault secrets.Resolver

	mu  sync.Mutex
	at  time.Time
	cur flowlogs.Settings
	err error
	ttl time.Duration
	now func() time.Time
}

func (t *flowLogTokens) Reload(_ context.Context, what string) error {
	if what == flowlogs.SettingKey {
		t.mu.Lock()
		t.at = time.Time{}
		t.mu.Unlock()
	}
	return nil
}

func (t *flowLogTokens) settings(ctx context.Context) (flowlogs.Settings, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.at.IsZero() && t.now().Sub(t.at) < t.ttl {
		return t.cur, t.err
	}
	t.cur, t.err = LoadFlowLogsSettings(ctx, t.st)
	t.at = t.now()
	return t.cur, t.err
}

func (t *flowLogTokens) Token(ctx context.Context, provider string) (string, error) {
	s, err := t.settings(ctx)
	if err != nil {
		return "", err
	}
	p := s.Provider(provider)
	if p == nil || !p.Enabled || p.TokenRef == "" {
		return "", flowlogs.ErrDisabled
	}
	if !secrets.IsRef(p.TokenRef) {
		return "", fmt.Errorf("the %s ingest token is stored outside OpenBao", provider)
	}
	return secrets.Value(t.vault, p.TokenRef)
}

// FlowLogs is the cloud flow log ingest of an API process.
type FlowLogs struct {
	H      *flowlogs.Handler
	tokens *flowLogTokens
}

// NewFlowLogs returns the ingest handler putting flows into sink (the bus).
func NewFlowLogs(sink flow.Sink, st SettingStore, vault secrets.Resolver, reg prometheus.Registerer, log *slog.Logger) (*FlowLogs, error) {
	tk := &flowLogTokens{st: st, vault: vault, ttl: 30 * time.Second, now: time.Now}
	h, err := flowlogs.New(flowlogs.Config{Sink: sink, Token: tk.Token, Metrics: reg, Log: log})
	if err != nil {
		return nil, err
	}
	return &FlowLogs{H: h, tokens: tk}, nil
}

// Reload implements app.Reloader (what = flowlogs.SettingKey).
func (f *FlowLogs) Reload(ctx context.Context, what string) error { return f.tokens.Reload(ctx, what) }
