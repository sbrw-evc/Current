package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]store.Session
}

func (m *memStore) CreateSession(_ context.Context, s store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[s.IDHash] = s
	return nil
}
func (m *memStore) GetSession(_ context.Context, h string) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[h]
	if !ok {
		return s, store.ErrNotFound
	}
	return s, nil
}
func (m *memStore) TouchSession(_ context.Context, h string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.m[h]
	s.LastSeen = at
	m.m[h] = s
	return nil
}
func (m *memStore) DeleteSession(_ context.Context, h string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, h)
	return nil
}
func (m *memStore) DeleteUserSessions(_ context.Context, id int64, keep string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.m {
		if s.UserID == id && k != keep {
			delete(m.m, k)
		}
	}
	return nil
}
func (m *memStore) PurgeSessions(context.Context, time.Time, time.Time) (int64, error) { return 0, nil }

func TestSessions(t *testing.T) {
	ms := &memStore{m: map[string]store.Session{}}
	_, vault := secretstest.New(t)
	keys := NewKeys(vault)
	if err := keys.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := NewSessions(ms, keys, true)
	now := time.Now()
	s.now = func() time.Time { return now }
	ctx := context.Background()
	rec := httptest.NewRecorder()
	ss, err := s.Create(ctx, rec, 7, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != CookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("%+v", cookie)
	}
	if _, ok := ms.m[ss.ID]; ok {
		t.Fatal("raw session id stored")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	got, err := s.Get(ctx, req)
	if err != nil || got == nil || got.UserID != 7 || got.CSRF != ss.CSRF {
		t.Fatal(got, err)
	}
	now = now.Add(IdleTimeout + time.Minute)
	if got, _ := s.Get(ctx, req); got != nil {
		t.Fatal("idle session accepted")
	}
	if len(ms.m) != 0 {
		t.Fatal("expired session kept")
	}
}

func TestKeys(t *testing.T) {
	fake, vault := secretstest.New(t)
	keys := NewKeys(vault)
	if err := keys.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	k1 := fake.Get("flow/keys")["session"]
	_ = keys.Ensure(context.Background())
	if fake.Get("flow/keys")["session"] != k1 {
		t.Fatal("keys regenerated")
	}
	h1, _ := keys.SessionHash("abc")
	c1, _ := keys.CSRF("abc")
	if h1 == "" || c1 == "" || h1 == c1 {
		t.Fatal(h1, c1)
	}
	m1, err1 := keys.StateMAC(context.Background(), "s1")
	m2, _ := keys.StateMAC(context.Background(), "s2")
	if err1 != nil || len(m1) != 32 || string(m1) == string(m2) || fake.Get("flow/keys")["state"] == nil {
		t.Fatal("state key", err1)
	}
}

func TestAPITokens(t *testing.T) {
	_, vault := secretstest.New(t)
	keys := NewKeys(vault)
	ctx := context.Background()
	tok := NewAPIToken()
	if !WellFormedToken(tok) || WellFormedToken(tok+"x") || WellFormedToken("umb_"+tok[5:]) || WellFormedToken(tok[:20]+"!"+tok[21:]) {
		t.Fatal("token format", tok)
	}
	// The key is created on first use.
	h1, err := keys.TokenHash(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := keys.TokenHash(ctx, tok)
	h3, _ := keys.TokenHash(ctx, NewAPIToken())
	if h1 != h2 || h1 == h3 || len(h1) != 64 {
		t.Fatal("hash", h1, h2, h3)
	}
	if TokenDisplay(tok) != tok[:9]+"…" {
		t.Fatal(TokenDisplay(tok))
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "bearer "+tok)
	if got, ok := BearerToken(r); !ok || got != tok {
		t.Fatal("bearer")
	}
	r.Header.Set("Authorization", "Basic x")
	if _, ok := BearerToken(r); ok {
		t.Fatal("basic accepted")
	}
}
