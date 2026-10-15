package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

func TestPassword(t *testing.T) {
	old := Iterations
	Iterations = 1000
	defer func() { Iterations = old }()
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong") || CheckPassword("", "") {
		t.Fatal("password check")
	}
}

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

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		l.Fail("user:a", "ip:1")
	}
	if locked, _ := l.Locked("user:a"); locked {
		t.Fatal("locked too early")
	}
	l.Fail("user:a", "ip:1")
	if locked, d := l.Locked("user:b", "ip:1"); !locked || d != 5*time.Minute {
		t.Fatal(locked, d)
	}
	now = now.Add(6 * time.Minute)
	if locked, _ := l.Locked("user:a"); locked {
		t.Fatal("lock did not expire")
	}
}

func TestPasswordsInVault(t *testing.T) {
	Iterations = 1000
	fake, vault := secretstest.New(t)
	p := NewPasswords(vault)
	ref, err := p.Set(context.Background(), 42, "secret-password")
	if err != nil || ref != "openbao://flow/users/42#password_hash" {
		t.Fatal(ref, err)
	}
	if h, _ := fake.Get("flow/users/42")["password_hash"].(string); h == "" || h == "secret-password" {
		t.Fatal("hash not stored", h)
	}
	if ok, err := p.Verify(ref, "secret-password"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := p.Verify(ref, "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _ := p.Verify("", "x"); ok {
		t.Fatal("empty ref accepted")
	}
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
}

func TestPolicy(t *testing.T) {
	violated := func(p PasswordPolicy, pw, user string) []string {
		var pe *PolicyError
		if err := p.Validate(pw, user); err != nil && !errors.As(err, &pe) {
			t.Fatal(err)
		} else if pe != nil {
			return pe.Violations
		}
		return nil
	}
	if v := violated(DefaultPolicy, "Short-1", "x"); !slices.Contains(v, ViolationLength) {
		t.Fatal("short accepted", v)
	}
	if v := violated(DefaultPolicy, "Correct-Horse-9", "x"); v != nil {
		t.Fatal(v)
	}
	if v := violated(DefaultPolicy, "Qwerty123456!", "x"); !slices.Contains(v, ViolationCommon) {
		t.Error("common password accepted", v)
	}
	if v := violated(DefaultPolicy, "Admin2024!xx", "admin2024"); !slices.Contains(v, ViolationCommon) {
		t.Error("user name with a few characters accepted", v)
	}
	if v := violated(DefaultPolicy, "Correct-Horse-Ж9", "x"); !slices.Contains(v, ViolationLetters) {
		t.Error("cyrillic accepted by a latin policy", v)
	}
	if err := (PasswordPolicy{MinLength: 12, RequireDigits: true, MinDigits: 4}).Check(); err != nil {
		t.Error(err)
	}
	if err := (PasswordPolicy{MinLength: 8, RequireDigits: true, MinDigits: 8, RequireMixedCase: true}).Check(); err == nil {
		t.Error("impossible policy accepted")
	}
	if err := (PasswordPolicy{MinLength: 12, LockoutAttempts: 2, LockoutMinutes: 5}).Check(); err == nil {
		t.Error("lockout below 3 accepted")
	}
}

func TestPolicyLegacyJSON(t *testing.T) {
	var p PasswordPolicy
	if err := json.Unmarshal([]byte(`{"min_length":14,"letters":true,"digits":true,"symbols":false,"not_username":true}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.MinLength != 14 || !p.RequireDigits || p.MinDigits != 1 || p.RequireSpecial || !p.BlockCommon || p.Letters != LettersAny {
		t.Fatalf("%+v", p)
	}
	b, _ := json.Marshal(DefaultPolicy)
	var q PasswordPolicy
	if err := json.Unmarshal(b, &q); err != nil || q != DefaultPolicy {
		t.Fatalf("%+v %v", q, err)
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
