package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/store"
)

const (
	// CookieName is the session cookie (HttpOnly, SameSite=Lax).
	CookieName = "flow_session"
	// CSRFHeader carries the csrf value of the session on state-changing requests.
	CSRFHeader = "X-CSRF-Token"
)

var (
	IdleTimeout = 12 * time.Hour
	MaxLifetime = 7 * 24 * time.Hour
	// touchEvery limits last_seen writes to one per session per minute.
	touchEvery = time.Minute
)

// SessionStore persists sessions; *store.Store implements it.
type SessionStore interface {
	CreateSession(ctx context.Context, s store.Session) error
	GetSession(ctx context.Context, idHash string) (store.Session, error)
	TouchSession(ctx context.Context, idHash string, at time.Time) error
	DeleteSession(ctx context.Context, idHash string) error
	DeleteUserSessions(ctx context.Context, userID int64, keepHash string) error
	PurgeSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error)
}

// Session is a valid session; ID is the cookie value.
type Session struct {
	ID       string
	UserID   int64
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

// SessionKeys hashes session IDs and derives CSRF tokens (*Keys).
type SessionKeys interface {
	SessionHash(id string) (string, error)
	CSRF(id string) (string, error)
}

// Sessions creates, checks and ends sessions.
type Sessions struct {
	st     SessionStore
	keys   SessionKeys
	secure bool
	now    func() time.Time
}

// NewSessions returns a session manager; secure sets the Secure cookie flag.
func NewSessions(st SessionStore, keys SessionKeys, secure bool) *Sessions {
	return &Sessions{st: st, keys: keys, secure: secure, now: time.Now}
}

// Create starts a session for the user and sets the cookie.
func (s *Sessions) Create(ctx context.Context, w http.ResponseWriter, userID int64, remote string) (*Session, error) {
	now := s.now().UTC()
	ss := &Session{ID: RandomToken("", 32), UserID: userID, Created: now, LastSeen: now}
	h, err := s.keys.SessionHash(ss.ID)
	if err != nil {
		return nil, err
	}
	if ss.CSRF, err = s.keys.CSRF(ss.ID); err != nil {
		return nil, err
	}
	if err := s.st.CreateSession(ctx, store.Session{IDHash: h, UserID: userID, Remote: remote,
		Created: now, LastSeen: now}); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: ss.ID, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(MaxLifetime / time.Second)})
	return ss, nil
}

// Get returns the session of the request's cookie, or nil when there is none
// or it has expired.
func (s *Sessions) Get(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return nil, nil
	}
	h, err := s.keys.SessionHash(c.Value)
	if err != nil {
		return nil, err
	}
	row, err := s.st.GetSession(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if now.Sub(row.LastSeen) > IdleTimeout || now.Sub(row.Created) > MaxLifetime {
		_ = s.st.DeleteSession(ctx, h)
		return nil, nil
	}
	if now.Sub(row.LastSeen) > touchEvery {
		if err := s.st.TouchSession(ctx, h, now.UTC()); err != nil {
			slog.Warn("session not touched", "err", err)
		}
		row.LastSeen = now
	}
	csrf, err := s.keys.CSRF(c.Value)
	if err != nil {
		return nil, err
	}
	return &Session{ID: c.Value, UserID: row.UserID, CSRF: csrf, Created: row.Created, LastSeen: row.LastSeen}, nil
}

// Delete ends the session of the request and clears the cookie.
func (s *Sessions) Delete(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	s.ClearCookie(w)
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	h, err := s.keys.SessionHash(c.Value)
	if err != nil {
		return err
	}
	return s.st.DeleteSession(ctx, h)
}

// ClearCookie removes the session cookie in the browser.
func (s *Sessions) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// DeleteUser ends every session of the user except keep (a cookie value, "" = all).
func (s *Sessions) DeleteUser(ctx context.Context, userID int64, keep string) error {
	k := ""
	if keep != "" {
		var err error
		if k, err = s.keys.SessionHash(keep); err != nil {
			return err
		}
	}
	return s.st.DeleteUserSessions(ctx, userID, k)
}

// Run deletes expired sessions every 10 minutes until ctx ends.
func (s *Sessions) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		now := s.now()
		if n, err := s.st.PurgeSessions(ctx, now.Add(-IdleTimeout), now.Add(-MaxLifetime)); err != nil && ctx.Err() == nil {
			slog.Warn("expired sessions not purged", "err", err)
		} else if n > 0 {
			slog.Debug("expired sessions purged", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Limiter locks sign-in for a key (user name, client address) after
// MaxFailures failures within the window, for LockFor.
type Limiter struct {
	MaxFailures int
	Window      time.Duration
	LockFor     time.Duration

	mu  sync.Mutex
	m   map[string]*attempts
	now func() time.Time
}

type attempts struct {
	n     int
	first time.Time
	until time.Time
}

// NewLimiter: 5 failures in 15 minutes lock the key for 5 minutes.
func NewLimiter() *Limiter {
	return &Limiter{MaxFailures: 5, Window: 15 * time.Minute, LockFor: 5 * time.Minute, m: map[string]*attempts{}, now: time.Now}
}

// Locked reports whether any key is locked and for how long.
func (l *Limiter) Locked(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		if a := l.m[k]; a != nil && now.Before(a.until) {
			return true, a.until.Sub(now)
		}
	}
	return false, 0
}

// Fail counts a failure for every key.
func (l *Limiter) Fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, a := range l.m { // keep the map small
		if now.Sub(a.first) > l.Window && now.After(a.until) {
			delete(l.m, k)
		}
	}
	for _, k := range keys {
		a := l.m[k]
		if a == nil || now.Sub(a.first) > l.Window {
			a = &attempts{first: now}
			l.m[k] = a
		}
		a.n++
		if a.n >= l.MaxFailures {
			a.until, a.n, a.first = now.Add(l.LockFor), 0, now
		}
	}
}

// Reset forgets the failures of the keys after a successful sign-in.
func (l *Limiter) Reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.m, k)
	}
}

// Tune changes the threshold and the lock duration (the password policy's
// lockout); zero values keep the current ones.
func (l *Limiter) Tune(maxFailures int, lockFor time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if maxFailures > 0 {
		l.MaxFailures = maxFailures
	}
	if lockFor > 0 {
		l.LockFor = lockFor
	}
}
