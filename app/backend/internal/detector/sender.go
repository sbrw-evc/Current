package detector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sink receives the events of the detector.
type Sink interface {
	Deliver(ctx context.Context, events []Event) error
}

// TokenFunc returns the Bearer token of the Umbrella ingest endpoint. The
// platform reads it from OpenBao on each call (with its cache); the sender
// never stores nor logs it.
type TokenFunc func(ctx context.Context) (string, error)

// SenderConfig configures the Umbrella sender.
type SenderConfig struct {
	URL        string       // Umbrella ingest URL (…/api/ingest/<slug>)
	Token      TokenFunc    // may be nil: no Authorization header
	Client     *http.Client // default: 15 s timeout
	BatchSize  int          // events per POST; default 100
	OutboxSize int          // undelivered events kept; default 10000 (oldest dropped)
	Attempts   int          // attempts per batch on 429 / 5xx / network errors; default 4
	MinBackoff time.Duration
	MaxBackoff time.Duration // default 500 ms … 10 s; Retry-After is honoured up to MaxBackoff
	Logger     *slog.Logger
}

func (c SenderConfig) withDefaults() SenderConfig {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.OutboxSize <= 0 {
		c.OutboxSize = 10000
	}
	if c.Attempts <= 0 {
		c.Attempts = 4
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = 500 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 10 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Sender posts events to Umbrella. Events that cannot be delivered stay in
// a bounded outbox, in order, and are retried on the next Deliver or Flush.
type Sender struct {
	mu      sync.Mutex
	cfg     SenderConfig
	outbox  []Event
	dropped uint64
	sent    uint64
	lastOK  time.Time
	lastErr string
	sendMu  sync.Mutex // one delivery at a time keeps the order
}

// NewSender returns a sender.
func NewSender(cfg SenderConfig) *Sender { return &Sender{cfg: cfg.withDefaults()} }

// SetTarget changes the ingest URL and token provider (settings changed).
func (s *Sender) SetTarget(url string, token TokenFunc) {
	s.mu.Lock()
	s.cfg.URL, s.cfg.Token = url, token
	s.mu.Unlock()
}

// SenderStatus is shown on the detector page.
type SenderStatus struct {
	URL         string    `json:"url"`
	Outbox      int       `json:"outbox"`
	Sent        uint64    `json:"sent"`
	Dropped     uint64    `json:"dropped"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	Configured  bool      `json:"configured"`
}

func (s *Sender) Status() SenderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SenderStatus{URL: s.cfg.URL, Outbox: len(s.outbox), Sent: s.sent, Dropped: s.dropped,
		LastSuccess: s.lastOK, LastError: s.lastErr, Configured: s.cfg.URL != ""}
}

// Pending returns a copy of the outbox (persisted by the detector).
func (s *Sender) Pending() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.outbox...)
}

// Restore puts events back in the outbox (after a restart), ahead of new ones.
func (s *Sender) Restore(events []Event) {
	s.mu.Lock()
	s.outbox = append(append([]Event(nil), events...), s.outbox...)
	s.trimLocked()
	s.mu.Unlock()
}

func (s *Sender) trimLocked() {
	if over := len(s.outbox) - s.cfg.OutboxSize; over > 0 {
		s.outbox = append([]Event(nil), s.outbox[over:]...)
		s.dropped += uint64(over)
		s.cfg.Logger.Warn("umbrella outbox full, oldest events dropped", "dropped", over)
	}
}

// Deliver queues events and sends the outbox. The error tells that some
// events are still queued (they will be retried).
func (s *Sender) Deliver(ctx context.Context, events []Event) error {
	s.mu.Lock()
	s.outbox = append(s.outbox, events...)
	s.trimLocked()
	s.mu.Unlock()
	return s.Flush(ctx)
}

// Flush sends the outbox in batches, stopping at the first batch that
// cannot be delivered.
func (s *Sender) Flush(ctx context.Context) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for {
		s.mu.Lock()
		cfg := s.cfg
		n := min(len(s.outbox), cfg.BatchSize)
		batch := append([]Event(nil), s.outbox[:n]...)
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		if cfg.URL == "" {
			return errors.New("umbrella: ingest URL is not configured")
		}
		err := s.sendWithRetry(ctx, cfg, batch)
		s.mu.Lock()
		var perm *permanentError
		switch {
		case err == nil:
			s.sent += uint64(n)
			s.lastOK, s.lastErr = time.Now(), ""
		case errors.As(err, &perm):
			// The payload will never be accepted: drop it.
			s.dropped += uint64(n)
			s.lastErr = err.Error()
			cfg.Logger.Error("umbrella rejected events, dropped", "events", n, "err", err)
		default:
			s.lastErr = err.Error()
			s.mu.Unlock()
			return err
		}
		// The outbox may have been trimmed meanwhile: remove what was sent by identity.
		s.outbox = removePrefix(s.outbox, batch)
		s.mu.Unlock()
	}
}

func removePrefix(outbox, batch []Event) []Event {
	i := 0
	for i < len(outbox) && i < len(batch) && outbox[i].ID == batch[i].ID && outbox[i].Status == batch[i].Status {
		i++
	}
	return append([]Event(nil), outbox[i:]...)
}

type permanentError struct{ msg string }

func (e *permanentError) Error() string { return e.msg }

type retryError struct {
	msg   string
	after time.Duration
}

func (e *retryError) Error() string { return e.msg }

func (s *Sender) sendWithRetry(ctx context.Context, cfg SenderConfig, batch []Event) error {
	backoff := cfg.MinBackoff
	var err error
	for attempt := 1; ; attempt++ {
		err = post(ctx, cfg, batch)
		var re *retryError
		if err == nil || !errors.As(err, &re) || attempt >= cfg.Attempts {
			return err
		}
		wait := backoff
		if re.after > 0 {
			wait = min(re.after, cfg.MaxBackoff)
		}
		cfg.Logger.Warn("umbrella delivery failed, retrying", "events", len(batch), "attempt", attempt, "backoff", wait, "err", err)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		backoff = min(backoff*2, cfg.MaxBackoff)
	}
}

// post sends one batch. Errors are *retryError (429, 5xx, network, token,
// 401/403/404: may succeed later) or *permanentError (other 4xx).
func post(ctx context.Context, cfg SenderConfig, batch []Event) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return &permanentError{msg: "umbrella: encode events: " + err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return &permanentError{msg: "umbrella: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "umbrella-flow-detector")
	if cfg.Token != nil {
		tok, err := cfg.Token(ctx)
		if err != nil {
			return &retryError{msg: "umbrella: token: " + err.Error()}
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return &retryError{msg: "umbrella: " + err.Error()}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg := fmt.Sprintf("umbrella: HTTP %d", resp.StatusCode)
	if t := strings.TrimSpace(string(snippet)); t != "" {
		if len(t) > 200 {
			t = t[:200] + "…"
		}
		msg += ": " + t
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusRequestTimeout:
		re := &retryError{msg: msg}
		if v := resp.Header.Get("Retry-After"); v != "" {
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				re.after = time.Duration(secs) * time.Second
			}
		}
		// 401/403/404 are configuration problems: keep the events but do not
		// hammer the endpoint within this delivery.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return &configError{retryError: re}
		}
		return re
	default:
		return &permanentError{msg: msg}
	}
}

// configError: kept in the outbox, not retried within the same delivery.
type configError struct{ *retryError }

// TestEvent is the event the "Send test event" button sends: the Umbrella
// label umbrella_test=true keeps its incident away from PagerDuty and
// backup notification.
func TestEvent(ci string) Event {
	var b [6]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	if ci == "" {
		ci = "umbrella-flow"
	}
	return Event{
		ID:       "umbrella-test-" + nonce,
		Status:   StatusFiring,
		Signal:   "umbrella_test",
		Method:   "USE",
		Severity: "warning",
		Title:    "Тестовое событие Umbrella Flow",
		CI:       ci,
		Labels:   map[string]string{"umbrella_test": "true", "source": "umbrella-flow"},
		StartsAt: rfc3339(time.Now()),
	}
}

// SendTest posts one test event to url with the token (no retries, no
// outbox) — for the setup wizard and the settings page, before the
// settings are saved.
func SendTest(ctx context.Context, client *http.Client, url string, token TokenFunc, ci string) (Event, error) {
	if url == "" {
		return Event{}, errors.New("umbrella: ingest URL is empty")
	}
	cfg := SenderConfig{URL: url, Token: token, Client: client}.withDefaults()
	ev := TestEvent(ci)
	return ev, unwrapErr(post(ctx, cfg, []Event{ev}))
}

// SendTest sends a test event to the configured target.
func (s *Sender) SendTest(ctx context.Context, ci string) (Event, error) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	return SendTest(ctx, cfg.Client, cfg.URL, cfg.Token, ci)
}

func unwrapErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(err.Error())
}
