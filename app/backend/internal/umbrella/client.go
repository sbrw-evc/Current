// Package umbrella is Flow's client of the Umbrella Monitoring API
// (docs/integrations.md §3): visibility scopes of users (§3.2) with a 60 s
// per-user cache, and CMDB dependency proposals built from steady CI ↔ CI
// traffic (§3.3). Flow calls Umbrella with a service-account token
// (Authorization: Bearer umb_…) kept in OpenBao.
package umbrella

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the Umbrella API.
type Client struct {
	// BaseURL is Umbrella's address (https://umbrella.example), without /api.
	BaseURL string
	// Token is the service-account token.
	Token string
	// HTTP is the client (default: 15 s timeout).
	HTTP *http.Client
}

// ErrNotConfigured: no Umbrella address or token.
var ErrNotConfigured = errors.New("the Umbrella API connection is not configured (Settings → Umbrella)")

// HTTPError is a non-2xx answer of Umbrella.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	switch e.Status {
	case http.StatusUnauthorized:
		return "Umbrella rejected the service-account token (401)"
	case http.StatusForbidden:
		return "the Umbrella service account lacks the permission (403): " + msg
	}
	if msg == "" {
		return fmt.Sprintf("Umbrella answered %d", e.Status)
	}
	return fmt.Sprintf("Umbrella answered %d: %s", e.Status, msg)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" || c.Token == "" {
		return ErrNotConfigured
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("Umbrella is unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{Status: resp.StatusCode, Body: string(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("Umbrella answered with invalid JSON: %w", err)
	}
	return nil
}

// ScopeCI is a CI of a scope.
type ScopeCI struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	SourceRefs []string `json:"source_refs"`
	IPs        []string `json:"ips"`
}

// ScopeService is a service of a scope.
type ScopeService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Scope modes.
const (
	ModeAll      = "all"
	ModeTeams    = "teams"
	ModeSelected = "selected"
)

// ScopeReply is GET /api/integrations/flow/scope.
type ScopeReply struct {
	Username string         `json:"username"`
	Known    bool           `json:"known"`
	Mode     string         `json:"mode"`
	CIs      []ScopeCI      `json:"cis"`
	Services []ScopeService `json:"services"`
}

// Scope asks Umbrella what username may see.
func (c *Client) Scope(ctx context.Context, username string) (*ScopeReply, error) {
	var out ScopeReply
	if err := c.do(ctx, http.MethodGet, "/api/integrations/flow/scope?username="+url.QueryEscape(username), nil, &out); err != nil {
		return nil, err
	}
	if out.Known {
		switch out.Mode {
		case ModeAll, ModeTeams, ModeSelected:
		default:
			return nil, fmt.Errorf("Umbrella returned an unknown scope mode %q", out.Mode)
		}
	}
	return &out, nil
}

// ProposalsResult is the answer to POST /api/cmdb/proposals.
type ProposalsResult struct {
	Accepted int `json:"accepted"`
	Updated  int `json:"updated"`
	Ignored  int `json:"ignored"`
}

// Batch is the body of POST /api/cmdb/proposals.
type Batch struct {
	Source      string     `json:"source"`
	GeneratedAt time.Time  `json:"generated_at"`
	Proposals   []Proposal `json:"proposals"`
}

// SendProposals posts the proposals to Umbrella's CMDB.
func (c *Client) SendProposals(ctx context.Context, b Batch) (*ProposalsResult, error) {
	if b.Source == "" {
		b.Source = Source
	}
	if b.Proposals == nil {
		b.Proposals = []Proposal{}
	}
	var out ProposalsResult
	if err := c.do(ctx, http.MethodPost, "/api/cmdb/proposals", b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
