package drivers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTP is the client of a device REST API: base URL from the target, TLS
// verification off unless asked (devices mostly have self-signed
// certificates), a cookie jar for session logins, and default headers.
type HTTP struct {
	Base    string
	Client  *http.Client
	Header  http.Header
	User    string // basic auth when set
	Pass    string
	host    string
	timeout time.Duration
}

// NewHTTP returns the client of a target. scheme is used unless the
// transport is "http"; port 0 = the scheme's default.
func NewHTTP(t Target, scheme string, defaultPort int) *HTTP {
	if t.Transport == "http" {
		scheme = "http"
	}
	port := t.Port
	if port == 0 {
		port = defaultPort
	}
	host := t.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	base := scheme + "://" + host
	if port > 0 {
		base += ":" + strconv.Itoa(port)
	}
	jar, _ := cookiejar.New(nil)
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !t.VerifyTLS}, //nolint:gosec // devices use self-signed certificates unless VerifyTLS
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 2,
	}
	return &HTTP{Base: base, Client: &http.Client{Transport: tr, Jar: jar, Timeout: timeout}, Header: http.Header{}, host: t.Host, timeout: timeout}
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

// Do sends a request; body is JSON-encoded unless it is a []byte. It returns
// the response body of a 2xx answer.
func (h *HTTP) Do(ctx context.Context, method, path string, query url.Values, body any, timeout time.Duration) ([]byte, http.Header, error) {
	u := h.Base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		if b, ok := body.([]byte); ok {
			rd = bytes.NewReader(b)
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, nil, err
			}
			rd = bytes.NewReader(b)
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range h.Header {
		req.Header[k] = v
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if h.User != "" || h.Pass != "" {
		req.SetBasicAuth(h.User, h.Pass)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, resp.Header, err
	}
	if resp.StatusCode/100 != 2 {
		return data, resp.Header, &StatusError{Code: resp.StatusCode, Body: string(data)}
	}
	return data, resp.Header, nil
}

// Error turns a transport or status error into a message for the user.
func (h *HTTP) Error(err error) error {
	var se *StatusError
	if errors.As(err, &se) {
		if se.Code == 401 || se.Code == 403 {
			return Errorf("%s: API denied access (%d); check the credentials", h.host, se.Code)
		}
		b := strings.TrimSpace(se.Body)
		if len(b) > 200 {
			b = b[:200]
		}
		return Errorf("%s: API returned %d: %s", h.host, se.Code, b)
	}
	var de *Error
	if errors.As(err, &de) {
		return err
	}
	return Errorf("%s: API is unreachable (%v)", h.host, err)
}

// optionalCodes are the answers of an optional endpoint that mean "not here".
func optionalCode(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case 400, 403, 404, 405, 501:
		return true
	}
	return false
}

// Get decodes the JSON answer of a GET. optional: an absent endpoint, an
// unreachable path or a non-JSON answer returns nil without an error.
func (h *HTTP) Get(ctx context.Context, path string, optional bool, query url.Values) (any, error) {
	data, _, err := h.Do(ctx, http.MethodGet, path, query, nil, 0)
	if err != nil {
		if optional {
			return nil, nil
		}
		return nil, h.Error(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		if optional {
			return nil, nil
		}
		return nil, Errorf("%s: the API response is not JSON", h.host)
	}
	return v, nil
}

// GetObj is Get of an object (empty when absent).
func (h *HTTP) GetObj(ctx context.Context, path string, optional bool, query url.Values) (Obj, error) {
	v, err := h.Get(ctx, path, optional, query)
	if m, ok := v.(map[string]any); ok {
		return m, err
	}
	return Obj{}, err
}

// Send sends a request and decodes a JSON answer (the text when not JSON).
func (h *HTTP) Send(ctx context.Context, method, path string, body any, timeout time.Duration) (any, error) {
	data, _, err := h.Do(ctx, method, path, nil, body, timeout)
	if err != nil {
		return nil, h.Error(err)
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return string(data), nil
	}
	return v, nil
}

// Text is a GET of a plain text answer.
func (h *HTTP) Text(ctx context.Context, path string, query url.Values, timeout time.Duration) (string, error) {
	data, _, err := h.Do(ctx, http.MethodGet, path, query, nil, timeout)
	if err != nil {
		return "", h.Error(err)
	}
	return string(data), nil
}

// Close drops idle connections.
func (h *HTTP) Close() { h.Client.CloseIdleConnections() }

func q(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}
