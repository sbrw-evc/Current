// Package httpx holds HTTP helpers shared by the handlers: JSON replies, the
// error shape {"error": "<code>", "message": "<text>"}, security headers,
// client address behind trusted proxies and the static SPA handler.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// MaxBody limits request bodies read by Decode.
const MaxBody = 1 << 20

// Problem is the error reply.
type Problem struct {
	Code       string   `json:"error"`
	Message    string   `json:"message,omitempty"`
	Field      string   `json:"field,omitempty"`
	Violations []string `json:"violations,omitempty"`
}

// JSON writes v with the status code.
func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes {"error": code, "message": msg}.
func Error(w http.ResponseWriter, status int, code, msg string) {
	JSON(w, status, Problem{Code: code, Message: msg})
}

// Err writes err: an *Error keeps its status and code, any other error is a 500
// with the code "internal" (the text goes to the message).
func Err(w http.ResponseWriter, err error) {
	status, code := StatusOf(err)
	pr := Problem{Code: code, Message: err.Error()}
	var v interface{ PolicyViolations() []string }
	if errors.As(err, &v) {
		pr.Violations = v.PolicyViolations()
	}
	JSON(w, status, pr)
}

// HTTPError is an error with an HTTP status and a machine-readable code. Packages
// behind the API return it (or any error with HTTPStatus() int and optionally
// ErrorCode() string) to answer 4xx instead of 500.
type HTTPError struct {
	Status int
	Code   string
	Msg    string
	Err    error
}

func (e *HTTPError) Error() string {
	switch {
	case e.Msg != "":
		return e.Msg
	case e.Err != nil:
		return e.Err.Error()
	}
	return e.Code
}

func (e *HTTPError) Unwrap() error     { return e.Err }
func (e *HTTPError) HTTPStatus() int   { return e.Status }
func (e *HTTPError) ErrorCode() string { return e.Code }

// BadRequest returns a 400 error with the code and message.
func BadRequest(code, msg string) error {
	return &HTTPError{Status: http.StatusBadRequest, Code: code, Msg: msg}
}

// NotFound returns a 404 error.
func NotFound(msg string) error {
	return &HTTPError{Status: http.StatusNotFound, Code: "not_found", Msg: msg}
}

// StatusOf returns the HTTP status and the error code for err.
func StatusOf(err error) (int, string) {
	var st interface{ HTTPStatus() int }
	if !errors.As(err, &st) {
		return http.StatusInternalServerError, "internal"
	}
	status := st.HTTPStatus()
	code := strings.ToLower(strings.ReplaceAll(http.StatusText(status), " ", "_"))
	var c interface{ ErrorCode() string }
	if errors.As(err, &c) && c.ErrorCode() != "" {
		code = c.ErrorCode()
	}
	return status, code
}

// Decode reads a JSON body into v, rejecting unknown fields; on failure it
// writes a 400 reply and returns false.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		Error(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// Raw reads the body as raw JSON (checked to be valid); on failure it writes a
// 400 reply and returns nil, false. An empty body gives "{}".
func Raw(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(b) > MaxBody {
		Error(w, http.StatusBadRequest, "bad_request", "request body is too large or unreadable")
		return nil, false
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return json.RawMessage("{}"), true
	}
	if !json.Valid(b) {
		Error(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return nil, false
	}
	return json.RawMessage(b), true
}

// Secure sets the security headers.
func Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the client address: the remote address, or the last
// X-Forwarded-For hop not in trusted when the remote address is trusted.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if !inPrefixes(addr, trusted) {
		return addr.String()
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = a.Unmap()
		if !inPrefixes(addr, trusted) {
			break
		}
	}
	return addr.String()
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var imageExt = map[string]bool{".svg": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".avif": true}

// Web serves the built single-page application from dir: existing files as
// is (hashed assets cached for a year), every other path gets index.html so
// the client router handles it. /api/ paths answer a JSON 404. An empty dir
// serves 404 for everything.
func Web(dir string) http.Handler {
	if dir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Error(w, http.StatusNotFound, "not_found", "the web UI is not built (FLOW_WEB_DIR)")
		})
	}
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		if strings.HasPrefix(p, "/api/") || p == "/api" {
			Error(w, http.StatusNotFound, "not_found", "no such API endpoint")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Error(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
			return
		}
		if p != "/" {
			if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err == nil && !fi.IsDir() {
				switch {
				case strings.HasPrefix(p, "/assets/"):
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				case imageExt[strings.ToLower(path.Ext(p))]:
					w.Header().Set("Cache-Control", "public, max-age=604800, stale-while-revalidate=86400")
				}
				files.ServeHTTP(w, r)
				return
			}
			if path.Ext(p) != "" && strings.HasPrefix(p, "/assets/") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}
