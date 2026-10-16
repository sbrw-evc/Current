// Package flowlogs receives cloud flow logs over HTTP and turns them into
// flow records on the pipeline bus, next to NetFlow / IPFIX / sFlow:
//
//   - AWS VPC Flow Logs (default version 2 format and custom formats, with a
//     header line or a fields parameter): plain text lines, CloudWatch Logs
//     subscription JSON, or Kinesis Data Firehose HTTP endpoint deliveries
//     (base64 records, X-Amz-Firehose-Access-Key);
//   - Azure NSG flow logs (versions 1 and 2) and VNet flow logs (version 4);
//   - GCP VPC Flow Logs as Pub/Sub push messages (or plain LogEntry JSON).
//
// Every request is authenticated with the provider's token from OpenBao.
package flowlogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// Providers.
const (
	AWS   = "aws"
	Azure = "azure"
	GCP   = "gcp"
)

// Providers lists the providers in display order.
var Providers = []string{AWS, Azure, GCP}

// Flow types of the records.
const (
	FlowTypeAWS   = "aws-vpc"
	FlowTypeAzure = "azure-vnet"
	FlowTypeGCP   = "gcp-vpc"
)

// SettingKey is the PostgreSQL settings key; tokens live in OpenBao at
// SecretPath, one key per provider.
const (
	SettingKey = "flowlogs"
	SecretPath = "flowlogs"
)

// ProviderSettings of one provider.
type ProviderSettings struct {
	Enabled  bool   `json:"enabled"`
	TokenRef string `json:"token_ref,omitempty"` // openbao:// reference, never returned by the API
}

// Settings of the ingest endpoints.
type Settings struct {
	AWS   ProviderSettings `json:"aws"`
	Azure ProviderSettings `json:"azure"`
	GCP   ProviderSettings `json:"gcp"`
}

// Provider returns the settings of a provider.
func (s *Settings) Provider(p string) *ProviderSettings {
	switch p {
	case AWS:
		return &s.AWS
	case Azure:
		return &s.Azure
	case GCP:
		return &s.GCP
	}
	return nil
}

// ErrDisabled: the provider is not enabled or has no token.
var ErrDisabled = errors.New("flow logs ingestion is not enabled for this provider")

// TokenFunc returns the expected token of a provider, ErrDisabled when the
// provider is off.
type TokenFunc func(ctx context.Context, provider string) (string, error)

// Config of the Handler.
type Config struct {
	Sink  flow.Sink // the bus
	Token TokenFunc
	// MaxBody bounds a request body after decompression (default 64 MiB).
	MaxBody int64
	// BatchSize: flows per Put (default 1000).
	BatchSize int
	Metrics   prometheus.Registerer
	Log       *slog.Logger
	Now       func() time.Time
}

// Handler serves POST /api/ingest/flowlogs/{provider}.
type Handler struct {
	cfg      Config
	records  *prometheus.CounterVec
	requests *prometheus.CounterVec
}

// New returns the handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Sink == nil || cfg.Token == nil {
		return nil, errors.New("flowlogs: Sink and Token are required")
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 64 << 20
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := &Handler{cfg: cfg,
		records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flow_flowlogs_records_total", Help: "Cloud flow log records by provider and result (accepted, skipped).",
		}, []string{"provider", "result"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flow_flowlogs_requests_total", Help: "Cloud flow log ingest requests by provider and HTTP status.",
		}, []string{"provider", "code"}),
	}
	if cfg.Metrics != nil {
		for _, c := range []prometheus.Collector{h.records, h.requests} {
			if err := cfg.Metrics.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return h, nil
}

// Result of an ingest request.
type Result struct {
	Accepted int `json:"accepted"`
	Skipped  int `json:"skipped"`
}

type httpError struct {
	code      int
	errCode   string
	message   string
	retryable bool
}

func (e *httpError) Error() string { return e.message }

func badRequest(format string, args ...any) error {
	return &httpError{code: http.StatusBadRequest, errCode: "invalid_flowlogs", message: fmt.Sprintf(format, args...)}
}

// ServeHTTP handles a request; the provider is the {provider} path value
// (or the last path element).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("provider")
	if p == "" {
		p = r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	}
	firehose := p == AWS && r.Header.Get("X-Amz-Firehose-Request-Id") != ""
	res, err := h.serve(r, p, firehose)
	code := http.StatusOK
	var he *httpError
	if err != nil {
		if !errors.As(err, &he) {
			he = &httpError{code: http.StatusInternalServerError, errCode: "internal", message: err.Error()}
		}
		code = he.code
	}
	if p == AWS || p == Azure || p == GCP {
		h.requests.WithLabelValues(p, fmt.Sprint(code)).Inc()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if firehose {
		// Kinesis Data Firehose HTTP endpoint delivery response.
		out := map[string]any{"requestId": r.Header.Get("X-Amz-Firehose-Request-Id"), "timestamp": h.cfg.Now().UnixMilli()}
		if he != nil {
			out["errorMessage"] = he.message
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	if he != nil {
		if he.code == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="flowlogs"`)
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": he.errCode, "message": he.message})
		return
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(res)
}

func (h *Handler) serve(r *http.Request, p string, firehose bool) (Result, error) {
	ctx := r.Context()
	if p != AWS && p != Azure && p != GCP {
		return Result{}, &httpError{code: http.StatusNotFound, errCode: "not_found", message: "unknown flow log provider " + p}
	}
	want, err := h.cfg.Token(ctx, p)
	if errors.Is(err, ErrDisabled) {
		return Result{}, &httpError{code: http.StatusForbidden, errCode: "flowlogs_disabled", message: ErrDisabled.Error()}
	}
	if err != nil {
		h.cfg.Log.Warn("flow logs token not available", "provider", p, "err", err)
		return Result{}, &httpError{code: http.StatusServiceUnavailable, errCode: "openbao_unavailable", message: "the ingest token cannot be read"}
	}
	if want == "" || subtle.ConstantTimeCompare([]byte(presented(r, p)), []byte(want)) != 1 {
		return Result{}, &httpError{code: http.StatusUnauthorized, errCode: "unauthorized", message: "missing or wrong ingest token"}
	}
	body, err := h.readBody(r)
	if err != nil {
		return Result{}, err
	}
	b := &batch{h: h, ctx: ctx, provider: p, now: h.cfg.Now()}
	switch {
	case p == AWS && firehose:
		err = parseFirehose(body, b, r.URL.Query().Get("fields"))
	case p == AWS:
		err = parseAWSBody(body, b, r.URL.Query().Get("fields"))
	case p == Azure:
		err = parseAzure(body, b)
	case p == GCP:
		err = parseGCP(body, b)
	}
	if err == nil {
		err = b.flush()
	}
	h.records.WithLabelValues(p, "accepted").Add(float64(b.accepted))
	h.records.WithLabelValues(p, "skipped").Add(float64(b.skipped))
	return Result{Accepted: b.accepted, Skipped: b.skipped}, err
}

// presented is the token sent by the client: the Firehose access key
// header (AWS), a Bearer token, or a token query parameter (for Pub/Sub
// push subscriptions, which cannot send a static header).
func presented(r *http.Request, p string) string {
	if p == AWS {
		if k := r.Header.Get("X-Amz-Firehose-Access-Key"); k != "" {
			return k
		}
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return r.URL.Query().Get("token")
}

func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	var rd io.Reader = http.MaxBytesReader(nil, r.Body, h.cfg.MaxBody)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(rd)
		if err != nil {
			return nil, badRequest("gzip: %v", err)
		}
		defer zr.Close()
		rd = zr
	}
	body, err := io.ReadAll(io.LimitReader(rd, h.cfg.MaxBody+1))
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) || int64(len(body)) > h.cfg.MaxBody {
		return nil, &httpError{code: http.StatusRequestEntityTooLarge, errCode: "too_large", message: fmt.Sprintf("body larger than %d bytes", h.cfg.MaxBody)}
	}
	if err != nil {
		return nil, badRequest("body: %v", err)
	}
	return body, nil
}

// gunzipMaybe decompresses gzip data (CloudWatch Logs subscription
// payloads), returns other data as is.
func gunzipMaybe(b []byte, limit int64) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, errors.New("decompressed record too large")
	}
	return out, nil
}

// batch collects the flows of one request and puts them on the bus in
// chunks.
type batch struct {
	h        *Handler
	ctx      context.Context
	provider string
	now      time.Time
	flows    []*flow.Flow
	accepted int
	skipped  int
	err      error
}

func (b *batch) add(f *flow.Flow) {
	if b.err != nil {
		return
	}
	if f.SamplingRate == 0 {
		f.SamplingRate = 1
	}
	if f.TimeReceived.IsZero() {
		f.TimeReceived = b.received(f.TimeFlowEnd)
	}
	b.flows = append(b.flows, f)
	if len(b.flows) >= b.h.cfg.BatchSize {
		b.err = b.flush()
	}
}

func (b *batch) skip() { b.skipped++ }

// received is the time a record is stored under: the flow's end when it is
// within the last day (logs arrive minutes late; graphs should show the
// traffic when it happened), else now.
func (b *batch) received(end time.Time) time.Time {
	if end.IsZero() || end.After(b.now.Add(time.Minute)) || end.Before(b.now.Add(-24*time.Hour)) {
		return b.now.UTC()
	}
	return end.UTC()
}

func (b *batch) flush() error {
	if b.err != nil {
		return b.err
	}
	if len(b.flows) == 0 {
		return nil
	}
	if err := b.h.cfg.Sink.Put(b.ctx, b.flows); err != nil {
		b.err = &httpError{code: http.StatusServiceUnavailable, errCode: "bus_unavailable", message: "flows not accepted by the bus: " + err.Error(), retryable: true}
		return b.err
	}
	b.accepted += len(b.flows)
	b.flows = nil
	return nil
}
