package flowlogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// The samples in testdata are synthetic records written after the public
// format descriptions (no real customer data).

type sink struct {
	mu    sync.Mutex
	flows []*flow.Flow
	puts  int
	fail  bool
}

func (s *sink) Put(_ context.Context, fs []*flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("bus full")
	}
	s.puts++
	s.flows = append(s.flows, fs...)
	return nil
}

var tokens = map[string]string{AWS: "aws-secret", Azure: "azure-secret", GCP: "gcp-secret"}

func newServer(t *testing.T, mod func(*Config)) (*httptest.Server, *sink) {
	t.Helper()
	s := &sink{}
	cfg := Config{Sink: s, Metrics: prometheus.NewRegistry(),
		Now: func() time.Time { return time.Unix(1760000300, 0) },
		Token: func(_ context.Context, p string) (string, error) {
			if p == GCP && os.Getenv("X_DISABLED") == "1" {
				return "", ErrDisabled
			}
			return tokens[p], nil
		}}
	if mod != nil {
		mod(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /api/ingest/flowlogs/{provider}", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s
}

func post(t *testing.T, url string, body []byte, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bearer(p string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tokens[p]}
}

func TestAWSDefaultFormat(t *testing.T) {
	srv, s := newServer(t, nil)
	resp, out := post(t, srv.URL+"/api/ingest/flowlogs/aws", read(t, "aws-v2.log"), bearer(AWS))
	if resp.StatusCode != 200 || out["accepted"] != 3.0 || out["skipped"] != 1.0 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	f := s.flows[0]
	if f.FlowType != FlowTypeAWS || f.SrcAddr != netip.MustParseAddr("10.0.1.5") || f.DstPort != 443 || f.Proto != 6 ||
		f.Packets != 20 || f.Bytes != 4249 || f.SamplingRate != 1 || f.ForwardingStatus != fwdForwarded || f.EType != 0x0800 {
		t.Fatalf("flow %+v", f)
	}
	if !f.TimeFlowEnd.Equal(time.Unix(1760000060, 0)) || !f.TimeReceived.Equal(f.TimeFlowEnd) {
		t.Fatalf("times %v %v", f.TimeFlowEnd, f.TimeReceived)
	}
	if !Prefix.Contains(f.ExporterAddress) {
		t.Fatalf("exporter %s", f.ExporterAddress)
	}
	if n, _ := ExporterName(f.ExporterAddress); n != "eni-0a1b2c3d4e5f60718" {
		t.Fatalf("exporter name %q", n)
	}
	// The id survives without the in-process name registry (other roles).
	if n, _ := decode(f.ExporterAddress); n != "eni-0a1b2c3d4e5f60718" {
		t.Fatalf("decoded %q", n)
	}
	if s.flows[1].ForwardingStatus != fwdDropped || s.flows[2].EType != 0x86dd {
		t.Fatalf("reject / v6: %+v %+v", s.flows[1], s.flows[2])
	}
}

func TestAWSCustomFormatHeaderAndFields(t *testing.T) {
	srv, s := newServer(t, nil)
	resp, out := post(t, srv.URL+"/api/ingest/flowlogs/aws", read(t, "aws-custom.log"), bearer(AWS))
	if resp.StatusCode != 200 || out["accepted"] != 2.0 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	f := s.flows[0]
	if f.TCPFlags != 18 || f.Bytes != 1500 || f.Packets != 3 || f.DstPort != 80 {
		t.Fatalf("custom %+v", f)
	}
	if n, _ := ExporterName(f.ExporterAddress); n != "vpc-0f1e2d3c4b5a69788/eni-0a1b2c3d4e5f60718" {
		t.Fatalf("name %q", n)
	}
	// No interface id: the VPC is the exporter.
	if n, _ := decode(s.flows[1].ExporterAddress); n != "vpc-0f1e2d3c4b5a69788" {
		t.Fatalf("vpc exporter %q", n)
	}

	// Headerless custom format given as a parameter.
	s.flows = nil
	body := "eni-0a1b2c3d4e5f60718 10.0.0.1 10.0.0.2 6 100\n"
	resp, out = post(t, srv.URL+"/api/ingest/flowlogs/aws?fields="+strings.ReplaceAll("${interface-id} ${srcaddr} ${dstaddr} ${protocol} ${bytes}", " ", "%20"),
		[]byte(body), bearer(AWS))
	if resp.StatusCode != 200 || out["accepted"] != 1.0 || s.flows[0].Bytes != 100 {
		t.Fatalf("fields param: %d %v", resp.StatusCode, out)
	}
	// No time in the record: stored as received now.
	if !s.flows[0].TimeReceived.Equal(time.Unix(1760000300, 0)) {
		t.Fatalf("received %v", s.flows[0].TimeReceived)
	}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestAWSFirehose(t *testing.T) {
	srv, s := newServer(t, nil)
	lines := read(t, "aws-v2.log")
	cw, _ := json.Marshal(map[string]any{"messageType": "DATA_MESSAGE", "logEvents": []map[string]string{
		{"id": "1", "message": "2 123456789010 eni-0a1b2c3d4e5f60718 10.0.1.5 203.0.113.12 49153 443 6 2 100 1760000000 1760000060 ACCEPT OK"},
	}})
	req, _ := json.Marshal(map[string]any{"requestId": "req-1", "timestamp": 1760000300000, "records": []map[string]string{
		{"data": base64.StdEncoding.EncodeToString(lines)},
		{"data": base64.StdEncoding.EncodeToString(gz(cw))}, // CloudWatch Logs subscription → Firehose
		{"data": "%%%not-base64"},
	}})
	hdr := map[string]string{"X-Amz-Firehose-Request-Id": "req-1", "X-Amz-Firehose-Access-Key": tokens[AWS], "Content-Type": "application/json"}
	resp, out := post(t, srv.URL+"/api/ingest/flowlogs/aws", req, hdr)
	if resp.StatusCode != 200 || out["requestId"] != "req-1" || out["timestamp"] != 1760000300000.0 || out["errorMessage"] != nil {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	if len(s.flows) != 4 {
		t.Fatalf("flows %d", len(s.flows))
	}
	// Gzip content encoding (Firehose GZIP option).
	resp, _ = post(t, srv.URL+"/api/ingest/flowlogs/aws", gz(req), map[string]string{"X-Amz-Firehose-Request-Id": "req-2",
		"X-Amz-Firehose-Access-Key": tokens[AWS], "Content-Encoding": "gzip"})
	if resp.StatusCode != 200 || len(s.flows) != 8 {
		t.Fatalf("gzip: %d %d", resp.StatusCode, len(s.flows))
	}
	// Wrong key: Firehose-style error.
	hdr["X-Amz-Firehose-Access-Key"] = "nope"
	resp, out = post(t, srv.URL+"/api/ingest/flowlogs/aws", req, hdr)
	if resp.StatusCode != 401 || out["errorMessage"] == nil || out["requestId"] != "req-1" {
		t.Fatalf("bad key: %d %v", resp.StatusCode, out)
	}
}

func TestAzure(t *testing.T) {
	srv, s := newServer(t, nil)
	resp, out := post(t, srv.URL+"/api/ingest/flowlogs/azure", read(t, "azure-nsg-v2.json"), bearer(Azure))
	// Tuple 1: begin record without counts (skipped); tuple 2: both
	// directions; tuple 3: one direction.
	if resp.StatusCode != 200 || out["accepted"] != 3.0 || out["skipped"] != 1.0 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	in, back := s.flows[0], s.flows[1]
	if in.SrcAddr != netip.MustParseAddr("203.0.113.50") || in.Bytes != 3000 || in.Packets != 12 || in.DstPort != 443 || in.Proto != 6 {
		t.Fatalf("in %+v", in)
	}
	if back.SrcAddr != netip.MustParseAddr("10.5.16.4") || back.SrcPort != 443 || back.Bytes != 12000 {
		t.Fatalf("reverse %+v", back)
	}
	if s.flows[2].Proto != 17 || in.FlowType != FlowTypeAzure || !in.TimeFlowEnd.Equal(time.Unix(1760000010, 0)) {
		t.Fatalf("udp %+v", s.flows[2])
	}
	if n, _ := ExporterName(in.ExporterAddress); n != "WEB-NSG/000D3AF87856" {
		t.Fatalf("name %q", n)
	}
	if n, _ := decode(in.ExporterAddress); n != "mac-000D3AF87856" {
		t.Fatalf("decoded %q", n)
	}

	s.flows = nil
	resp, out = post(t, srv.URL+"/api/ingest/flowlogs/azure", read(t, "azure-vnet-v4.json"), bearer(Azure))
	if resp.StatusCode != 200 || out["accepted"] != 3.0 || out["skipped"] != 1.0 {
		t.Fatalf("vnet %d %v", resp.StatusCode, out)
	}
	if f := s.flows[0]; f.Bytes != 9000 || !f.TimeFlowEnd.Equal(time.UnixMilli(1760000003599)) || f.ForwardingStatus != fwdForwarded {
		t.Fatalf("vnet flow %+v", f)
	}
	if f := s.flows[2]; f.ForwardingStatus != fwdDropped || f.DstPort != 22 {
		t.Fatalf("denied %+v", f)
	}
	if n, _ := ExporterName(s.flows[0].ExporterAddress); n != "app-vnet/00224871C205" {
		t.Fatalf("vnet name %q", n)
	}
}

func TestGCPPubSubPush(t *testing.T) {
	srv, s := newServer(t, nil)
	entry := read(t, "gcp-entry.json")
	push, _ := json.Marshal(map[string]any{"message": map[string]any{"data": base64.StdEncoding.EncodeToString(entry),
		"messageId": "1", "publishTime": "2025-10-09T10:00:07Z"}, "subscription": "projects/demo-project/subscriptions/flow"})
	// Pub/Sub push cannot send a static header: the token may be a parameter.
	resp, out := post(t, srv.URL+"/api/ingest/flowlogs/gcp?token="+tokens[GCP], push, nil)
	if resp.StatusCode != 200 || out["accepted"] != 1.0 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	f := s.flows[0]
	if f.FlowType != FlowTypeGCP || f.Bytes != 5120 || f.Packets != 8 || f.SrcPort != 22 || f.DstAddr != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("gcp %+v", f)
	}
	if n, _ := ExporterName(f.ExporterAddress); n != "demo-project/bastion-1" {
		t.Fatalf("name %q", n)
	}
	if f.SamplingRate != 1 {
		t.Fatalf("GCP volumes are estimated totals, not to be scaled: rate %d", f.SamplingRate)
	}
	// A destination gateway reporter names the destination side.
	gw := strings.Replace(strings.Replace(string(entry), `"reporter":"SRC"`, `"reporter":"DEST_GATEWAY"`, 1),
		`"src_vpc":`, `"dest_vpc":{"project_id":"net-project","vpc_name":"core","subnetwork_name":"edge"},"src_vpc":`, 1)
	resp, out = post(t, srv.URL+"/api/ingest/flowlogs/gcp", []byte(gw), bearer(GCP))
	if resp.StatusCode != 200 || out["accepted"] != 1.0 {
		t.Fatalf("gateway %d %v", resp.StatusCode, out)
	}
	if n, _ := ExporterName(s.flows[len(s.flows)-1].ExporterAddress); n != "net-project/core/edge" {
		t.Fatalf("gateway reporter name %q", n)
	}
	// Raw LogEntry array with a Bearer token.
	arr := append(append([]byte("["), entry...), ']')
	resp, out = post(t, srv.URL+"/api/ingest/flowlogs/gcp", arr, bearer(GCP))
	if resp.StatusCode != 200 || out["accepted"] != 1.0 {
		t.Fatalf("array %d %v", resp.StatusCode, out)
	}
}

func TestAuthAndErrors(t *testing.T) {
	srv, s := newServer(t, func(c *Config) { c.BatchSize = 2; c.MaxBody = 4096 })
	cases := []struct {
		path string
		body string
		hdr  map[string]string
		code int
	}{
		{"aws", "x", nil, 401},
		{"aws", "x", bearer(Azure), 401},
		{"azure", "{}", map[string]string{"X-Amz-Firehose-Access-Key": tokens[Azure]}, 401}, // the Firehose header is AWS only
		{"oracle", "x", bearer(AWS), 404},
		{"azure", "{not json", bearer(Azure), 400},
		{"gcp", `{"message":{"data":"@@"}}`, bearer(GCP), 400},
		{"aws", strings.Repeat("a", 5000), bearer(AWS), 413},
	}
	for _, c := range cases {
		resp, out := post(t, srv.URL+"/api/ingest/flowlogs/"+c.path, []byte(c.body), c.hdr)
		if resp.StatusCode != c.code {
			t.Errorf("%s %v: %d %v, want %d", c.path, c.hdr, resp.StatusCode, out, c.code)
		}
	}
	t.Setenv("X_DISABLED", "1")
	if resp, _ := post(t, srv.URL+"/api/ingest/flowlogs/gcp", []byte("{}"), bearer(GCP)); resp.StatusCode != 403 {
		t.Errorf("disabled: %d", resp.StatusCode)
	}
	// Batching: 3 flows in chunks of 2.
	resp, _ := post(t, srv.URL+"/api/ingest/flowlogs/aws", read(t, "aws-v2.log"), bearer(AWS))
	if resp.StatusCode != 200 || s.puts != 2 {
		t.Fatalf("batches: %d puts %d", resp.StatusCode, s.puts)
	}
	s.fail = true
	if resp, _ := post(t, srv.URL+"/api/ingest/flowlogs/aws", read(t, "aws-v2.log"), bearer(AWS)); resp.StatusCode != 503 {
		t.Fatalf("bus failure: %d", resp.StatusCode)
	}
}

func TestSyntheticAddresses(t *testing.T) {
	for _, id := range []string{"eni-1a2b3c4d", "eni-0123456789abcdef0", "vpc-0abcdef1234567890", "vpc-1"} {
		a, ok := awsAddr(id)
		if !ok {
			t.Fatalf("%s not encoded", id)
		}
		if n, _ := decode(a); n != id {
			t.Errorf("%s → %s → %q", id, a, n)
		}
	}
	for _, id := range []string{"eni-", "eni-xyz", "i-0123", "eni-0123456789abcdef01"} {
		if _, ok := awsAddr(id); ok {
			t.Errorf("%s encoded", id)
		}
	}
	if _, ok := ExporterName(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("router address named")
	}
	if n, ok := ExporterName(hashAddr("unseen")); !ok || !strings.HasPrefix(n, "fd75:666c:") {
		t.Errorf("unknown hash name %q", n)
	}
}
