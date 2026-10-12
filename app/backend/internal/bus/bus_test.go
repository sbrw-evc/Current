package bus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

const natsServerBin = "/tmp/claude-0/bin/nats-server"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// startNATS runs a throwaway JetStream-enabled nats-server and returns its
// URL. The test is skipped when the binary is missing.
func startNATS(t *testing.T) string {
	t.Helper()
	bin := natsServerBin
	if env := os.Getenv("NATS_SERVER_BIN"); env != "" {
		bin = env
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("nats-server not available at %s", bin)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cmd := exec.Command(bin, "-a", "127.0.0.1", "-p", strconv.Itoa(port), "-js", "-sd", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		nc, err := nats.Connect(url)
		if err == nil {
			nc.Close()
			return url
		}
		if time.Now().After(deadline) {
			t.Fatalf("nats-server did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func testFlows(n, tag int) []*flow.Flow {
	out := make([]*flow.Flow, n)
	for i := range out {
		out[i] = &flow.Flow{
			TimeReceived:    time.Unix(1_760_000_000, 0),
			ExporterAddress: netip.MustParseAddr("192.0.2.1"),
			FlowType:        "ipfix",
			SrcAddr:         netip.AddrFrom4([4]byte{10, 0, byte(tag), byte(i)}),
			DstAddr:         netip.MustParseAddr("2001:db8::1"),
			Bytes:           uint64(tag*1000 + i),
			Packets:         1,
			SamplingRate:    100,
		}
	}
	return out
}

// collectSink records flows; fail makes the first N Put calls fail.
type collectSink struct {
	mu    sync.Mutex
	flows []*flow.Flow
	calls int
	fail  int
}

func (s *collectSink) Put(_ context.Context, flows []*flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls <= s.fail {
		return errors.New("sink unavailable")
	}
	s.flows = append(s.flows, flows...)
	return nil
}

func (s *collectSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestJetStreamRoundTrip(t *testing.T) {
	url := startNATS(t)
	ctx := context.Background()
	cfg := JetStreamConfig{
		URL: url, Subject: "flow.test", Stream: "FLOWTEST",
		MaxBytes: 64 << 20, MaxAge: time.Hour,
		MaxFlowsPerMessage: 300, Workers: 3, NakDelay: 200 * time.Millisecond,
	}
	pub, err := NewJetStream(ctx, cfg, prometheus.NewRegistry(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	// stream created with the configured limits
	st, err := pub.js.Stream(ctx, "FLOWTEST")
	if err != nil {
		t.Fatal(err)
	}
	if sc := st.CachedInfo().Config; sc.MaxBytes != 64<<20 || sc.MaxAge != time.Hour || sc.Subjects[0] != "flow.test" {
		t.Fatalf("stream config %+v", sc)
	}

	// 1000 flows -> 4 messages; 1 more batch of 10
	if err := pub.Put(ctx, testFlows(1000, 1)); err != nil {
		t.Fatal(err)
	}
	if err := pub.Put(ctx, testFlows(10, 2)); err != nil {
		t.Fatal(err)
	}
	// garbage on the subject is terminated, not redelivered forever
	if err := pub.nc.Publish("flow.test", []byte("not a batch")); err != nil {
		t.Fatal(err)
	}

	// a second connection consumes; the sink fails twice first
	cons, err := NewJetStream(ctx, cfg, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer cons.Close()
	sink := &collectSink{fail: 2}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- cons.Consume(cctx, sink) }()

	waitFor(t, "all flows", func() bool { return sink.count() == 1010 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	seen := map[uint64]bool{}
	for _, f := range sink.flows {
		if seen[f.Bytes] {
			t.Errorf("duplicate flow %d", f.Bytes)
		}
		seen[f.Bytes] = true
		if f.SamplingRate != 100 || f.DstAddr != netip.MustParseAddr("2001:db8::1") {
			t.Fatalf("bad flow %+v", f)
		}
	}
	calls := sink.calls
	sink.mu.Unlock()
	if calls != 5+2 {
		t.Errorf("sink calls = %d, want 7 (5 messages + 2 failures)", calls)
	}

	// everything acked: a new consumer run gets nothing more
	ci, err := cons.js.Consumer(ctx, "FLOWTEST", "enricher")
	if err != nil {
		t.Fatal(err)
	}
	info, err := ci.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.NumPending != 0 || info.NumAckPending != 0 {
		t.Errorf("pending=%d ackPending=%d", info.NumPending, info.NumAckPending)
	}
}

func TestJetStreamExistingStream(t *testing.T) {
	url := startNATS(t)
	ctx := context.Background()
	cfg := JetStreamConfig{URL: url}
	a, err := NewJetStream(ctx, cfg, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// reopening with other limits updates the stream in place
	cfg.MaxAge = 2 * time.Hour
	b, err := NewJetStream(ctx, cfg, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	st, err := b.js.Stream(ctx, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	if st.CachedInfo().Config.MaxAge != 2*time.Hour || st.CachedInfo().Config.Subjects[0] != "flow.raw" {
		t.Fatalf("config %+v", st.CachedInfo().Config)
	}
}

func TestInProcess(t *testing.T) {
	b := NewInProcess(InProcessConfig{Size: 4, Workers: 2, RetryDelay: 10 * time.Millisecond}, prometheus.NewRegistry(), quiet)
	sink := &collectSink{fail: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Consume(ctx, sink) }()

	batch := testFlows(5, 1)
	if err := b.Put(ctx, batch); err != nil {
		t.Fatal(err)
	}
	batch[0] = nil // the bus must have copied the slice
	for i := 2; i < 10; i++ {
		if err := b.Put(ctx, testFlows(5, i)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "flows", func() bool { return sink.count() == 45 })
	for _, f := range sink.flows {
		if f == nil {
			t.Fatal("nil flow: slice was not copied")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// full buffer: Put honours its context
	full := NewInProcess(InProcessConfig{Size: 1}, nil, quiet)
	if err := full.Put(context.Background(), testFlows(1, 1)); err != nil {
		t.Fatal(err)
	}
	pctx, pcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer pcancel()
	if err := full.Put(pctx, testFlows(1, 2)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Put on full bus: %v", err)
	}
}

func TestInProcessDrainOnShutdown(t *testing.T) {
	b := NewInProcess(InProcessConfig{Size: 16, Workers: 1}, nil, quiet)
	for i := range 10 {
		if err := b.Put(context.Background(), testFlows(3, i)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // consumer starts already canceled: everything is drained
	sink := &collectSink{}
	if err := b.Consume(ctx, sink); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 30 {
		t.Fatalf("drained %d flows", sink.count())
	}
}
