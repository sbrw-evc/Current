package wiring

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sbrw-evc/network/app/backend/internal/bmp"
)

// startNATS runs a throwaway JetStream nats-server (NATS_SERVER_BIN, default
// as in the bus tests); the test is skipped without it.
func startNATS(t *testing.T) string {
	t.Helper()
	bin := "/tmp/claude-0/bin/nats-server"
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
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if nc, err := nats.Connect(url); err == nil {
			nc.Close()
			return url
		}
		if time.Now().After(deadline) {
			t.Fatal("nats-server did not start")
		}
	}
}

func jsFor(t *testing.T, url string) jetstream.JetStream {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

// routeMonitoring builds a BMP Route Monitoring message announcing prefix
// from a global post-policy IPv4 peer with AS_PATH [as].
func routeMonitoring(peer netip.Addr, as uint32, prefix string) []byte {
	p := netip.MustParsePrefix(prefix)
	ph := []byte{0, 0x40}
	ph = append(ph, make([]byte, 8+12)...)
	a4 := peer.As4()
	ph = append(ph, a4[:]...)
	ph = binary.BigEndian.AppendUint32(ph, as)
	ph = append(ph, make([]byte, 12)...)
	path := binary.BigEndian.AppendUint32([]byte{2, 1}, as)
	attrs := append([]byte{0x40, 1, 1, 0, 0x40, 2, byte(len(path))}, path...)
	attrs = append(attrs, 0x40, 3, 4)
	attrs = append(attrs, a4[:]...)
	body := []byte{0, 0}
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, byte(p.Bits()))
	body = append(body, p.Addr().AsSlice()[:(p.Bits()+7)/8]...)
	msg := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(body)))
	msg = append(msg, 2)
	msg = append(msg, body...)
	out := []byte{3}
	out = binary.BigEndian.AppendUint32(out, uint32(6+len(ph)+len(msg)))
	out = append(out, bmp.MsgRouteMonitoring)
	out = append(out, ph...)
	return append(out, msg...)
}

// Two enricher processes: the session lands on A, B replays it from
// JetStream; a process started later rebuilds it; the end removes it.
func TestBMPReplicationJetStream(t *testing.T) {
	url := startNATS(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	replA := newBMPReplication(jsFor(t, url), quiet)
	if err := replA.ensureStream(ctx); err != nil {
		t.Fatal(err)
	}
	ribA := bmp.NewRIB()
	srvA := bmp.NewServer(bmp.Config{Listen: "127.0.0.1:0", Logger: quiet, Replicator: replA}, ribA)
	if err := srvA.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srvA.Run(ctx) }()

	replica := func() (*bmp.RIB, context.CancelFunc) {
		rib := bmp.NewRIB()
		r := newBMPReplication(jsFor(t, url), quiet)
		rctx, rcancel := context.WithCancel(ctx)
		go r.run(rctx, bmp.NewReplica(bmp.NewServer(bmp.Config{Logger: quiet}, rib)))
		return rib, rcancel
	}
	wait := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("timeout: " + what)
			}
		}
	}
	has := func(rib *bmp.RIB, a string) bool { _, ok := rib.Lookup(netip.MustParseAddr(a)); return ok }

	ribB, stopB := replica()
	defer stopB()
	c, err := net.Dial("tcp", srvA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("198.51.100.2")
	if _, err := c.Write(routeMonitoring(peer, 15169, "8.8.8.0/24")); err != nil {
		t.Fatal(err)
	}
	wait("route on A", func() bool { return has(ribA, "8.8.8.8") })
	wait("route on B", func() bool { return has(ribB, "8.8.8.8") })

	ribC, stopC := replica()
	defer stopC()
	wait("route on C", func() bool { return has(ribC, "8.8.8.8") })
	if r, _ := ribC.Lookup(netip.MustParseAddr("8.8.8.8")); r.OriginAS() != 15169 || r.NextHop != peer {
		t.Fatalf("C route %+v", r)
	}

	if _, err := c.Write(routeMonitoring(peer, 13335, "1.1.1.0/24")); err != nil {
		t.Fatal(err)
	}
	wait("second route on B", func() bool { return has(ribB, "1.1.1.1") })
	_ = c.Close()
	wait("routes gone on B", func() bool { return !has(ribB, "8.8.8.8") && !has(ribB, "1.1.1.1") })
	wait("routes gone on C", func() bool { return !has(ribC, "8.8.8.8") })
}
