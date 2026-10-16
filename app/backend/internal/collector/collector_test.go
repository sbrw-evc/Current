package collector

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

type captureSink struct {
	mu    sync.Mutex
	flows []*flow.Flow
}

func (s *captureSink) Put(_ context.Context, flows []*flow.Flow) error {
	s.mu.Lock()
	s.flows = append(s.flows, flows...)
	s.mu.Unlock()
	return nil
}

func (s *captureSink) get() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*flow.Flow(nil), s.flows...)
}

func newTestCollector(t *testing.T, cfg Config, sink flow.Sink) *Collector {
	t.Helper()
	if cfg.NetFlowListen == "" && cfg.SFlowListen == "" {
		cfg.NetFlowListen = "127.0.0.1:0"
	}
	c, err := New(cfg, sink, prometheus.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.closeConns)
	return c
}

// netflowV5 builds a NetFlow v5 datagram with one record.
func netflowV5(samplingInterval uint16) []byte {
	b := make([]byte, 24+48)
	be := binary.BigEndian
	be.PutUint16(b[0:], 5)
	be.PutUint16(b[2:], 1)
	be.PutUint32(b[4:], 100_000)       // uptime ms
	be.PutUint32(b[8:], 1_760_000_000) // unix secs
	be.PutUint32(b[16:], 77)           // sequence
	be.PutUint16(b[22:], 0x4000|samplingInterval)
	r := b[24:]
	copy(r[0:], []byte{192, 0, 2, 1})
	copy(r[4:], []byte{198, 51, 100, 2})
	copy(r[8:], []byte{203, 0, 113, 254})
	be.PutUint16(r[12:], 3)    // input
	be.PutUint16(r[14:], 4)    // output
	be.PutUint32(r[16:], 10)   // packets
	be.PutUint32(r[20:], 5000) // bytes
	be.PutUint32(r[24:], 40_000)
	be.PutUint32(r[28:], 90_000)
	be.PutUint16(r[32:], 443)
	be.PutUint16(r[34:], 50000)
	r[37], r[38], r[39] = 0x12, 6, 0x10
	be.PutUint16(r[40:], 15169)
	be.PutUint16(r[42:], 64500)
	r[44], r[45] = 24, 22
	return b
}

func TestNetFlowV5AndOverride(t *testing.T) {
	c := newTestCollector(t, Config{
		SamplingOverrides: []SamplingOverride{
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Rate: 4000},
			{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Rate: 5000},
		},
	}, &captureSink{})
	now := time.Now()
	out := c.decode(packet{kind: kindNetFlow, src: netip.MustParseAddr("192.0.2.9"), received: now, data: netflowV5(100)}, nil)
	if len(out) != 1 {
		t.Fatalf("got %d flows", len(out))
	}
	f := out[0]
	if f.FlowType != "netflow5" || f.SamplingRate != 100 || f.InIf != 3 || f.OutIf != 4 ||
		f.SrcAddr != netip.MustParseAddr("192.0.2.1") || f.DstAddr != netip.MustParseAddr("198.51.100.2") ||
		f.NextHop != netip.MustParseAddr("203.0.113.254") || f.Bytes != 5000 || f.Packets != 10 ||
		f.SrcAS != 15169 || f.DstAS != 64500 || f.SrcNetMask != 24 || f.DstNetMask != 22 ||
		f.SrcPort != 443 || f.DstPort != 50000 || f.Proto != 6 || f.TCPFlags != 0x12 || f.IPTos != 0x10 ||
		f.EType != 0x0800 || f.SequenceNum != 77 {
		t.Fatalf("unexpected flow %+v", f)
	}
	export := time.Unix(1_760_000_000, 0)
	if !f.TimeFlowStart.Equal(export.Add(-60*time.Second)) || !f.TimeFlowEnd.Equal(export.Add(-10*time.Second)) {
		t.Fatalf("times %v %v", f.TimeFlowStart, f.TimeFlowEnd)
	}

	// longest prefix override wins over the header
	out = c.decode(packet{kind: kindNetFlow, src: netip.MustParseAddr("10.1.2.3"), received: now, data: netflowV5(100)}, nil)
	if out[0].SamplingRate != 5000 {
		t.Fatalf("override: %d", out[0].SamplingRate)
	}
	// no rate at all: default
	out = c.decode(packet{kind: kindNetFlow, src: netip.MustParseAddr("192.0.2.10"), received: now, data: netflowV5(0)}, nil)
	if out[0].SamplingRate != 1 {
		t.Fatalf("default: %d", out[0].SamplingRate)
	}
}

// ipfixPacket assembles an IPFIX datagram from sets.
func ipfixPacket(domain uint32, sets ...[]byte) []byte {
	b := []byte{0, 10, 0, 0}
	b = binary.BigEndian.AppendUint32(b, 1_760_000_000)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, domain)
	for _, s := range sets {
		b = append(b, s...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func set(id uint16, body ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0, 0)
	for _, x := range body {
		b = append(b, x...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func u16s(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint16(b, x)
	}
	return b
}

func TestIPFIXSamplingAndTemplates(t *testing.T) {
	c := newTestCollector(t, Config{DefaultSamplingRate: 7}, &captureSink{})
	src := netip.MustParseAddr("192.0.2.20")
	now := time.Now()
	decode := func(data []byte) []*flow.Flow {
		return c.decode(packet{kind: kindNetFlow, src: src, received: now, data: data}, nil)
	}

	// data before template: counted as a decode error, no flow
	data := set(300, []byte{10, 0, 0, 1}, []byte{0, 0, 0, 100}, u16s(0, 0)[:1])
	if out := decode(ipfixPacket(5, data)); len(out) != 0 {
		t.Fatalf("flows without template: %d", len(out))
	}
	if e := c.Exporters()[0]; e.DecodeErrors != 1 {
		t.Fatalf("decode errors = %d", e.DecodeErrors)
	}

	// template 300: srcIPv4, octetDeltaCount(4 bytes, reduced size), selectorId(1)
	tmpl := set(2, u16s(300, 3, 8, 4, 1, 4, 302, 1))
	// options template 301: scope selectorId(1), option samplingInterval(4)
	opts := set(3, u16s(301, 2, 1, 302, 1, 34, 4))
	optData := set(301, []byte{9}, []byte{0, 0, 0x03, 0xe8}) // selector 9 -> 1000
	rec := set(300,
		[]byte{10, 0, 0, 1}, []byte{0, 0, 0, 100}, []byte{9}, // selector 9
		[]byte{10, 0, 0, 2}, []byte{0, 0, 0, 200}, []byte{3}, // unknown selector: domain fallback
	)
	out := decode(ipfixPacket(5, tmpl, opts, optData, rec))
	if len(out) != 2 {
		t.Fatalf("got %d flows", len(out))
	}
	if out[0].SamplingRate != 1000 || out[0].Bytes != 100 || out[0].SrcAddr != netip.MustParseAddr("10.0.0.1") || out[0].EType != 0x0800 {
		t.Fatalf("flow 0: %+v", out[0])
	}
	if out[1].SamplingRate != 1000 {
		t.Fatalf("flow 1 fallback rate: %d", out[1].SamplingRate)
	}

	// another observation domain does not share templates nor samplers
	if out := decode(ipfixPacket(6, rec)); len(out) != 0 {
		t.Fatalf("domain 6 decoded with domain 5 templates")
	}
	// same domain, other template carrying an in-record rate (IE 34)
	tmpl2 := set(2, u16s(310, 2, 8, 4, 34, 4))
	rec2 := set(310, []byte{10, 0, 0, 3}, []byte{0, 0, 0, 50})
	out = decode(ipfixPacket(6, tmpl2, rec2))
	if len(out) != 1 || out[0].SamplingRate != 50 {
		t.Fatalf("in-record rate: %+v", out)
	}
	// template without any rate in a fresh domain: default
	tmpl3 := set(2, u16s(320, 1, 8, 4))
	out = decode(ipfixPacket(7, tmpl3, set(320, []byte{10, 0, 0, 4})))
	if len(out) != 1 || out[0].SamplingRate != 7 {
		t.Fatalf("default rate: %+v", out)
	}

	info := c.Exporters()[0]
	if info.Templates != 4 || len(info.SamplingRates) != 3 || info.DecodeErrors != 2 {
		t.Fatalf("exporter info: %+v", info)
	}
}

func TestParseEthernet(t *testing.T) {
	// Ethernet + 802.1Q(vlan 42) + IPv6 + hop-by-hop + TCP
	b := make([]byte, 12)
	b = append(b, 0x81, 0x00, 0x00, 42, 0x86, 0xdd)
	ip6 := make([]byte, 40)
	ip6[0], ip6[1] = 0x6b, 0x80 // tclass 0xb8
	ip6[6] = 0                  // hop-by-hop
	copy(ip6[8:], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(ip6[24:], netip.MustParseAddr("2001:db8::2").AsSlice())
	b = append(b, ip6...)
	b = append(b, 6, 0, 0, 0, 0, 0, 0, 0) // hop-by-hop, next = TCP, len 8
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 1234)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[13] = 0x02
	b = append(b, tcp...)

	var f flow.Flow
	parseEthernet(b, &f)
	if f.SrcVlan != 42 || f.EType != 0x86dd || f.IPTos != 0xb8 || f.Proto != 6 ||
		f.SrcAddr != netip.MustParseAddr("2001:db8::1") || f.DstAddr != netip.MustParseAddr("2001:db8::2") ||
		f.SrcPort != 1234 || f.DstPort != 443 || f.TCPFlags != 0x02 {
		t.Fatalf("parsed %+v", f)
	}
	// truncated headers must not panic
	for i := range b {
		var g flow.Flow
		parseEthernet(b[:i], &g)
	}
}

func TestParseSamplingOverrides(t *testing.T) {
	ov, err := ParseSamplingOverrides("192.0.2.0/24=1000, 2001:db8::1=512")
	if err != nil {
		t.Fatal(err)
	}
	if len(ov) != 2 || ov[0].Rate != 1000 || ov[1].Prefix.Bits() != 128 {
		t.Fatalf("%+v", ov)
	}
	for _, bad := range []string{"192.0.2.0/24", "x=1", "192.0.2.0/24=0", "192.0.2.0/24=abc"} {
		if _, err := ParseSamplingOverrides(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

// TestRunFlushOnShutdown sends a datagram over UDP and checks that the
// pending batch is flushed when the context is canceled.
func TestRunFlushOnShutdown(t *testing.T) {
	sink := &captureSink{}
	c := newTestCollector(t, Config{FlushInterval: time.Hour, BatchSize: 1000}, sink)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	conn, err := net.Dial("udp", c.NetFlowAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := conn.Write(netflowV5(10)); err != nil {
			t.Fatal(err)
		}
		if exps := c.Exporters(); len(exps) == 1 && exps[0].Flows > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("datagram never decoded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(sink.get()) != 0 {
		t.Fatal("flushed before shutdown despite long interval")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := sink.get(); len(got) == 0 || got[0].SamplingRate != 10 {
		t.Fatalf("after shutdown: %d flows", len(got))
	}
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("second Run should fail")
	}
}

// FuzzDecode feeds arbitrary datagrams to both decoders: they must never
// panic, whatever the exporters send.
func FuzzDecode(f *testing.F) {
	f.Add(false, netflowV5(10))
	f.Add(false, ipfixPacket(1, set(2, u16s(300, 2, 8, 4, 82, 0xffff)), set(300, []byte{1, 2, 3, 4, 3, 'a', 'b', 'c'})))
	f.Add(true, []byte{0, 0, 0, 5, 0, 0, 0, 1, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0})
	sink := &captureSink{}
	c, err := New(Config{NetFlowListen: "127.0.0.1:0"}, sink, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		f.Fatal(err)
	}
	defer c.closeConns()
	f.Fuzz(func(t *testing.T, sflow bool, data []byte) {
		kind := kindNetFlow
		if sflow {
			kind = kindSFlow
		}
		c.decode(packet{kind: kind, src: netip.MustParseAddr("192.0.2.1"), received: time.Now(), data: data}, nil)
	})
}

func TestSFlowHugeExpandedSample(t *testing.T) {
	c := newTestCollector(t, Config{}, &captureSink{})
	b := []byte{0, 0, 0, 5, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
	b = binary.BigEndian.AppendUint32(b, 3)  // expanded flow sample
	b = binary.BigEndian.AppendUint32(b, 48) // length
	body := make([]byte, 48)
	binary.BigEndian.PutUint32(body[40:], 0xffffffff) // record count after 10 fields
	b = append(b, body...)
	if err := sflowSane(b); err == nil {
		t.Fatal("expected rejection")
	}
	if out := c.decode(packet{kind: kindSFlow, src: netip.MustParseAddr("192.0.2.1"), received: time.Now(), data: b}, nil); len(out) != 0 {
		t.Fatal("unexpected flows")
	}
}
