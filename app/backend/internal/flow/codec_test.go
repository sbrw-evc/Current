package flow

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func sampleFlows() []*Flow {
	now := time.Date(2026, 10, 12, 9, 30, 0, 123456789, time.UTC)
	return []*Flow{
		{
			TimeReceived: now, TimeFlowStart: now.Add(-30 * time.Second), TimeFlowEnd: now.Add(-time.Second),
			SamplingRate: 1000, ExporterAddress: netip.MustParseAddr("192.0.2.1"), SequenceNum: 42,
			FlowType: "netflow9", InIf: 10, OutIf: 20,
			SrcAddr: netip.MustParseAddr("203.0.113.5"), DstAddr: netip.MustParseAddr("198.51.100.7"),
			SrcNetMask: 24, DstNetMask: 22, NextHop: netip.MustParseAddr("192.0.2.254"),
			SrcAS: 4200000000, DstAS: 64500, SrcPort: 443, DstPort: 51234, Proto: 6, EType: 0x0800,
			TCPFlags: 0x1b, IPTos: 0xb8, SrcVlan: 100, DstVlan: 4094, ForwardingStatus: 64,
			Bytes: 1 << 40, Packets: 1234567,
		},
		{
			// same exporter, IPv6, ICMP
			TimeReceived: now, SamplingRate: 1, ExporterAddress: netip.MustParseAddr("192.0.2.1"),
			FlowType: "ipfix", SrcAddr: netip.MustParseAddr("2001:db8::1"), DstAddr: netip.MustParseAddr("2001:db8:ffff::2"),
			SrcNetMask: 48, DstNetMask: 64, NextHop: netip.MustParseAddr("fe80::1"),
			Proto: 58, EType: 0x86dd, ICMPType: 128, ICMPCode: 0, Bytes: 64, Packets: 1,
		},
		{
			// zero everything
		},
		{
			// IPv4-mapped IPv6 exporter, custom flow type, times without TimeReceived
			TimeFlowStart: time.Unix(0, 0).UTC(), TimeFlowEnd: time.Unix(1, 5).UTC(),
			ExporterAddress: netip.MustParseAddr("::ffff:10.0.0.1"), FlowType: "custom",
			SrcAddr: netip.MustParseAddr("10.1.1.1"), Bytes: ^uint64(0), Packets: ^uint64(0), SamplingRate: ^uint64(0),
		},
		{
			TimeReceived: now, ExporterAddress: netip.MustParseAddr("2001:db8::99"), FlowType: "sflow",
		},
	}
}

func TestCodecRoundTrip(t *testing.T) {
	in := sampleFlows()
	b := MarshalBatch(nil, in)
	out, err := UnmarshalBatch(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d flows, want %d", len(out), len(in))
	}
	for i := range in {
		assertFlowEqual(t, i, in[i], out[i])
	}
}

func TestCodecEmptyAndNil(t *testing.T) {
	out, err := UnmarshalBatch(MarshalBatch(nil, nil))
	if err != nil || len(out) != 0 {
		t.Fatalf("empty: %v %v", out, err)
	}
	out, err = UnmarshalBatch(MarshalBatch(nil, []*Flow{nil, {Bytes: 5}, nil}))
	if err != nil || len(out) != 1 || out[0].Bytes != 5 {
		t.Fatalf("nil entries: %v %v", out, err)
	}
}

func TestCodecErrors(t *testing.T) {
	good := MarshalBatch(nil, sampleFlows())
	cases := map[string][]byte{
		"empty":     nil,
		"magic":     []byte("XX\x01\x00"),
		"version":   []byte("UF\x09\x00"),
		"truncated": good[:len(good)-3],
		"trailing":  append(append([]byte{}, good...), 0),
		"count":     []byte("UF\x01\xff\xff\xff\x7f"),
	}
	for name, b := range cases {
		if _, err := UnmarshalBatch(b); !errors.Is(err, ErrCodec) {
			t.Errorf("%s: expected ErrCodec, got %v", name, err)
		}
	}
}

func assertFlowEqual(t *testing.T, i int, want, got *Flow) {
	t.Helper()
	// times are compared with Equal (location and monotonic clock differ)
	for _, p := range [][2]time.Time{
		{want.TimeReceived, got.TimeReceived},
		{want.TimeFlowStart, got.TimeFlowStart},
		{want.TimeFlowEnd, got.TimeFlowEnd},
	} {
		if !p[0].Equal(p[1]) || p[0].IsZero() != p[1].IsZero() {
			t.Errorf("flow %d: time %v != %v", i, p[0], p[1])
		}
	}
	w, g := *want, *got
	w.TimeReceived, w.TimeFlowStart, w.TimeFlowEnd = time.Time{}, time.Time{}, time.Time{}
	g.TimeReceived, g.TimeFlowStart, g.TimeFlowEnd = time.Time{}, time.Time{}, time.Time{}
	if !reflect.DeepEqual(w, g) {
		t.Errorf("flow %d:\nwant %+v\n got %+v", i, w, g)
	}
}

func FuzzUnmarshalBatch(f *testing.F) {
	f.Add(MarshalBatch(nil, sampleFlows()))
	f.Add(MarshalBatch(nil, nil))
	f.Add([]byte("UF\x01\x01\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		flows, err := UnmarshalBatch(b)
		if err != nil {
			return
		}
		// whatever decodes must survive a re-encode unchanged
		again, err := UnmarshalBatch(MarshalBatch(nil, flows))
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if len(again) != len(flows) {
			t.Fatalf("re-decode count %d != %d", len(again), len(flows))
		}
		for i := range flows {
			assertFlowEqual(t, i, flows[i], again[i])
		}
	})
}

func benchFlows(n int) []*Flow {
	base := sampleFlows()
	out := make([]*Flow, n)
	for i := range out {
		f := *base[i%2]
		f.SrcPort = uint16(i)
		out[i] = &f
	}
	return out
}

func BenchmarkMarshalBatch(b *testing.B) {
	flows := benchFlows(1000)
	buf := MarshalBatch(nil, flows)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		buf = MarshalBatch(buf[:0], flows)
	}
	b.ReportMetric(float64(len(buf))/1000, "B/flow")
}

func BenchmarkUnmarshalBatch(b *testing.B) {
	buf := MarshalBatch(nil, benchFlows(1000))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := UnmarshalBatch(buf); err != nil {
			b.Fatal(err)
		}
	}
}
