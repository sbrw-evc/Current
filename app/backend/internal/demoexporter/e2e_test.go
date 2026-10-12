package demoexporter_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/demoexporter"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
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

// TestEndToEnd sends demo traffic to a real collector on localhost and
// checks what comes out of it.
func TestEndToEnd(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sink := &captureSink{}
	reg := prometheus.NewRegistry()
	c, err := collector.New(collector.Config{
		NetFlowListen: "127.0.0.1:0",
		SFlowListen:   "127.0.0.1:0",
		Workers:       2,
		Sockets:       2,
		FlushInterval: 50 * time.Millisecond,
	}, sink, reg, log)
	if err != nil {
		t.Fatal(err)
	}
	cctx, cstop := context.WithCancel(context.Background())
	cdone := make(chan error, 1)
	go func() { cdone <- c.Run(cctx) }()

	cfg := demoexporter.DefaultConfig(c.NetFlowAddr().String())
	cfg.SFlowTarget = c.SFlowAddr().String()
	cfg.FlowsPerSecond = 3000
	cfg.Tick = 20 * time.Millisecond
	cfg.Seed = 42
	cfg.Logger = log
	noon := time.Date(2026, 10, 12, 12, 0, 0, 0, time.Local)
	cfg.Now = func() time.Time { return noon }

	dctx, dstop := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer dstop()
	if err := demoexporter.Run(dctx, cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the last datagrams be decoded
	cstop()
	if err := <-cdone; err != nil {
		t.Fatal(err)
	}

	sink.mu.Lock()
	flows := sink.flows
	sink.mu.Unlock()
	if len(flows) < 1000 {
		t.Fatalf("only %d flows decoded", len(flows))
	}

	type want struct {
		typ  string
		rate uint64
		ifs  []uint32
	}
	exps := map[netip.Addr]want{}
	for _, e := range cfg.Exporters {
		w := want{typ: e.Protocol, rate: uint64(e.SamplingRate)}
		for _, itf := range e.Interfaces {
			w.ifs = append(w.ifs, itf.Index)
		}
		addr := e.SourceAddr
		if e.Protocol == demoexporter.ProtoSFlow {
			addr = e.AgentAddr
		}
		exps[addr] = w
	}
	known := append([]netip.Prefix{}, cfg.LocalPrefixes...)
	for _, p := range cfg.Peers {
		known = append(known, p.Prefixes...)
	}
	inKnown := func(a netip.Addr) bool {
		for _, p := range known {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	perExporter := map[netip.Addr]int{}
	var v4, v6, tcp, udp, icmp int
	for i, f := range flows {
		w, ok := exps[f.ExporterAddress]
		if !ok {
			t.Fatalf("flow %d from unexpected exporter %v", i, f.ExporterAddress)
		}
		perExporter[f.ExporterAddress]++
		if f.FlowType != w.typ {
			t.Fatalf("flow %d from %v: type %q, want %q", i, f.ExporterAddress, f.FlowType, w.typ)
		}
		if f.SamplingRate != w.rate {
			t.Fatalf("flow %d from %v (%s): sampling rate %d, want %d", i, f.ExporterAddress, f.FlowType, f.SamplingRate, w.rate)
		}
		if !slices.Contains(w.ifs, f.InIf) || !slices.Contains(w.ifs, f.OutIf) {
			t.Fatalf("flow %d from %v: interfaces %d -> %d not on the exporter", i, f.ExporterAddress, f.InIf, f.OutIf)
		}
		if !inKnown(f.SrcAddr) || !inKnown(f.DstAddr) {
			t.Fatalf("flow %d: addresses %v -> %v outside configured prefixes", i, f.SrcAddr, f.DstAddr)
		}
		if f.Bytes == 0 || f.Packets == 0 {
			t.Fatalf("flow %d: empty volume %+v", i, f)
		}
		if !f.NextHop.IsValid() || f.SrcAS == 0 || f.DstAS == 0 || f.SrcNetMask == 0 {
			t.Fatalf("flow %d: missing routing info: nh=%v as=%d->%d mask=%d", i, f.NextHop, f.SrcAS, f.DstAS, f.SrcNetMask)
		}
		if f.SrcAddr.Is4() && f.EType == 0x0800 {
			v4++
		} else if f.SrcAddr.Is6() && f.EType == 0x86dd {
			v6++
		} else {
			t.Fatalf("flow %d: etype %#x for %v", i, f.EType, f.SrcAddr)
		}
		switch f.Proto {
		case 6:
			tcp++
			if f.SrcPort == 0 || f.DstPort == 0 || f.TCPFlags == 0 {
				t.Fatalf("flow %d: tcp without ports/flags: %+v", i, f)
			}
		case 17:
			udp++
		case 1, 58:
			icmp++
		}
		if f.TimeFlowStart.After(f.TimeFlowEnd) || f.TimeReceived.IsZero() {
			t.Fatalf("flow %d: bad times %v %v", i, f.TimeFlowStart, f.TimeFlowEnd)
		}
	}
	for addr, w := range exps {
		if perExporter[addr] == 0 {
			t.Errorf("no flows from %v (%s)", addr, w.typ)
		}
	}
	if v4 == 0 || v6 == 0 || tcp == 0 || udp == 0 || icmp == 0 {
		t.Errorf("traffic mix: v4=%d v6=%d tcp=%d udp=%d icmp=%d", v4, v6, tcp, udp, icmp)
	}
	t.Logf("%d flows: %v; v4=%d v6=%d tcp=%d udp=%d icmp=%d", len(flows), perExporter, v4, v6, tcp, udp, icmp)

	// interface names learned from options (NetFlow v9, IPFIX) and speeds
	// from counter samples (sFlow)
	names := c.IfNames()
	for _, e := range cfg.Exporters {
		addr := e.SourceAddr
		if e.Protocol == demoexporter.ProtoSFlow {
			addr = e.AgentAddr
		}
		for _, itf := range e.Interfaces {
			name, descr, speed, ok := names.Lookup(addr, itf.Index)
			if !ok {
				t.Errorf("%s: interface %d not learned", e.Name, itf.Index)
				continue
			}
			if e.Protocol == demoexporter.ProtoSFlow {
				if speed != itf.Speed {
					t.Errorf("%s: interface %d speed %d, want %d", e.Name, itf.Index, speed, itf.Speed)
				}
				continue
			}
			if name != itf.Name || descr != itf.Description {
				t.Errorf("%s: interface %d = %q / %q, want %q / %q", e.Name, itf.Index, name, descr, itf.Name, itf.Description)
			}
		}
	}

	infos := c.Exporters()
	if len(infos) != 3 {
		t.Fatalf("exporters: %+v", infos)
	}
	for _, info := range infos {
		w := exps[info.Address]
		if !slices.Equal(info.SamplingRates, []uint64{w.rate}) || !slices.Equal(info.FlowTypes, []string{w.typ}) {
			t.Errorf("exporter %v: rates %v types %v", info.Address, info.SamplingRates, info.FlowTypes)
		}
		if info.DecodeErrors != 0 {
			t.Errorf("exporter %v: %d decode errors", info.Address, info.DecodeErrors)
		}
		if w.typ != demoexporter.ProtoSFlow && info.Templates != 4 {
			t.Errorf("exporter %v: %d templates, want 4", info.Address, info.Templates)
		}
		if len(info.Interfaces) != len(w.ifs) {
			t.Errorf("exporter %v: interfaces %+v", info.Address, info.Interfaces)
		}
	}

	// metrics are exported
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, mf := range mfs {
		seen[mf.GetName()] = true
	}
	for _, name := range []string{"flow_collector_packets_total", "flow_collector_flows_total", "flow_collector_templates", "flow_collector_exporters"} {
		if !seen[name] {
			t.Errorf("metric %s missing", name)
		}
	}
}
