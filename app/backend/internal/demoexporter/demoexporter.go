package demoexporter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Run sends traffic for every configured exporter until ctx is canceled.
// It returns an error only for invalid configuration or socket setup.
func Run(ctx context.Context, cfg Config) error {
	cfg = cfg.withDefaults()
	if len(cfg.Exporters) == 0 {
		return errors.New("demoexporter: no exporters configured")
	}
	type job struct {
		exp  *Exporter
		conn *net.UDPConn
	}
	var jobs []job
	closeAll := func() {
		for _, j := range jobs {
			j.conn.Close()
		}
	}
	for i := range cfg.Exporters {
		exp := &cfg.Exporters[i]
		target := cfg.NetFlowTarget
		switch exp.Protocol {
		case ProtoNetFlow9, ProtoIPFIX:
		case ProtoSFlow:
			target = cfg.SFlowTarget
		default:
			closeAll()
			return fmt.Errorf("demoexporter: exporter %q: unknown protocol %q", exp.Name, exp.Protocol)
		}
		if exp.SamplingRate == 0 {
			exp.SamplingRate = 1
		}
		raddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			closeAll()
			return fmt.Errorf("demoexporter: exporter %q: target %q: %w", exp.Name, target, err)
		}
		var laddr *net.UDPAddr
		if exp.SourceAddr.IsValid() {
			laddr = &net.UDPAddr{IP: exp.SourceAddr.AsSlice()}
		}
		conn, err := net.DialUDP("udp", laddr, raddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("demoexporter: exporter %q: %w", exp.Name, err)
		}
		jobs = append(jobs, job{exp, conn})
	}
	defer closeAll()

	seed := cfg.Seed
	if seed == 0 {
		seed = uint64(time.Now().UnixNano())
	}
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() { runExporter(ctx, &cfg, j.exp, j.conn, seed+uint64(i)*7919) })
	}
	cfg.Logger.Info("demo exporter started", "exporters", len(jobs),
		"netflow", cfg.NetFlowTarget, "sflow", cfg.SFlowTarget)
	wg.Wait()
	return nil
}

func runExporter(ctx context.Context, cfg *Config, exp *Exporter, conn *net.UDPConn, seed uint64) {
	log := cfg.Logger.With("component", "demoexporter", "exporter", exp.Name)
	gen := newGenerator(cfg, exp, seed)
	boot := cfg.Now().Add(-72 * time.Hour)

	var (
		nf *nfEncoder
		sf *sfEncoder
	)
	if exp.Protocol == ProtoSFlow {
		agent := exp.AgentAddr
		if !agent.IsValid() {
			agent = exp.SourceAddr
		}
		if !agent.IsValid() {
			if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				agent = a.AddrPort().Addr().Unmap()
			}
		}
		sf = &sfEncoder{agent: agent, localAS: cfg.LocalAS, rate: exp.SamplingRate, boot: boot, ifaces: exp.Interfaces}
	} else {
		nf = &nfEncoder{
			ipfix: exp.Protocol == ProtoIPFIX, domain: exp.ObservationDomain,
			rate: exp.SamplingRate, boot: boot, ifaces: exp.Interfaces,
		}
	}

	ticker := time.NewTicker(cfg.Tick)
	defer ticker.Stop()
	var (
		lastControl time.Time // real (monotonic) time, independent of cfg.Now
		carry       float64
		sendErrors  int
		flows       []genFlow
	)
	for {
		now := cfg.Now()
		control := lastControl.IsZero() || time.Since(lastControl) >= cfg.TemplateInterval
		if control {
			lastControl = time.Now()
		}

		want := cfg.FlowsPerSecond*diurnal(now)*cfg.Tick.Seconds() + carry
		n := int(want)
		carry = want - float64(n)
		flows = flows[:0]
		for range n {
			if f, ok := gen.next(now); ok {
				flows = append(flows, f)
			}
		}

		var pkts [][]byte
		if nf != nil {
			if control {
				pkts = append(pkts, nf.controlPacket(now))
			}
			pkts = append(pkts, nf.dataPackets(now, flows, cfg.MTU)...)
		} else {
			pkts = sf.packets(now, flows, control, cfg.MTU)
		}
		for _, p := range pkts {
			if _, err := conn.Write(p); err != nil {
				// typically ECONNREFUSED while the collector is down
				if sendErrors%1000 == 0 {
					log.Debug("send failed", "err", err)
				}
				sendErrors++
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
