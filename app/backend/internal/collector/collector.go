package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// listener kinds
const (
	kindNetFlow = "netflow"
	kindSFlow   = "sflow"
)

// packet is one received datagram waiting to be decoded.
type packet struct {
	kind     string
	src      netip.Addr
	received time.Time
	data     []byte
}

// Collector receives and decodes flow datagrams. Create it with New (which
// binds the sockets) and start it with Run.
type Collector struct {
	cfg  Config
	sink flow.Sink
	log  *slog.Logger
	m    *metrics
	reg  *registry
	ifc  *ifCache

	conns     []*net.UDPConn
	connKinds []string // listener kind of each conn
	nfAddr    net.Addr
	sfAddr    net.Addr
	queues    []chan packet
	seed      maphash.Seed
	runOnce   sync.Once
}

// New validates cfg, binds the UDP sockets and registers metrics on reg
// (nil skips registration). Flows are delivered to sink in batches.
func New(cfg Config, sink flow.Sink, reg prometheus.Registerer, log *slog.Logger) (*Collector, error) {
	if sink == nil {
		return nil, errors.New("collector: nil sink")
	}
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	if !reusePortSupported {
		cfg.Sockets = 1
	}
	c := &Collector{
		cfg:  cfg,
		sink: sink,
		log:  log.With("component", "collector"),
		ifc:  newIfCache(),
		seed: maphash.MakeSeed(),
	}
	c.reg = newRegistry(&c.cfg)
	c.m = newMetrics(reg, func() float64 { return float64(c.reg.count()) })

	var err error
	if cfg.NetFlowListen != "" {
		if c.nfAddr, err = c.listen(kindNetFlow, cfg.NetFlowListen); err != nil {
			c.closeConns()
			return nil, err
		}
	}
	if cfg.SFlowListen != "" {
		if c.sfAddr, err = c.listen(kindSFlow, cfg.SFlowListen); err != nil {
			c.closeConns()
			return nil, err
		}
	}
	if len(c.conns) == 0 {
		return nil, errors.New("collector: no listen address configured")
	}
	return c, nil
}

// listen binds cfg.Sockets sockets to addr and returns the bound address
// (useful with port 0).
func (c *Collector) listen(kind, addr string) (net.Addr, error) {
	lc := net.ListenConfig{}
	if c.cfg.Sockets > 1 {
		lc.Control = setReusePort
	}
	var bound net.Addr
	for i := 0; i < c.cfg.Sockets; i++ {
		a := addr
		if bound != nil {
			// with port 0 the next sockets must join the port the first got
			a = bound.String()
		}
		pc, err := lc.ListenPacket(context.Background(), "udp", a)
		if err != nil {
			return nil, fmt.Errorf("collector: listen %s %s: %w", kind, addr, err)
		}
		conn := pc.(*net.UDPConn)
		if err := conn.SetReadBuffer(c.cfg.ReadBuffer); err != nil {
			c.log.Warn("cannot set socket read buffer", "listener", kind, "bytes", c.cfg.ReadBuffer, "err", err)
		}
		c.conns = append(c.conns, conn)
		c.connKinds = append(c.connKinds, kind)
		bound = conn.LocalAddr()
	}
	c.log.Info("listening", "listener", kind, "addr", bound.String(), "sockets", c.cfg.Sockets)
	return bound, nil
}

func (c *Collector) closeConns() {
	for _, conn := range c.conns {
		conn.Close()
	}
}

// NetFlowAddr returns the bound NetFlow/IPFIX address, nil if disabled.
func (c *Collector) NetFlowAddr() net.Addr { return c.nfAddr }

// SFlowAddr returns the bound sFlow address, nil if disabled.
func (c *Collector) SFlowAddr() net.Addr { return c.sfAddr }

// SetSamplingOverrides replaces the sampling rate overrides at run time
// (longest prefix wins). Flows decoded afterwards use the new rates. Safe for
// concurrent use.
func (c *Collector) SetSamplingOverrides(ov []SamplingOverride) {
	ov = Config{SamplingOverrides: ov}.withDefaults().SamplingOverrides
	c.reg.setOverrides(ov)
}

// IfNames returns the interface names learned from the exporters.
func (c *Collector) IfNames() IfNameSource { return c.ifc }

// Exporters returns the exporters seen so far, ordered by address.
func (c *Collector) Exporters() []ExporterInfo {
	exps := c.reg.all()
	out := make([]ExporterInfo, len(exps))
	for i, e := range exps {
		out[i] = e.info(c.ifc)
	}
	return out
}

// Run processes datagrams until ctx is canceled, then flushes pending
// batches (bounded by ShutdownTimeout) and returns. It may be called once.
func (c *Collector) Run(ctx context.Context) error {
	err := errors.New("collector: Run called twice")
	c.runOnce.Do(func() { err = c.run(ctx) })
	return err
}

func (c *Collector) run(ctx context.Context) error {
	// Sink calls survive ctx cancellation for ShutdownTimeout so that the
	// last batches are not lost on a clean stop.
	sinkCtx, cancelSink := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelSink()
	go func() {
		select {
		case <-ctx.Done():
		case <-sinkCtx.Done():
			return
		}
		t := time.NewTimer(c.cfg.ShutdownTimeout)
		defer t.Stop()
		select {
		case <-t.C:
			cancelSink()
		case <-sinkCtx.Done():
		}
	}()

	var workers sync.WaitGroup
	c.queues = make([]chan packet, c.cfg.Workers)
	for i := range c.queues {
		q := make(chan packet, c.cfg.QueueSize)
		c.queues[i] = q
		workers.Go(func() { c.worker(sinkCtx, q) })
	}

	var readers sync.WaitGroup
	for i, conn := range c.conns {
		kind := c.connKinds[i]
		readers.Go(func() { c.reader(ctx, kind, conn) })
	}

	housekeeping := time.NewTicker(5 * time.Second)
	defer housekeeping.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case now := <-housekeeping.C:
			for _, e := range c.reg.all() {
				e.updateRate(now)
			}
			c.ifc.prune(now.Add(-c.cfg.InterfaceTTL))
		}
	}

	c.closeConns()
	readers.Wait()
	for _, q := range c.queues {
		close(q)
	}
	workers.Wait()
	c.log.Info("stopped")
	return nil
}

// reader receives datagrams from one socket and dispatches them to the
// worker owning their source address.
func (c *Collector) reader(ctx context.Context, kind string, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, ap, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warn("read error", "listener", kind, "err", err)
			continue
		}
		src := ap.Addr().Unmap()
		p := packet{
			kind:     kind,
			src:      src,
			received: time.Now(),
			data:     append([]byte(nil), buf[:n]...),
		}
		q := c.queues[c.workerFor(src)]
		select {
		case q <- p:
		default:
			c.m.drops.WithLabelValues(src.String(), kind).Inc()
		}
	}
}

func (c *Collector) workerFor(a netip.Addr) int {
	b := a.As16()
	return int(maphash.Bytes(c.seed, b[:]) % uint64(len(c.queues)))
}

// worker decodes datagrams and batches flows toward the sink.
func (c *Collector) worker(sinkCtx context.Context, in <-chan packet) {
	batch := make([]*flow.Flow, 0, c.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.m.batchSize.Observe(float64(len(batch)))
		if err := c.sink.Put(sinkCtx, batch); err != nil {
			c.m.sinkErrors.Inc()
			c.m.sinkDropped.Add(float64(len(batch)))
			c.log.Warn("sink refused batch", "flows", len(batch), "err", err)
		}
		clear(batch) // the sink may keep the records, not the slice
		batch = batch[:0]
	}
	t := time.NewTicker(c.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case p, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = c.decode(p, batch)
			if len(batch) >= c.cfg.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// decode decodes one datagram, updates the exporter state and metrics, and
// appends the resulting flows to out.
func (c *Collector) decode(p packet, out []*flow.Flow) (result []*flow.Flow) {
	before := len(out)
	defer func() {
		// third-party decoders on hostile input: never take the process down
		if r := recover(); r != nil {
			c.log.Error("decoder panic", "src", p.src, "listener", p.kind, "panic", r)
			c.m.decodeErrors.WithLabelValues(p.src.String(), p.kind).Inc()
			result = out[:before]
		}
	}()
	var (
		exp     *exporter
		typ     string
		rates   []uint64
		hadTmpl bool
		err     error
	)
	switch p.kind {
	case kindSFlow:
		typ = "sflow"
		exp, out, rates, err = c.decodeSFlow(p, out)
	default:
		exp = c.reg.get(p.src)
		version := uint16(0)
		if len(p.data) >= 2 {
			version = binary.BigEndian.Uint16(p.data)
		}
		switch version {
		case 5:
			typ = "netflow5"
			out, rates, err = c.decodeNetFlowV5(p, exp, out)
		case 9, 10:
			typ = "netflow9"
			if version == 10 {
				typ = "ipfix"
			}
			out, rates, hadTmpl, err = c.decodeNetFlowV9IPFIX(p, exp, out)
		default:
			typ = "unknown"
			err = fmt.Errorf("unknown NetFlow version %d", version)
		}
	}
	rates = exp.applyIfOverrides(out[before:], c.ifc, rates)
	exp.account(c.m, typ, p.received, len(out)-before, err != nil)
	exp.noteRates(rates)
	if hadTmpl {
		c.m.templates.WithLabelValues(exp.label, typ).Set(float64(countTemplates(exp.templates, typ)))
	}
	if err != nil {
		lvl := slog.LevelDebug
		if !errors.Is(err, netflow.ErrorTemplateNotFound) {
			lvl = slog.LevelDebug + 2 // between debug and info: noisy on bad exporters
		}
		c.log.Log(context.Background(), lvl, "decode error", "exporter", exp.label, "type", typ, "err", err)
	}
	return out
}

// countTemplates counts the templates of one protocol version. goflow2 keys
// templates by version<<48 | domain<<16 | id.
func countTemplates(ts netflow.NetFlowTemplateSystem, typ string) int {
	v := uint64(9)
	if typ == "ipfix" {
		v = 10
	}
	n := 0
	for k := range ts.GetTemplates() {
		if k>>48 == v {
			n++
		}
	}
	return n
}
