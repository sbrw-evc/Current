// Package demoexporter generates synthetic but realistic flow traffic and
// sends it as real NetFlow v9, IPFIX and sFlow v5 datagrams, so that a demo
// stand (or an end-to-end test) can exercise the whole pipeline without a
// router.
//
// Each exporter periodically resends its templates, sampler options and
// interface name options (sFlow: interface counters), like real devices do.
// Volume follows a daily sine pattern.
package demoexporter

import (
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Protocols an exporter can speak.
const (
	ProtoNetFlow9 = "netflow9"
	ProtoIPFIX    = "ipfix"
	ProtoSFlow    = "sflow"
)

// Config describes the simulated network.
type Config struct {
	// NetFlowTarget receives NetFlow v9 and IPFIX (host:port).
	NetFlowTarget string
	// SFlowTarget receives sFlow (host:port).
	SFlowTarget string

	Exporters []Exporter
	Peers     []Peer

	// LocalAS and LocalPrefixes describe "our" network: addresses behind
	// internal interfaces.
	LocalAS       uint32
	LocalPrefixes []netip.Prefix

	// FlowsPerSecond is the number of (sampled) flow records, or sFlow
	// samples, each exporter emits per second at the daily peak.
	FlowsPerSecond float64
	// IPv6Share is the fraction of flows over IPv6, when prefixes allow.
	IPv6Share float64
	// Tick is the sending period.
	Tick time.Duration
	// TemplateInterval is how often templates and option data (sFlow:
	// counter samples) are resent.
	TemplateInterval time.Duration
	// MTU bounds the datagram payload size.
	MTU int
	// Seed makes the traffic reproducible; 0 seeds from the clock.
	Seed uint64
	// Now returns the current time (tests may freeze the diurnal pattern).
	Now func() time.Time

	Logger *slog.Logger
}

// Exporter is one simulated device.
type Exporter struct {
	Name     string
	Protocol string // ProtoNetFlow9, ProtoIPFIX or ProtoSFlow
	// SourceAddr is the local address datagrams are sent from (optional).
	// On Linux any 127.0.0.0/8 address works for loopback targets, which
	// gives each exporter its own identity on a single host.
	SourceAddr netip.Addr
	// AgentAddr is the sFlow agent address (defaults to SourceAddr).
	AgentAddr netip.Addr
	// ObservationDomain is the IPFIX observation domain / NetFlow v9
	// source id.
	ObservationDomain uint32
	SamplingRate      uint32
	Interfaces        []Interface
}

// Interface is one interface of a simulated device.
type Interface struct {
	Index       uint32
	Name        string
	Description string
	Speed       uint64 // bits per second
	// External interfaces face other networks and carry traffic from/to
	// the listed Peers; internal ones carry LocalPrefixes.
	External bool
	Peers    []string
	Vlan     uint16
}

// Peer is a remote network reachable through external interfaces.
type Peer struct {
	Name     string
	AS       uint32
	Prefixes []netip.Prefix
}

func (c Config) withDefaults() Config {
	if c.FlowsPerSecond <= 0 {
		c.FlowsPerSecond = 200
	}
	if c.IPv6Share < 0 {
		c.IPv6Share = 0
	}
	if c.Tick <= 0 {
		c.Tick = 100 * time.Millisecond
	}
	if c.TemplateInterval <= 0 {
		c.TemplateInterval = 30 * time.Second
	}
	if c.MTU <= 0 {
		c.MTU = 1400
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// DefaultConfig returns a small ISP-like network: two edge routers (NetFlow
// v9 and IPFIX) with transit, IX and PNI links, and an sFlow switch. target
// is the collector host, optionally with the NetFlow port ("flow",
// "127.0.0.1:2055"); sFlow goes to port 6343 on the same host. For loopback
// targets every exporter gets its own 127.0.0.x source address.
func DefaultConfig(target string) Config {
	host, port := target, "2055"
	if h, p, err := net.SplitHostPort(target); err == nil {
		host, port = h, p
	}
	loopback := host == "localhost"
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		loopback = true
	}
	src := func(last byte) netip.Addr {
		if !loopback {
			return netip.Addr{}
		}
		return netip.AddrFrom4([4]byte{127, 0, 0, last})
	}
	agent := netip.MustParseAddr("192.0.2.13")
	if loopback {
		agent = src(13)
	}
	p := netip.MustParsePrefix
	const g = 1_000_000_000
	return Config{
		NetFlowTarget: net.JoinHostPort(host, port),
		SFlowTarget:   net.JoinHostPort(host, "6343"),
		LocalAS:       64500,
		LocalPrefixes: []netip.Prefix{
			p("10.10.0.0/16"), p("10.20.0.0/16"), p("198.51.100.0/24"),
			p("2001:db8:10::/48"), p("2001:db8:20::/48"),
		},
		Peers: []Peer{
			{Name: "google", AS: 15169, Prefixes: []netip.Prefix{p("8.8.8.0/24"), p("142.250.0.0/15"), p("2001:4860::/32")}},
			{Name: "cloudflare", AS: 13335, Prefixes: []netip.Prefix{p("1.1.1.0/24"), p("104.16.0.0/13"), p("2606:4700::/32")}},
			{Name: "netflix", AS: 2906, Prefixes: []netip.Prefix{p("45.57.0.0/17"), p("2a00:86c0::/32")}},
			{Name: "meta", AS: 32934, Prefixes: []netip.Prefix{p("31.13.64.0/18"), p("157.240.0.0/16"), p("2a03:2880::/32")}},
			{Name: "akamai", AS: 20940, Prefixes: []netip.Prefix{p("23.32.0.0/11"), p("2a02:26f0::/29")}},
			{Name: "fastly", AS: 54113, Prefixes: []netip.Prefix{p("151.101.0.0/16"), p("2a04:4e40::/32")}},
			{Name: "yandex", AS: 13238, Prefixes: []netip.Prefix{p("77.88.0.0/18"), p("5.255.255.0/24"), p("2a02:6b8::/32")}},
			{Name: "amazon", AS: 16509, Prefixes: []netip.Prefix{p("52.0.0.0/11"), p("54.144.0.0/12"), p("2600:1f00::/24")}},
		},
		FlowsPerSecond:   200,
		IPv6Share:        0.25,
		TemplateInterval: 30 * time.Second,
		Exporters: []Exporter{
			{
				Name: "edge-01", Protocol: ProtoNetFlow9, SourceAddr: src(11), ObservationDomain: 1, SamplingRate: 1000,
				Interfaces: []Interface{
					{Index: 1001, Name: "Te0/0/0", Description: "Transit: Cogent [CID-12345]", Speed: 10 * g, External: true, Peers: []string{"google", "amazon", "akamai", "fastly"}},
					{Index: 1002, Name: "Te0/0/1", Description: "IX: MSK-IX peering", Speed: 10 * g, External: true, Peers: []string{"yandex", "cloudflare", "meta"}},
					{Index: 1010, Name: "Te0/1/0", Description: "core-01 Te1/1", Speed: 10 * g},
					{Index: 1011, Name: "Te0/1/1", Description: "core-02 Te1/1", Speed: 10 * g},
				},
			},
			{
				Name: "edge-02", Protocol: ProtoIPFIX, SourceAddr: src(12), ObservationDomain: 2, SamplingRate: 512,
				Interfaces: []Interface{
					{Index: 2001, Name: "xe-0/0/0", Description: "Transit: RETN [CID-67890]", Speed: 10 * g, External: true, Peers: []string{"google", "amazon", "meta", "fastly"}},
					{Index: 2002, Name: "xe-0/0/1", Description: "PNI: Netflix OCA", Speed: 100 * g, External: true, Peers: []string{"netflix"}},
					{Index: 2010, Name: "ae0", Description: "core-01 ae2", Speed: 40 * g},
					{Index: 2011, Name: "ae1", Description: "core-02 ae2", Speed: 40 * g},
				},
			},
			{
				Name: "dc-sw-01", Protocol: ProtoSFlow, SourceAddr: src(13), AgentAddr: agent, SamplingRate: 2048,
				Interfaces: []Interface{
					{Index: 3001, Name: "Ethernet1", Description: "Transit: local ISP backup", Speed: 1 * g, External: true, Peers: []string{"cloudflare", "yandex"}},
					{Index: 3010, Name: "Ethernet10", Description: "srv-web-01", Speed: 10 * g, Vlan: 100},
					{Index: 3011, Name: "Ethernet11", Description: "srv-db-01", Speed: 10 * g, Vlan: 200},
				},
			},
		},
	}
}
