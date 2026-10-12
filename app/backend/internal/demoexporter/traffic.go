package demoexporter

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"time"
)

// genFlow is one synthetic flow (or, for sFlow, one sampled packet).
type genFlow struct {
	src, dst         netip.Addr
	srcMask, dstMask uint8
	nextHop          netip.Addr
	srcAS, dstAS     uint32
	srcPort, dstPort uint16
	proto            uint8
	tcpFlags         uint8
	tos              uint8
	icmpType         uint8
	icmpCode         uint8
	inIf, outIf      uint32
	vlan             uint16
	bytes, packets   uint64
	start, end       time.Time
}

// app is a traffic class: protocol, server port, packet size and flow size.
type app struct {
	proto    uint8
	port     uint16
	pktSize  int     // average packet size, bytes
	pkts     float64 // average packets per (unsampled-looking) flow record
	weight   float64
	inbound  float64 // share of flows downloading toward our network
	tos      uint8
	icmpType uint8
}

var apps = []app{
	{proto: 6, port: 443, pktSize: 1200, pkts: 40, weight: 45, inbound: 0.85},            // https
	{proto: 17, port: 443, pktSize: 1250, pkts: 50, weight: 15, inbound: 0.9},            // quic
	{proto: 6, port: 80, pktSize: 1100, pkts: 25, weight: 8, inbound: 0.8},               // http
	{proto: 17, port: 53, pktSize: 90, pkts: 1, weight: 12, inbound: 0.5},                // dns
	{proto: 6, port: 22, pktSize: 200, pkts: 30, weight: 2, inbound: 0.3},                // ssh
	{proto: 6, port: 25, pktSize: 600, pkts: 12, weight: 1, inbound: 0.6},                // smtp
	{proto: 17, port: 123, pktSize: 76, pkts: 1, weight: 2, inbound: 0.5},                // ntp
	{proto: 6, port: 993, pktSize: 400, pkts: 10, weight: 2, inbound: 0.7},               // imaps
	{proto: 17, port: 3478, pktSize: 900, pkts: 60, weight: 3, inbound: 0.5},             // stun / webrtc
	{proto: 6, port: 5060, pktSize: 500, pkts: 4, weight: 1, inbound: 0.5},               // sip
	{proto: 1, pktSize: 84, pkts: 3, weight: 2, inbound: 0.5, icmpType: 8},               // ping
	{proto: 6, port: 3389, pktSize: 300, pkts: 50, weight: 1, inbound: 0.2},              // rdp
	{proto: 6, port: 8443, pktSize: 1000, pkts: 20, weight: 2, inbound: 0.7},             // alt https
	{proto: 17, port: 4500, pktSize: 1300, pkts: 80, weight: 2, inbound: 0.5},            // ipsec nat-t
	{proto: 6, port: 443, pktSize: 1400, pkts: 300, weight: 2, inbound: 0.97, tos: 0x20}, // bulk video
}

var appWeightTotal = func() float64 {
	t := 0.0
	for _, a := range apps {
		t += a.weight
	}
	return t
}()

// diurnal returns the traffic factor at t: a sine with its trough at 04:00
// and its peak at 16:00 local time, between 0.2 and 1.
func diurnal(t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60
	return 0.6 + 0.4*math.Sin(2*math.Pi*(h-10)/24)
}

// generator produces flows for one exporter.
type generator struct {
	rnd      *rand.Rand
	cfg      *Config
	exp      *Exporter
	peers    map[string]*Peer
	external []*Interface
	internal []*Interface
	local4   []netip.Prefix
	local6   []netip.Prefix
}

func newGenerator(cfg *Config, exp *Exporter, seed uint64) *generator {
	g := &generator{
		rnd:   rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		cfg:   cfg,
		exp:   exp,
		peers: make(map[string]*Peer),
	}
	for i := range cfg.Peers {
		g.peers[cfg.Peers[i].Name] = &cfg.Peers[i]
	}
	for i := range exp.Interfaces {
		itf := &exp.Interfaces[i]
		if itf.External {
			g.external = append(g.external, itf)
		} else {
			g.internal = append(g.internal, itf)
		}
	}
	for _, p := range cfg.LocalPrefixes {
		if p.Addr().Is4() {
			g.local4 = append(g.local4, p)
		} else {
			g.local6 = append(g.local6, p)
		}
	}
	return g
}

func (g *generator) pickApp() *app {
	x := g.rnd.Float64() * appWeightTotal
	for i := range apps {
		x -= apps[i].weight
		if x <= 0 {
			return &apps[i]
		}
	}
	return &apps[0]
}

// randomHost returns a random address inside p (avoiding the network
// address).
func (g *generator) randomHost(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	hostBits := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && hostBits > 0; i-- {
		n := min(hostBits, 8)
		mask := byte(1<<n - 1)
		b[i] = b[i]&^mask | byte(g.rnd.IntN(256))&mask
		hostBits -= n
	}
	if len(b) == 16 && p.Bits() <= 64 {
		// keep IPv6 hosts in the first /64 of the prefix so that they look
		// like a few LANs rather than noise
		for i := p.Bits() / 8; i < 8; i++ {
			if i*8 >= p.Bits() {
				b[i] = 0
			}
		}
		b[7] = byte(g.rnd.IntN(8))
	}
	a, _ := netip.AddrFromSlice(b)
	if a == p.Addr() {
		a = a.Next()
	}
	return a
}

// next makes one flow ending at now.
func (g *generator) next(now time.Time) (genFlow, bool) {
	if len(g.internal) == 0 {
		return genFlow{}, false
	}
	a := g.pickApp()
	internal := g.internal[g.rnd.IntN(len(g.internal))]

	var f genFlow
	var remote netip.Prefix
	var remoteAS uint32
	var extIf *Interface
	v6 := g.rnd.Float64() < g.cfg.IPv6Share && len(g.local6) > 0

	// remote side: a peer behind an external interface, or (for devices
	// without external interfaces, or 15% of the time) another internal
	// interface
	if len(g.external) > 0 && g.rnd.Float64() > 0.15 {
		extIf = g.external[g.rnd.IntN(len(g.external))]
		if len(extIf.Peers) > 0 {
			peer := g.peers[extIf.Peers[g.rnd.IntN(len(extIf.Peers))]]
			if peer != nil {
				remote, v6 = pickFamily(g.rnd, peer.Prefixes, v6)
				remoteAS = peer.AS
			}
		}
	}
	var local netip.Prefix
	if v6 {
		local = g.local6[g.rnd.IntN(len(g.local6))]
	} else if len(g.local4) > 0 {
		local = g.local4[g.rnd.IntN(len(g.local4))]
	} else {
		return genFlow{}, false
	}
	if !remote.IsValid() {
		// east-west traffic between two internal interfaces
		extIf = g.internal[g.rnd.IntN(len(g.internal))]
		remote = local
		remoteAS = g.cfg.LocalAS
	}

	localHost, remoteHost := g.randomHost(local), g.randomHost(remote)
	ephemeral := uint16(32768 + g.rnd.IntN(28000))
	inbound := g.rnd.Float64() < a.inbound
	localMask, remoteMask := maskFor(local), maskFor(remote)
	if inbound {
		f.src, f.dst = remoteHost, localHost
		f.srcMask, f.dstMask = remoteMask, localMask
		f.srcAS, f.dstAS = remoteAS, g.cfg.LocalAS
		f.srcPort, f.dstPort = a.port, ephemeral
		f.inIf, f.outIf = extIf.Index, internal.Index
		f.nextHop = routerAddr(internal.Index, v6)
		f.vlan = internal.Vlan
	} else {
		f.src, f.dst = localHost, remoteHost
		f.srcMask, f.dstMask = localMask, remoteMask
		f.srcAS, f.dstAS = g.cfg.LocalAS, remoteAS
		f.srcPort, f.dstPort = ephemeral, a.port
		f.inIf, f.outIf = internal.Index, extIf.Index
		f.nextHop = routerAddr(extIf.Index, v6)
		f.vlan = internal.Vlan
	}
	f.proto = a.proto
	f.tos = a.tos
	switch a.proto {
	case 6:
		f.tcpFlags = 0x10 | 0x08 // ACK PSH
		if g.rnd.IntN(4) == 0 {
			f.tcpFlags |= 0x02 // SYN seen
		}
		if g.rnd.IntN(4) == 0 {
			f.tcpFlags |= 0x01 // FIN seen
		}
	case 1:
		f.srcPort, f.dstPort = 0, 0
		f.icmpType = a.icmpType
		if !inbound {
			f.icmpType = 0 // echo reply
		}
		if v6 {
			f.proto = 58
			f.icmpType = 128 // echo request
			if !inbound {
				f.icmpType = 129 // echo reply
			}
		}
	}
	// exponential flow sizes around the app average
	pkts := max(1, uint64(g.rnd.ExpFloat64()*a.pkts))
	size := max(40, a.pktSize+g.rnd.IntN(a.pktSize/4+1)-a.pktSize/8)
	f.packets = pkts
	f.bytes = pkts * uint64(size)
	dur := time.Duration(g.rnd.Int64N(int64(30*time.Second))) + time.Millisecond
	f.end = now.Add(-time.Duration(g.rnd.Int64N(int64(time.Second))))
	f.start = f.end.Add(-dur)
	return f, true
}

func pickFamily(rnd *rand.Rand, prefixes []netip.Prefix, v6 bool) (netip.Prefix, bool) {
	var same, other []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is6() == v6 {
			same = append(same, p)
		} else {
			other = append(other, p)
		}
	}
	switch {
	case len(same) > 0:
		return same[rnd.IntN(len(same))], v6
	case len(other) > 0:
		return other[rnd.IntN(len(other))], !v6
	}
	return netip.Prefix{}, v6
}

// maskFor returns the mask a router would report: the prefix length,
// capped to typical routing granularity.
func maskFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return uint8(max(p.Bits(), 16))
	}
	return uint8(max(p.Bits(), 32))
}

// routerAddr makes a stable next-hop address for an interface.
func routerAddr(ifIndex uint32, v6 bool) netip.Addr {
	if v6 {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 14: byte(ifIndex >> 8), 15: byte(ifIndex)})
	}
	return netip.AddrFrom4([4]byte{100, 64, byte(ifIndex >> 8), byte(ifIndex)})
}
