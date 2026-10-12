package demoexporter

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// sFlow v5 encoding (XDR, big-endian, 4-byte aligned).

const (
	sfSampleFlow    = 1
	sfSampleCounter = 2

	sfRecordRawHeader  = 1
	sfRecordExtSwitch  = 1001
	sfRecordExtRouter  = 1002
	sfRecordExtGateway = 1003
	sfCounterGenericIf = 1

	sfHeaderEthernet = 1
)

// sfEncoder builds sFlow datagrams for one agent.
type sfEncoder struct {
	agent      netip.Addr
	localAS    uint32
	rate       uint32
	boot       time.Time
	ifaces     []Interface
	seq        uint32 // datagrams
	sampleSeq  uint32
	counterSeq uint32
	pool       uint32
	octets     map[uint32]uint64
}

func (e *sfEncoder) header(b []byte, now time.Time, samples int) []byte {
	b = be32(b, 5)
	if e.agent.Is4() {
		b = be32(b, 1)
	} else {
		b = be32(b, 2)
	}
	b = append(b, e.agent.AsSlice()...)
	b = be32(b, 0) // sub-agent
	b = be32(b, e.seq)
	b = be32(b, uint32(now.Sub(e.boot).Milliseconds()))
	return be32(b, uint32(samples))
}

// packets encodes flows as flow samples (one sampled packet each) and,
// when counters is set, one counter sample per interface.
func (e *sfEncoder) packets(now time.Time, flows []genFlow, counters bool, mtu int) [][]byte {
	var samples [][]byte
	if counters {
		for _, itf := range e.ifaces {
			samples = append(samples, e.counterSample(itf))
		}
	}
	for i := range flows {
		samples = append(samples, e.flowSample(&flows[i]))
	}
	var out [][]byte
	hdrLen := 28
	if e.agent.Is6() {
		hdrLen = 40
	}
	for len(samples) > 0 {
		n, size := 0, hdrLen
		for n < len(samples) && (n == 0 || size+len(samples[n]) <= mtu) {
			size += len(samples[n])
			n++
		}
		b := e.header(make([]byte, 0, size), now, n)
		for _, s := range samples[:n] {
			b = append(b, s...)
		}
		e.seq++
		out = append(out, b)
		samples = samples[n:]
	}
	return out
}

// beginRecord / endRecord frame a data_format + length block.
func beginRecord(b []byte, format uint32) ([]byte, int) {
	b = be32(b, format)
	off := len(b)
	return be32(b, 0), off
}

func endRecord(b []byte, off int) []byte {
	for (len(b)-off-4)%4 != 0 {
		b = append(b, 0)
	}
	binary.BigEndian.PutUint32(b[off:], uint32(len(b)-off-4))
	return b
}

func appendSFAddr(b []byte, a netip.Addr) []byte {
	switch {
	case a.Is4():
		b = be32(b, 1)
	case a.Is6():
		b = be32(b, 2)
	default:
		return append(be32(b, 1), 0, 0, 0, 0)
	}
	return append(b, a.AsSlice()...)
}

func (e *sfEncoder) flowSample(f *genFlow) []byte {
	e.sampleSeq++
	e.pool += e.rate
	b, off := beginRecord(nil, sfSampleFlow)
	b = be32(b, e.sampleSeq)
	b = be32(b, f.inIf) // source id: type 0 (ifIndex) << 24 | ifIndex
	b = be32(b, e.rate)
	b = be32(b, e.pool)
	b = be32(b, 0) // drops
	b = be32(b, f.inIf)
	b = be32(b, f.outIf)
	b = be32(b, 4) // records

	hdr, frameLen := buildFrame(f)
	r, roff := beginRecord(b, sfRecordRawHeader)
	r = be32(r, sfHeaderEthernet)
	r = be32(r, frameLen)
	r = be32(r, 4) // FCS stripped
	r = be32(r, uint32(len(hdr)))
	r = append(r, hdr...)
	b = endRecord(r, roff)

	b, roff = beginRecord(b, sfRecordExtSwitch)
	b = be32(b, uint32(f.vlan))
	b = be32(b, 0)
	b = be32(b, uint32(f.vlan))
	b = be32(b, 0)
	b = endRecord(b, roff)

	b, roff = beginRecord(b, sfRecordExtRouter)
	b = appendSFAddr(b, f.nextHop)
	b = be32(b, uint32(f.srcMask))
	b = be32(b, uint32(f.dstMask))
	b = endRecord(b, roff)

	b, roff = beginRecord(b, sfRecordExtGateway)
	b = appendSFAddr(b, f.nextHop)
	b = be32(b, e.localAS)
	b = be32(b, f.srcAS)
	b = be32(b, f.srcAS) // src peer AS
	if f.dstAS != 0 && f.dstAS != e.localAS {
		b = be32(b, 1) // one AS path segment
		b = be32(b, 2) // AS_SEQUENCE
		b = be32(b, 1)
		b = be32(b, f.dstAS)
	} else {
		b = be32(b, 0)
	}
	b = be32(b, 0)   // communities
	b = be32(b, 100) // local pref
	b = endRecord(b, roff)

	return endRecord(b, off)
}

func (e *sfEncoder) counterSample(itf Interface) []byte {
	e.counterSeq++
	if e.octets == nil {
		e.octets = make(map[uint32]uint64)
	}
	e.octets[itf.Index] += uint64(e.counterSeq) * 1_000_000
	oct := e.octets[itf.Index]
	b, off := beginRecord(nil, sfSampleCounter)
	b = be32(b, e.counterSeq)
	b = be32(b, itf.Index)
	b = be32(b, 1) // records
	r, roff := beginRecord(b, sfCounterGenericIf)
	r = be32(r, itf.Index)
	r = be32(r, 6) // ethernetCsmacd
	r = binary.BigEndian.AppendUint64(r, itf.Speed)
	r = be32(r, 1) // full duplex
	r = be32(r, 3) // admin up, oper up
	r = binary.BigEndian.AppendUint64(r, oct)
	for range 6 {
		r = be32(r, 0)
	}
	r = binary.BigEndian.AppendUint64(r, oct/2)
	for range 6 {
		r = be32(r, 0)
	}
	b = endRecord(r, roff)
	return endRecord(b, off)
}

// buildFrame synthesizes the first bytes of a sampled Ethernet frame:
// Ethernet (+802.1Q), IPv4/IPv6 and the transport header.
func buildFrame(f *genFlow) ([]byte, uint32) {
	pktSize := 64
	if f.packets > 0 {
		pktSize = max(64, int(f.bytes/f.packets))
	}
	b := make([]byte, 0, 96)
	b = append(b, 0x02, 0, 0, 0, 0, 0x01) // dst MAC
	b = append(b, 0x02, 0, 0, 0, 0, 0x02) // src MAC
	frameLen := pktSize + 14
	if f.vlan != 0 {
		b = be16(b, 0x8100)
		b = be16(b, f.vlan&0x0fff)
		frameLen += 4
	}
	l4 := l4Header(f)
	ipLen := pktSize
	if f.src.Is4() {
		b = be16(b, 0x0800)
		b = append(b, 0x45, f.tos)
		b = be16(b, uint16(ipLen))
		b = append(b, 0, 0, 0x40, 0) // id, DF
		b = append(b, 64, f.proto, 0, 0)
		b = append(b, f.src.AsSlice()...)
		b = append(b, f.dst.AsSlice()...)
	} else {
		b = be16(b, 0x86dd)
		b = append(b, 0x60|f.tos>>4, f.tos<<4, 0, 0)
		b = be16(b, uint16(max(0, ipLen-40)))
		b = append(b, f.proto, 64)
		b = append(b, f.src.AsSlice()...)
		b = append(b, f.dst.AsSlice()...)
	}
	b = append(b, l4...)
	return b, uint32(frameLen)
}

func l4Header(f *genFlow) []byte {
	switch f.proto {
	case 6:
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:], f.srcPort)
		binary.BigEndian.PutUint16(h[2:], f.dstPort)
		h[12] = 5 << 4
		h[13] = f.tcpFlags
		return h
	case 17:
		h := make([]byte, 8)
		binary.BigEndian.PutUint16(h[0:], f.srcPort)
		binary.BigEndian.PutUint16(h[2:], f.dstPort)
		return h
	case 1, 58:
		return []byte{f.icmpType, f.icmpCode, 0, 0, 0, 1, 0, 1}
	}
	return nil
}
