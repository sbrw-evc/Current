package demoexporter

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// NetFlow v9 / IPFIX encoding. Both share information element numbers for
// everything used here; they differ in headers, set ids and option
// templates.

type field struct{ ie, length uint16 }

const (
	tmplV4      = 256
	tmplV6      = 257
	tmplSampler = 258
	tmplIfaces  = 259

	variableLength = 0xffff

	v9ScopeSystem = 1

	// forwardingStatus: "forwarded", reason unknown (RFC 7270)
	fwdForwarded = 64
)

var (
	v9FieldsV4 = []field{
		{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}, {8, 4}, {9, 1}, {10, 4}, {11, 2}, {12, 4},
		{13, 1}, {14, 4}, {15, 4}, {16, 4}, {17, 4}, {21, 4}, {22, 4}, {32, 2}, {48, 1}, {58, 2}, {89, 1},
	}
	v9FieldsV6 = []field{
		{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}, {27, 16}, {29, 1}, {10, 4}, {11, 2}, {28, 16},
		{30, 1}, {14, 4}, {62, 16}, {16, 4}, {17, 4}, {21, 4}, {22, 4}, {139, 2}, {48, 1}, {58, 2}, {89, 1},
	}
	ipfixFieldsV4 = []field{
		{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}, {8, 4}, {9, 1}, {10, 4}, {11, 2}, {12, 4},
		{13, 1}, {14, 4}, {15, 4}, {16, 4}, {17, 4}, {152, 8}, {153, 8}, {176, 1}, {177, 1}, {243, 2}, {89, 1},
	}
	ipfixFieldsV6 = []field{
		{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}, {27, 16}, {29, 1}, {10, 4}, {11, 2}, {28, 16},
		{30, 1}, {14, 4}, {62, 16}, {16, 4}, {17, 4}, {152, 8}, {153, 8}, {178, 1}, {179, 1}, {243, 2}, {89, 1},
	}

	// sampler options: v9 announces sampler id 1 in random mode, and data
	// records name it (IE 48); IPFIX announces a domain-wide
	// samplingPacketInterval / samplingPacketSpace pair.
	v9SamplerScope    = []field{{v9ScopeSystem, 4}}
	v9SamplerOptions  = []field{{48, 1}, {49, 1}, {50, 4}}
	ipfixSamplerScope = []field{{149, 4}}
	ipfixSamplerOpts  = []field{{305, 4}, {306, 4}}

	v9IfScope      = []field{{v9ScopeSystem, 4}}
	v9IfOptions    = []field{{10, 4}, {82, 32}, {83, 64}}
	ipfixIfScope   = []field{{10, 4}}
	ipfixIfOptions = []field{{82, variableLength}, {83, variableLength}}
)

func recordSize(fields []field) int {
	n := 0
	for _, f := range fields {
		n += int(f.length)
	}
	return n
}

// nfEncoder builds NetFlow v9 or IPFIX datagrams for one exporter.
type nfEncoder struct {
	ipfix  bool
	domain uint32
	rate   uint32
	boot   time.Time
	ifaces []Interface
	seq    uint32 // v9: datagrams sent; IPFIX: data records sent
}

func (e *nfEncoder) fields(v6 bool) []field {
	switch {
	case e.ipfix && v6:
		return ipfixFieldsV6
	case e.ipfix:
		return ipfixFieldsV4
	case v6:
		return v9FieldsV6
	default:
		return v9FieldsV4
	}
}

func (e *nfEncoder) headerLen() int {
	if e.ipfix {
		return 16
	}
	return 20
}

// header appends a header; count (v9) and length (IPFIX) are patched by
// finish.
func (e *nfEncoder) header(b []byte, now time.Time) []byte {
	if e.ipfix {
		b = be16(b, 10)
		b = be16(b, 0) // length, patched
		b = be32(b, uint32(now.Unix()))
		b = be32(b, e.seq)
		return be32(b, e.domain)
	}
	b = be16(b, 9)
	b = be16(b, 0) // count, patched
	b = be32(b, e.uptime(now))
	b = be32(b, uint32(now.Unix()))
	b = be32(b, e.seq)
	return be32(b, e.domain)
}

func (e *nfEncoder) finish(b []byte, records int) []byte {
	if e.ipfix {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		e.seq += uint32(records)
	} else {
		binary.BigEndian.PutUint16(b[2:], uint16(records))
		e.seq++
	}
	return b
}

func (e *nfEncoder) uptime(now time.Time) uint32 {
	return uint32(now.Sub(e.boot).Milliseconds())
}

// beginSet starts a set and returns its offset for endSet.
func beginSet(b []byte, id uint16) ([]byte, int) {
	off := len(b)
	b = be16(b, id)
	return be16(b, 0), off
}

// endSet patches the set length; v9 sets are padded to 4 bytes.
func (e *nfEncoder) endSet(b []byte, off int) []byte {
	if !e.ipfix {
		for (len(b)-off)%4 != 0 {
			b = append(b, 0)
		}
	}
	binary.BigEndian.PutUint16(b[off+2:], uint16(len(b)-off))
	return b
}

func appendFields(b []byte, fields []field) []byte {
	for _, f := range fields {
		b = be16(b, f.ie)
		b = be16(b, f.length)
	}
	return b
}

// controlPacket returns a datagram with templates, option templates, the
// sampler option record and the interface option records.
func (e *nfEncoder) controlPacket(now time.Time) []byte {
	b := e.header(make([]byte, 0, 1500), now)
	records := 0

	// data templates
	id := uint16(0)
	if e.ipfix {
		id = 2
	}
	b, off := beginSet(b, id)
	for _, t := range []struct {
		id uint16
		v6 bool
	}{{tmplV4, false}, {tmplV6, true}} {
		fs := e.fields(t.v6)
		b = be16(b, t.id)
		b = be16(b, uint16(len(fs)))
		b = appendFields(b, fs)
		records++
	}
	b = e.endSet(b, off)

	// option templates
	sScope, sOpts, iScope, iOpts := v9SamplerScope, v9SamplerOptions, v9IfScope, v9IfOptions
	if e.ipfix {
		sScope, sOpts, iScope, iOpts = ipfixSamplerScope, ipfixSamplerOpts, ipfixIfScope, ipfixIfOptions
	}
	id = 1
	if e.ipfix {
		id = 3
	}
	b, off = beginSet(b, id)
	for _, t := range []struct {
		id            uint16
		scope, option []field
	}{{tmplSampler, sScope, sOpts}, {tmplIfaces, iScope, iOpts}} {
		b = be16(b, t.id)
		if e.ipfix {
			b = be16(b, uint16(len(t.scope)+len(t.option)))
			b = be16(b, uint16(len(t.scope)))
		} else {
			b = be16(b, uint16(len(t.scope)*4)) // lengths in bytes
			b = be16(b, uint16(len(t.option)*4))
		}
		b = appendFields(b, t.scope)
		b = appendFields(b, t.option)
		records++
	}
	b = e.endSet(b, off)

	// sampler option data
	b, off = beginSet(b, tmplSampler)
	if e.ipfix {
		b = be32(b, e.domain)
		b = be32(b, 1)        // samplingPacketInterval: select 1 packet...
		b = be32(b, e.rate-1) // samplingPacketSpace: ...then skip rate-1
	} else {
		b = be32(b, 0)      // system scope
		b = append(b, 1, 2) // sampler id 1, random sampling
		b = be32(b, e.rate) // samplerRandomInterval
	}
	records++
	b = e.endSet(b, off)

	// interface option data
	b, off = beginSet(b, tmplIfaces)
	for _, itf := range e.ifaces {
		if e.ipfix {
			b = be32(b, itf.Index)
			b = appendVarString(b, itf.Name)
			b = appendVarString(b, itf.Description)
		} else {
			b = be32(b, 0)
			b = be32(b, itf.Index)
			b = appendFixedString(b, itf.Name, 32)
			b = appendFixedString(b, itf.Description, 64)
		}
		records++
	}
	b = e.endSet(b, off)
	// option records do not count in the IPFIX sequence number (it counts
	// data records only), but they do in the v9 header count
	if e.ipfix {
		return e.finish(b, 0)
	}
	return e.finish(b, records)
}

func appendVarString(b []byte, s string) []byte {
	if len(s) > 254 {
		s = s[:254]
	}
	b = append(b, byte(len(s)))
	return append(b, s...)
}

func appendFixedString(b []byte, s string, n int) []byte {
	if len(s) > n {
		s = s[:n]
	}
	b = append(b, s...)
	for i := len(s); i < n; i++ {
		b = append(b, 0)
	}
	return b
}

// dataPackets encodes flows into as many datagrams as needed.
func (e *nfEncoder) dataPackets(now time.Time, flows []genFlow, mtu int) [][]byte {
	var out [][]byte
	for _, v6 := range []bool{false, true} {
		fields := e.fields(v6)
		size := recordSize(fields)
		perPacket := max(1, (mtu-e.headerLen()-4)/size)
		tmpl := uint16(tmplV4)
		if v6 {
			tmpl = tmplV6
		}
		var batch []*genFlow
		emit := func() {
			if len(batch) == 0 {
				return
			}
			b := e.header(make([]byte, 0, e.headerLen()+4+len(batch)*size+3), now)
			b, off := beginSet(b, tmpl)
			for _, f := range batch {
				b = e.appendRecord(b, f, fields)
			}
			b = e.endSet(b, off)
			out = append(out, e.finish(b, len(batch)))
			batch = batch[:0]
		}
		for i := range flows {
			if flows[i].src.Is6() != v6 {
				continue
			}
			batch = append(batch, &flows[i])
			if len(batch) == perPacket {
				emit()
			}
		}
		emit()
	}
	return out
}

func (e *nfEncoder) appendRecord(b []byte, f *genFlow, fields []field) []byte {
	for _, fd := range fields {
		var v uint64
		switch fd.ie {
		case 1:
			v = f.bytes
		case 2:
			v = f.packets
		case 4:
			v = uint64(f.proto)
		case 5:
			v = uint64(f.tos)
		case 6:
			v = uint64(f.tcpFlags)
		case 7:
			v = uint64(f.srcPort)
		case 8, 27:
			b = appendAddr(b, f.src, int(fd.length))
			continue
		case 12, 28:
			b = appendAddr(b, f.dst, int(fd.length))
			continue
		case 15, 62:
			b = appendAddr(b, f.nextHop, int(fd.length))
			continue
		case 9, 29:
			v = uint64(f.srcMask)
		case 13, 30:
			v = uint64(f.dstMask)
		case 10:
			v = uint64(f.inIf)
		case 11:
			v = uint64(f.dstPort)
		case 14:
			v = uint64(f.outIf)
		case 16:
			v = uint64(f.srcAS)
		case 17:
			v = uint64(f.dstAS)
		case 21:
			v = uint64(e.uptime(f.end))
		case 22:
			v = uint64(e.uptime(f.start))
		case 32, 139:
			v = uint64(f.icmpType)<<8 | uint64(f.icmpCode)
		case 48:
			v = 1 // sampler id announced in the options
		case 58, 243:
			v = uint64(f.vlan)
		case 89:
			v = fwdForwarded
		case 152:
			v = uint64(f.start.UnixMilli())
		case 153:
			v = uint64(f.end.UnixMilli())
		case 176, 178:
			v = uint64(f.icmpType)
		case 177, 179:
			v = uint64(f.icmpCode)
		}
		b = beN(b, v, int(fd.length))
	}
	return b
}

func be16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func be32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// beN appends the low n bytes of v, big-endian.
func beN(b []byte, v uint64, n int) []byte {
	for i := n - 1; i >= 0; i-- {
		if i >= 8 {
			b = append(b, 0)
			continue
		}
		b = append(b, byte(v>>(8*i)))
	}
	return b
}

// appendAddr appends an address as exactly n bytes (zeros if it does not
// fit the field).
func appendAddr(b []byte, a netip.Addr, n int) []byte {
	s := a.AsSlice()
	if len(s) != n {
		return append(b, make([]byte, n)...)
	}
	return append(b, s...)
}
