package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Binary batch codec used on the bus between the collector and the enricher.
// Only the decoded fields of Flow are carried: enrichment happens after the
// bus, so there is no point in shipping empty strings around.
//
// Layout (version 1):
//
//	magic "UF" | version byte | uvarint flow count | flows...
//
// Each flow:
//
//	flags byte (bit 0..2: TimeReceived / TimeFlowStart / TimeFlowEnd present)
//	varint TimeReceived (unix ns), varint start/end (ns, relative to
//	TimeReceived when present, absolute otherwise)
//	flow type byte (known types as a code, codeFlowTypeOther + string otherwise)
//	uvarints: SamplingRate SequenceNum InIf OutIf SrcAS DstAS SrcPort DstPort
//	          EType SrcVlan DstVlan Bytes Packets
//	addresses: ExporterAddress SrcAddr DstAddr NextHop (tag byte + 0/4/16 bytes;
//	          exporter may use tagSameExporter to repeat the previous one)
//	bytes: SrcNetMask DstNetMask Proto TCPFlags IPTos ICMPType ICMPCode
//	       ForwardingStatus

const (
	codecMagic0  = 'U'
	codecMagic1  = 'F'
	codecVersion = 1

	// minimal encoded size of one flow, used to bound allocations on decode
	minFlowSize = 1 + 1 + 13 + 4 + 8
)

const (
	flagReceived = 1 << iota
	flagStart
	flagEnd
)

// address tags
const (
	tagAddrNone     = 0
	tagAddr4        = 4
	tagAddr6        = 6
	tagSameExporter = 7
)

const codeFlowTypeOther = 255

var flowTypeCodes = []string{"", "netflow5", "netflow9", "ipfix", "sflow"}

// ErrCodec is wrapped by every decoding error of UnmarshalBatch.
var ErrCodec = errors.New("flow codec")

// MarshalBatch appends the binary encoding of flows to dst and returns the
// extended buffer. Nil entries are skipped.
func MarshalBatch(dst []byte, flows []*Flow) []byte {
	n := 0
	for _, f := range flows {
		if f != nil {
			n++
		}
	}
	dst = append(dst, codecMagic0, codecMagic1, codecVersion)
	dst = binary.AppendUvarint(dst, uint64(n))
	var prevExporter netip.Addr
	first := true
	for _, f := range flows {
		if f == nil {
			continue
		}
		dst = appendFlow(dst, f, &prevExporter, first)
		first = false
	}
	return dst
}

func appendFlow(b []byte, f *Flow, prevExporter *netip.Addr, first bool) []byte {
	var flags byte
	if !f.TimeReceived.IsZero() {
		flags |= flagReceived
	}
	if !f.TimeFlowStart.IsZero() {
		flags |= flagStart
	}
	if !f.TimeFlowEnd.IsZero() {
		flags |= flagEnd
	}
	b = append(b, flags)
	var base int64
	if flags&flagReceived != 0 {
		base = f.TimeReceived.UnixNano()
		b = binary.AppendVarint(b, base)
	}
	if flags&flagStart != 0 {
		b = binary.AppendVarint(b, f.TimeFlowStart.UnixNano()-base)
	}
	if flags&flagEnd != 0 {
		b = binary.AppendVarint(b, f.TimeFlowEnd.UnixNano()-base)
	}

	code := codeFlowTypeOther
	for i, t := range flowTypeCodes {
		if t == f.FlowType {
			code = i
			break
		}
	}
	b = append(b, byte(code))
	if code == codeFlowTypeOther {
		b = binary.AppendUvarint(b, uint64(len(f.FlowType)))
		b = append(b, f.FlowType...)
	}

	b = binary.AppendUvarint(b, f.SamplingRate)
	b = binary.AppendUvarint(b, uint64(f.SequenceNum))
	b = binary.AppendUvarint(b, uint64(f.InIf))
	b = binary.AppendUvarint(b, uint64(f.OutIf))
	b = binary.AppendUvarint(b, uint64(f.SrcAS))
	b = binary.AppendUvarint(b, uint64(f.DstAS))
	b = binary.AppendUvarint(b, uint64(f.SrcPort))
	b = binary.AppendUvarint(b, uint64(f.DstPort))
	b = binary.AppendUvarint(b, uint64(f.EType))
	b = binary.AppendUvarint(b, uint64(f.SrcVlan))
	b = binary.AppendUvarint(b, uint64(f.DstVlan))
	b = binary.AppendUvarint(b, f.Bytes)
	b = binary.AppendUvarint(b, f.Packets)

	if !first && f.ExporterAddress == *prevExporter {
		b = append(b, tagSameExporter)
	} else {
		b = appendAddr(b, f.ExporterAddress)
		*prevExporter = f.ExporterAddress
	}
	b = appendAddr(b, f.SrcAddr)
	b = appendAddr(b, f.DstAddr)
	b = appendAddr(b, f.NextHop)

	return append(b, f.SrcNetMask, f.DstNetMask, f.Proto, f.TCPFlags,
		f.IPTos, f.ICMPType, f.ICMPCode, f.ForwardingStatus)
}

// appendAddr encodes an address. IPv4-mapped IPv6 addresses stay IPv6 so
// that the round trip is exact; zones are dropped.
func appendAddr(b []byte, a netip.Addr) []byte {
	switch {
	case a.Is4():
		v := a.As4()
		b = append(b, tagAddr4)
		return append(b, v[:]...)
	case a.Is6():
		v := a.As16()
		b = append(b, tagAddr6)
		return append(b, v[:]...)
	default:
		return append(b, tagAddrNone)
	}
}

// decoder is a bounds-checked reader over an encoded batch. The first error
// sticks; later reads return zero values.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail(what string) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: truncated or invalid %s", ErrCodec, what)
	}
	d.b = nil
}

func (d *decoder) byte(what string) byte {
	if len(d.b) < 1 {
		d.fail(what)
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *decoder) uvarint(what string) uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail(what)
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) uvarintMax(what string, max uint64) uint64 {
	v := d.uvarint(what)
	if v > max {
		d.fail(what)
		return 0
	}
	return v
}

func (d *decoder) varint(what string) int64 {
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail(what)
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) addr(what string, prev netip.Addr, allowSame bool) netip.Addr {
	switch tag := d.byte(what); tag {
	case tagAddrNone:
		return netip.Addr{}
	case tagAddr4:
		if len(d.b) < 4 {
			d.fail(what)
			return netip.Addr{}
		}
		a := netip.AddrFrom4([4]byte(d.b[:4]))
		d.b = d.b[4:]
		return a
	case tagAddr6:
		if len(d.b) < 16 {
			d.fail(what)
			return netip.Addr{}
		}
		a := netip.AddrFrom16([16]byte(d.b[:16]))
		d.b = d.b[16:]
		return a
	case tagSameExporter:
		if !allowSame {
			d.fail(what)
		}
		return prev
	default:
		d.fail(what)
		return netip.Addr{}
	}
}

// UnmarshalBatch decodes a batch produced by MarshalBatch. Times are returned
// in UTC.
func UnmarshalBatch(b []byte) ([]*Flow, error) {
	if len(b) < 3 || b[0] != codecMagic0 || b[1] != codecMagic1 {
		return nil, fmt.Errorf("%w: bad magic", ErrCodec)
	}
	if b[2] != codecVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCodec, b[2])
	}
	d := decoder{b: b[3:]}
	count := d.uvarint("count")
	if d.err != nil {
		return nil, d.err
	}
	if count > uint64(len(d.b)/minFlowSize) {
		return nil, fmt.Errorf("%w: count %d exceeds payload", ErrCodec, count)
	}
	// One backing array for all records keeps decoding allocation-light.
	recs := make([]Flow, count)
	out := make([]*Flow, count)
	var prevExporter netip.Addr
	for i := range recs {
		f := &recs[i]
		out[i] = f
		flags := d.byte("flags")
		if flags&^(flagReceived|flagStart|flagEnd) != 0 {
			d.fail("flags")
		}
		var base int64
		if flags&flagReceived != 0 {
			base = d.varint("time received")
			f.TimeReceived = time.Unix(0, base).UTC()
		}
		if flags&flagStart != 0 {
			f.TimeFlowStart = time.Unix(0, base+d.varint("time start")).UTC()
		}
		if flags&flagEnd != 0 {
			f.TimeFlowEnd = time.Unix(0, base+d.varint("time end")).UTC()
		}
		code := int(d.byte("flow type"))
		switch {
		case code < len(flowTypeCodes):
			f.FlowType = flowTypeCodes[code]
		case code == codeFlowTypeOther:
			if n := d.uvarint("flow type"); n > uint64(len(d.b)) {
				d.fail("flow type")
			} else {
				f.FlowType = string(d.b[:n])
				d.b = d.b[n:]
			}
		default:
			d.fail("flow type")
		}
		f.SamplingRate = d.uvarint("sampling rate")
		f.SequenceNum = uint32(d.uvarintMax("sequence", 1<<32-1))
		f.InIf = uint32(d.uvarintMax("in if", 1<<32-1))
		f.OutIf = uint32(d.uvarintMax("out if", 1<<32-1))
		f.SrcAS = uint32(d.uvarintMax("src as", 1<<32-1))
		f.DstAS = uint32(d.uvarintMax("dst as", 1<<32-1))
		f.SrcPort = uint16(d.uvarintMax("src port", 1<<16-1))
		f.DstPort = uint16(d.uvarintMax("dst port", 1<<16-1))
		f.EType = uint16(d.uvarintMax("etype", 1<<16-1))
		f.SrcVlan = uint16(d.uvarintMax("src vlan", 1<<16-1))
		f.DstVlan = uint16(d.uvarintMax("dst vlan", 1<<16-1))
		f.Bytes = d.uvarint("bytes")
		f.Packets = d.uvarint("packets")
		f.ExporterAddress = d.addr("exporter", prevExporter, i > 0)
		prevExporter = f.ExporterAddress
		f.SrcAddr = d.addr("src addr", netip.Addr{}, false)
		f.DstAddr = d.addr("dst addr", netip.Addr{}, false)
		f.NextHop = d.addr("next hop", netip.Addr{}, false)
		if len(d.b) < 8 {
			d.fail("trailer")
		} else {
			t := d.b[:8]
			f.SrcNetMask, f.DstNetMask, f.Proto, f.TCPFlags = t[0], t[1], t[2], t[3]
			f.IPTos, f.ICMPType, f.ICMPCode, f.ForwardingStatus = t[4], t[5], t[6], t[7]
			d.b = d.b[8:]
		}
		if d.err != nil {
			return nil, d.err
		}
	}
	if len(d.b) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrCodec, len(d.b))
	}
	return out, nil
}
