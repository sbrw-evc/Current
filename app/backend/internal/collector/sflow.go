package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/netsampler/goflow2/v2/decoders/sflow"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// sFlow sampled_header protocols we can parse.
const (
	sflowHeaderEthernet = 1
	sflowHeaderIPv4     = 11
	sflowHeaderIPv6     = 12
)

// decodeSFlow decodes an sFlow v5 datagram. The exporter is the agent
// address announced in the datagram (falling back to the UDP source), so
// lookup happens here rather than in the caller.
func (c *Collector) decodeSFlow(p packet, out []*flow.Flow) (*exporter, []*flow.Flow, []uint64, error) {
	var pkt sflow.Packet
	var err error
	if err = sflowSane(p.data); err == nil {
		err = sflow.DecodeMessageVersion(bytes.NewBuffer(p.data), &pkt)
	}
	addr := p.src
	if a, ok := netip.AddrFromSlice(pkt.AgentIP); ok && a.IsValid() && !a.IsUnspecified() {
		addr = a.Unmap()
	}
	exp := c.reg.get(addr)
	var rates []uint64
	for _, s := range pkt.Samples {
		switch s := s.(type) {
		case sflow.FlowSample:
			f := c.newSFlowFlow(p, exp, pkt.SequenceNumber, s.SamplingRate)
			f.InIf, f.OutIf = sflowIfIndex(s.Input), sflowIfIndex(s.Output)
			out = c.appendSFlowRecords(out, f, s.Records)
			rates = appendRate(rates, f.SamplingRate)
		case sflow.ExpandedFlowSample:
			f := c.newSFlowFlow(p, exp, pkt.SequenceNumber, s.SamplingRate)
			if s.InputIfFormat == 0 {
				f.InIf = s.InputIfValue
			}
			if s.OutputIfFormat == 0 {
				f.OutIf = s.OutputIfValue
			}
			out = c.appendSFlowRecords(out, f, s.Records)
			rates = appendRate(rates, f.SamplingRate)
		case sflow.CounterSample:
			for _, r := range s.Records {
				if ifc, ok := r.Data.(sflow.IfCounters); ok && ifc.IfSpeed > 0 {
					c.ifc.setSpeed(exp.addr, ifc.IfIndex, ifc.IfSpeed, p.received)
				}
			}
		}
	}
	return exp, out, rates, err
}

// sflowSane rejects datagrams the goflow2 decoder would turn into huge
// allocations: it bounds the record count of samples, but not of expanded
// flow samples.
func sflowSane(b []byte) error {
	if len(b) < 8 {
		return errors.New("sflow: short datagram")
	}
	off := 8
	switch binary.BigEndian.Uint32(b[4:]) {
	case 1:
		off += 4
	case 2:
		off += 16
	default:
		return nil // the decoder reports it
	}
	off += 12 // sub-agent, sequence, uptime
	if len(b) < off+4 {
		return nil
	}
	n := int(min(binary.BigEndian.Uint32(b[off:]), 1000))
	off += 4
	for i := 0; i < n && len(b) >= off+8; i++ {
		format := binary.BigEndian.Uint32(b[off:])
		length := int(binary.BigEndian.Uint32(b[off+4:]))
		body := off + 8
		if length < 0 || length > len(b)-body {
			return nil
		}
		// expanded flow sample: 40 bytes of fields, then the record count
		if format == sflow.SAMPLE_FORMAT_EXPANDED_FLOW && length >= 44 &&
			binary.BigEndian.Uint32(b[body+40:]) > 1000 {
			return errors.New("sflow: too many records in expanded flow sample")
		}
		off = body + length
	}
	return nil
}

func appendRate(rates []uint64, r uint64) []uint64 {
	if len(rates) == 0 || rates[len(rates)-1] != r {
		rates = append(rates, r)
	}
	return rates
}

func (c *Collector) newSFlowFlow(p packet, exp *exporter, seq, rate uint32) *flow.Flow {
	return &flow.Flow{
		TimeReceived:    p.received,
		TimeFlowStart:   p.received,
		TimeFlowEnd:     p.received,
		SamplingRate:    exp.effectiveRate(uint64(rate), c.cfg.DefaultSamplingRate),
		ExporterAddress: exp.addr,
		SequenceNum:     seq,
		FlowType:        "sflow",
		Packets:         1,
	}
}

// sflowIfIndex extracts an ifIndex from the compact interface encoding: the
// two top bits give the format, only format 0 is a plain ifIndex, and
// 0x3fffffff means "unknown".
func sflowIfIndex(v uint32) uint32 {
	if v>>30 != 0 || v == 0x3fffffff {
		return 0
	}
	return v
}

// appendSFlowRecords fills f from the flow records of one sample and appends
// it if it carried anything useful.
func (c *Collector) appendSFlowRecords(out []*flow.Flow, f *flow.Flow, records []sflow.FlowRecord) []*flow.Flow {
	var gwNextHop netip.Addr
	useful := false
	for _, r := range records {
		switch d := r.Data.(type) {
		case sflow.SampledHeader:
			f.Bytes = uint64(d.FrameLength)
			switch d.Protocol {
			case sflowHeaderEthernet:
				parseEthernet(d.HeaderData, f)
			case sflowHeaderIPv4:
				f.EType = 0x0800
				parseIPv4(d.HeaderData, f)
			case sflowHeaderIPv6:
				f.EType = 0x86dd
				parseIPv6(d.HeaderData, f)
			}
			useful = true
		case sflow.SampledIPv4:
			if !f.SrcAddr.IsValid() {
				fillSampledIP(f, d.SampledIPBase)
				f.IPTos = uint8(d.Tos)
				f.EType = 0x0800
			}
			useful = true
		case sflow.SampledIPv6:
			if !f.SrcAddr.IsValid() {
				fillSampledIP(f, d.SampledIPBase)
				f.IPTos = uint8(d.Priority)
				f.EType = 0x86dd
			}
			useful = true
		case sflow.ExtendedSwitch:
			f.SrcVlan, f.DstVlan = uint16(d.SrcVlan), uint16(d.DstVlan)
		case sflow.ExtendedRouter:
			f.NextHop = addrFrom(d.NextHop)
			f.SrcNetMask, f.DstNetMask = uint8(d.SrcMaskLen), uint8(d.DstMaskLen)
		case sflow.ExtendedGateway:
			gwNextHop = addrFrom(d.NextHop)
			f.SrcAS = d.SrcAS
			if n := len(d.ASPath); n > 0 {
				f.DstAS = d.ASPath[n-1]
			} else {
				// empty path: the destination is in the router's own AS
				f.DstAS = d.AS
			}
		}
	}
	if !useful {
		return out
	}
	if (!f.NextHop.IsValid() || f.NextHop.IsUnspecified()) && gwNextHop.IsValid() {
		f.NextHop = gwNextHop
	}
	fixICMP(f)
	return append(out, f)
}

func fillSampledIP(f *flow.Flow, d sflow.SampledIPBase) {
	f.SrcAddr, f.DstAddr = addrFrom(d.SrcIP), addrFrom(d.DstIP)
	f.Proto = uint8(d.Protocol)
	f.SrcPort, f.DstPort = uint16(d.SrcPort), uint16(d.DstPort)
	f.TCPFlags = uint8(d.TcpFlags)
	if f.Bytes == 0 {
		f.Bytes = uint64(d.Length)
	}
}

// parseEthernet decodes an Ethernet frame header (with 802.1Q / 802.1ad
// tags) and what follows. Truncated headers fill what they can.
func parseEthernet(b []byte, f *flow.Flow) {
	if len(b) < 14 {
		return
	}
	etype := binary.BigEndian.Uint16(b[12:14])
	b = b[14:]
	for (etype == 0x8100 || etype == 0x88a8) && len(b) >= 4 {
		if f.SrcVlan == 0 {
			f.SrcVlan = binary.BigEndian.Uint16(b) & 0x0fff
		}
		etype = binary.BigEndian.Uint16(b[2:4])
		b = b[4:]
	}
	f.EType = etype
	switch etype {
	case 0x0800:
		parseIPv4(b, f)
	case 0x86dd:
		parseIPv6(b, f)
	}
}

func parseIPv4(b []byte, f *flow.Flow) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	f.IPTos = b[1]
	f.Proto = b[9]
	f.SrcAddr = netip.AddrFrom4([4]byte(b[12:16]))
	f.DstAddr = netip.AddrFrom4([4]byte(b[16:20]))
	// only the first fragment carries the transport header
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 || ihl < 20 || len(b) < ihl {
		return
	}
	parseL4(b[ihl:], f)
}

func parseIPv6(b []byte, f *flow.Flow) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	f.IPTos = b[0]<<4 | b[1]>>4
	next := b[6]
	f.SrcAddr = netip.AddrFrom16([16]byte(b[8:24]))
	f.DstAddr = netip.AddrFrom16([16]byte(b[24:40]))
	b = b[40:]
	// skip the common extension headers
ext:
	for i := 0; i < 8; i++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(b) < 8 {
				f.Proto = next
				return
			}
			l := (int(b[1]) + 1) * 8
			if len(b) < l {
				f.Proto = next
				return
			}
			next, b = b[0], b[l:]
			continue
		case 44: // fragment
			if len(b) < 8 {
				f.Proto = next
				return
			}
			frag := binary.BigEndian.Uint16(b[2:4]) &^ 7
			next, b = b[0], b[8:]
			if frag != 0 {
				f.Proto = next
				return
			}
			continue
		}
		break ext
	}
	f.Proto = next
	parseL4(b, f)
}

func parseL4(b []byte, f *flow.Flow) {
	switch f.Proto {
	case 6: // TCP
		if len(b) >= 14 {
			f.TCPFlags = b[13]
		}
		fallthrough
	case 17, 132: // UDP, SCTP
		if len(b) >= 4 {
			f.SrcPort = binary.BigEndian.Uint16(b[0:2])
			f.DstPort = binary.BigEndian.Uint16(b[2:4])
		}
	case 1, 58: // ICMP, ICMPv6
		if len(b) >= 2 {
			f.ICMPType, f.ICMPCode = b[0], b[1]
		}
	}
}
