package collector

import (
	"bytes"
	"net/netip"
	"strings"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/decoders/netflowlegacy"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// Information element numbers used below (IANA IPFIX registry; NetFlow v9
// uses the same numbers for the common ones).
const (
	ieOctetDeltaCount        = 1
	iePacketDeltaCount       = 2
	ieProtocol               = 4
	ieTOS                    = 5
	ieTCPFlags               = 6
	ieSrcPort                = 7
	ieSrcIPv4                = 8
	ieSrcMaskV4              = 9
	ieIngressInterface       = 10
	ieDstPort                = 11
	ieDstIPv4                = 12
	ieDstMaskV4              = 13
	ieEgressInterface        = 14
	ieNextHopIPv4            = 15
	ieSrcAS                  = 16
	ieDstAS                  = 17
	ieBGPNextHopIPv4         = 18
	ieLastSwitched           = 21
	ieFirstSwitched          = 22
	iePostOctetDelta         = 23
	iePostPacketDelta        = 24
	ieSrcIPv6                = 27
	ieDstIPv6                = 28
	ieSrcMaskV6              = 29
	ieDstMaskV6              = 30
	ieICMPTypeCodeV4         = 32
	ieSamplingInterval       = 34
	ieSamplerID              = 48
	ieSamplerRandomInterval  = 50
	ieSrcVlan                = 58
	ieDstVlan                = 59
	ieIPVersion              = 60
	ieNextHopIPv6            = 62
	ieBGPNextHopIPv6         = 63
	ieInterfaceName          = 82
	ieInterfaceDescription   = 83
	ieOctetTotalCount        = 85
	iePacketTotalCount       = 86
	ieForwardingStatus       = 89
	ieICMPTypeCodeV6         = 139
	ieFlowStartSeconds       = 150
	ieFlowEndSeconds         = 151
	ieFlowStartMilliseconds  = 152
	ieFlowEndMilliseconds    = 153
	ieSystemInitTimeMillis   = 160
	ieICMPTypeV4             = 176
	ieICMPCodeV4             = 177
	ieICMPTypeV6             = 178
	ieICMPCodeV6             = 179
	ieDot1qVlanID            = 243
	iePostDot1qVlanID        = 254
	ieEthernetType           = 256
	ieSelectorID             = 302
	ieSamplingPacketInterval = 305
	ieSamplingPacketSpace    = 306
	ieSamplingSize           = 309
	ieSamplingPopulation     = 310

	// NetFlow v9 option scope types (not IEs).
	v9ScopeInterface = 2
)

// beUint decodes a big-endian unsigned integer of 1..8 bytes (reduced-size
// encoding is allowed by IPFIX); longer values keep their last 8 bytes.
func beUint(b []byte) uint64 {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func fieldBytes(f netflow.DataField) []byte {
	b, _ := f.Value.([]byte)
	return b
}

// samplingFields collects sampling IEs found in a record or option data.
type samplingFields struct {
	interval, random, pktInterval, pktSpace, size, population uint64
	samplerID                                                 uint64
	hasSampler                                                bool
}

func (s *samplingFields) set(ie uint16, v uint64) bool {
	switch ie {
	case ieSamplingInterval:
		s.interval = v
	case ieSamplerRandomInterval:
		s.random = v
	case ieSamplingPacketInterval:
		s.pktInterval = v
	case ieSamplingPacketSpace:
		s.pktSpace = v
	case ieSamplingSize:
		s.size = v
	case ieSamplingPopulation:
		s.population = v
	case ieSamplerID, ieSelectorID:
		s.samplerID, s.hasSampler = v, true
	default:
		return false
	}
	return true
}

func (s *samplingFields) rate() uint64 {
	switch {
	case s.interval > 0:
		return s.interval
	case s.random > 0:
		return s.random
	case s.pktInterval > 0:
		// select pktInterval packets, then skip pktSpace packets
		return (s.pktInterval + s.pktSpace) / s.pktInterval
	case s.size > 0 && s.population > 0:
		return s.population / s.size
	}
	return 0
}

// nfContext carries per-datagram data needed to convert records.
type nfContext struct {
	exp        *exporter
	received   time.Time
	version    uint16
	domain     uint32
	sequence   uint32
	exportTime time.Time // header export time (seconds precision)
	uptimeMs   uint32    // v9 only
	flowType   string
}

// decodeNetFlowV5 decodes a NetFlow v5 datagram and returns the sampling
// rates applied.
func (c *Collector) decodeNetFlowV5(p packet, exp *exporter, out []*flow.Flow) ([]*flow.Flow, []uint64, error) {
	var pkt netflowlegacy.PacketNetFlowV5
	if err := netflowlegacy.DecodeMessageVersion(bytes.NewBuffer(p.data), &pkt); err != nil {
		return out, nil, err
	}
	// low 14 bits: interval; high 2 bits: sampling mode
	rate := exp.effectiveRate(uint64(pkt.SamplingInterval&0x3fff), c.cfg.DefaultSamplingRate)
	export := time.Unix(int64(pkt.UnixSecs), int64(pkt.UnixNSecs))
	uptimeToTime := func(ms uint32) time.Time {
		return export.Add(-time.Duration(int32(pkt.SysUptime-ms)) * time.Millisecond)
	}
	for _, r := range pkt.Records {
		f := &flow.Flow{
			TimeReceived:    p.received,
			TimeFlowStart:   uptimeToTime(r.First),
			TimeFlowEnd:     uptimeToTime(r.Last),
			SamplingRate:    rate,
			ExporterAddress: exp.addr,
			SequenceNum:     pkt.FlowSequence,
			FlowType:        "netflow5",
			InIf:            uint32(r.Input),
			OutIf:           uint32(r.Output),
			SrcAddr:         v4(uint32(r.SrcAddr)),
			DstAddr:         v4(uint32(r.DstAddr)),
			NextHop:         v4(uint32(r.NextHop)),
			SrcNetMask:      r.SrcMask,
			DstNetMask:      r.DstMask,
			SrcAS:           uint32(r.SrcAS),
			DstAS:           uint32(r.DstAS),
			SrcPort:         r.SrcPort,
			DstPort:         r.DstPort,
			Proto:           r.Proto,
			EType:           0x0800,
			TCPFlags:        r.TCPFlags,
			IPTos:           r.Tos,
			Bytes:           uint64(r.DOctets),
			Packets:         uint64(r.DPkts),
		}
		fixICMP(f)
		out = append(out, f)
	}
	if len(pkt.Records) == 0 {
		return out, nil, nil
	}
	return out, []uint64{rate}, nil
}

func v4(a uint32) netip.Addr {
	if a == 0 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
}

// decodeNetFlowV9IPFIX handles NetFlow v9 and IPFIX. Template, options and
// data sets are processed in datagram order, so options sent ahead of data in
// the same datagram already apply to it.
func (c *Collector) decodeNetFlowV9IPFIX(p packet, exp *exporter, out []*flow.Flow) ([]*flow.Flow, []uint64, bool, error) {
	var (
		v9         netflow.NFv9Packet
		ipfix      netflow.IPFIXPacket
		flowSets   []any
		ctx        = nfContext{exp: exp, received: p.received}
		hadTmpl    bool
		ratesSeen  []uint64
		decodeErrs = netflow.DecodeMessageVersion(bytes.NewBuffer(p.data), exp.templates, &v9, &ipfix)
	)
	switch {
	case v9.Version == 9:
		ctx.version, ctx.domain, ctx.sequence = 9, v9.SourceId, v9.SequenceNumber
		ctx.exportTime = time.Unix(int64(v9.UnixSeconds), 0)
		ctx.uptimeMs = v9.SystemUptime
		ctx.flowType = "netflow9"
		flowSets = v9.FlowSets
	case ipfix.Version == 10:
		ctx.version, ctx.domain, ctx.sequence = 10, ipfix.ObservationDomainId, ipfix.SequenceNumber
		ctx.exportTime = time.Unix(int64(ipfix.ExportTime), 0)
		ctx.flowType = "ipfix"
		flowSets = ipfix.FlowSets
	default:
		return out, nil, false, decodeErrs
	}

	for _, fs := range flowSets {
		switch fs := fs.(type) {
		case netflow.TemplateFlowSet, netflow.NFv9OptionsTemplateFlowSet, netflow.IPFIXOptionsTemplateFlowSet:
			hadTmpl = true
		case netflow.OptionsDataFlowSet:
			for _, rec := range fs.Records {
				c.applyOptions(&ctx, rec)
			}
		case netflow.DataFlowSet:
			for _, rec := range fs.Records {
				f, rate := c.convertRecord(&ctx, rec.Values)
				out = append(out, f)
				if len(ratesSeen) == 0 || ratesSeen[len(ratesSeen)-1] != rate {
					ratesSeen = append(ratesSeen, rate)
				}
			}
		}
	}
	return out, ratesSeen, hadTmpl, decodeErrs
}

// applyOptions learns sampler rates and interface names from option data.
func (c *Collector) applyOptions(ctx *nfContext, rec netflow.OptionsDataRecord) {
	var (
		s           samplingFields
		ifIndex     uint64
		hasIf       bool
		name, descr string
	)
	for _, f := range rec.ScopesValues {
		if f.PenProvided {
			continue
		}
		b := fieldBytes(f)
		if ctx.version == 9 {
			// v9 scopes are scope types, not IEs
			if f.Type == v9ScopeInterface {
				ifIndex, hasIf = beUint(b), true
			}
			continue
		}
		switch f.Type {
		case ieIngressInterface, ieEgressInterface:
			ifIndex, hasIf = beUint(b), true
		default:
			s.set(f.Type, beUint(b))
		}
	}
	for _, f := range rec.OptionsValues {
		if f.PenProvided {
			continue
		}
		b := fieldBytes(f)
		switch f.Type {
		case ieIngressInterface, ieEgressInterface:
			ifIndex, hasIf = beUint(b), true
		case ieInterfaceName:
			name = cleanString(b)
		case ieInterfaceDescription:
			descr = cleanString(b)
		default:
			s.set(f.Type, beUint(b))
		}
	}
	if rate := s.rate(); rate > 0 {
		id := anySampler
		if s.hasSampler {
			id = s.samplerID
		}
		ctx.exp.setSampler(samplerKey{ctx.version, ctx.domain, id}, rate)
	}
	if hasIf && (name != "" || descr != "") {
		c.ifc.setNames(ctx.exp.addr, uint32(ifIndex), name, descr, ctx.received)
	}
}

// cleanString trims the NUL padding fixed-length string fields carry.
func cleanString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// convertRecord turns a v9/IPFIX data record into a flow and returns the
// effective sampling rate applied.
func (c *Collector) convertRecord(ctx *nfContext, values []netflow.DataField) (*flow.Flow, uint64) {
	f := &flow.Flow{
		TimeReceived:    ctx.received,
		ExporterAddress: ctx.exp.addr,
		SequenceNum:     ctx.sequence,
		FlowType:        ctx.flowType,
	}
	var (
		s                                   samplingFields
		postBytes, postPkts, totBytes, totP uint64
		bgpNH4, bgpNH6                      netip.Addr
		first, last                         uint64
		hasFirst, hasLast                   bool
		startMs, endMs, startS, endS        uint64
		sysInit                             uint64
		ipVersion                           uint64
		icmpTC                              uint64
		hasICMPTC, hasICMPSplit             bool
		dot1q, postDot1q                    uint64
	)
	for _, v := range values {
		if v.PenProvided {
			continue
		}
		b := fieldBytes(v)
		switch v.Type {
		case ieOctetDeltaCount:
			f.Bytes = beUint(b)
		case iePacketDeltaCount:
			f.Packets = beUint(b)
		case iePostOctetDelta:
			postBytes = beUint(b)
		case iePostPacketDelta:
			postPkts = beUint(b)
		case ieOctetTotalCount:
			totBytes = beUint(b)
		case iePacketTotalCount:
			totP = beUint(b)
		case ieProtocol:
			f.Proto = uint8(beUint(b))
		case ieTOS:
			f.IPTos = uint8(beUint(b))
		case ieTCPFlags:
			f.TCPFlags = uint8(beUint(b)) // IPFIX may use 2 bytes; low byte holds the classic flags
		case ieSrcPort:
			f.SrcPort = uint16(beUint(b))
		case ieDstPort:
			f.DstPort = uint16(beUint(b))
		case ieSrcIPv4, ieSrcIPv6:
			f.SrcAddr = addrFrom(b)
		case ieDstIPv4, ieDstIPv6:
			f.DstAddr = addrFrom(b)
		case ieSrcMaskV4, ieSrcMaskV6:
			f.SrcNetMask = uint8(beUint(b))
		case ieDstMaskV4, ieDstMaskV6:
			f.DstNetMask = uint8(beUint(b))
		case ieIngressInterface:
			f.InIf = uint32(beUint(b))
		case ieEgressInterface:
			f.OutIf = uint32(beUint(b))
		case ieNextHopIPv4, ieNextHopIPv6:
			f.NextHop = addrFrom(b)
		case ieBGPNextHopIPv4:
			bgpNH4 = addrFrom(b)
		case ieBGPNextHopIPv6:
			bgpNH6 = addrFrom(b)
		case ieSrcAS:
			f.SrcAS = uint32(beUint(b))
		case ieDstAS:
			f.DstAS = uint32(beUint(b))
		case ieFirstSwitched:
			first, hasFirst = beUint(b), true
		case ieLastSwitched:
			last, hasLast = beUint(b), true
		case ieFlowStartSeconds:
			startS = beUint(b)
		case ieFlowEndSeconds:
			endS = beUint(b)
		case ieFlowStartMilliseconds:
			startMs = beUint(b)
		case ieFlowEndMilliseconds:
			endMs = beUint(b)
		case ieSystemInitTimeMillis:
			sysInit = beUint(b)
		case ieICMPTypeCodeV4, ieICMPTypeCodeV6:
			icmpTC, hasICMPTC = beUint(b), true
		case ieICMPTypeV4, ieICMPTypeV6:
			f.ICMPType, hasICMPSplit = uint8(beUint(b)), true
		case ieICMPCodeV4, ieICMPCodeV6:
			f.ICMPCode, hasICMPSplit = uint8(beUint(b)), true
		case ieSrcVlan:
			f.SrcVlan = uint16(beUint(b))
		case ieDstVlan:
			f.DstVlan = uint16(beUint(b))
		case ieDot1qVlanID:
			dot1q = beUint(b)
		case iePostDot1qVlanID:
			postDot1q = beUint(b)
		case ieIPVersion:
			ipVersion = beUint(b)
		case ieEthernetType:
			f.EType = uint16(beUint(b))
		case ieForwardingStatus:
			f.ForwardingStatus = uint8(beUint(b))
		default:
			s.set(v.Type, beUint(b))
		}
	}

	// volumes: prefer ingress delta counters
	if f.Bytes == 0 {
		f.Bytes = max(postBytes, totBytes)
	}
	if f.Packets == 0 {
		f.Packets = max(postPkts, totP)
	}
	if !f.NextHop.IsValid() || f.NextHop.IsUnspecified() {
		if bgpNH4.IsValid() && !bgpNH4.IsUnspecified() {
			f.NextHop = bgpNH4
		} else if bgpNH6.IsValid() && !bgpNH6.IsUnspecified() {
			f.NextHop = bgpNH6
		}
	}
	if f.SrcVlan == 0 {
		f.SrcVlan = uint16(dot1q)
	}
	if f.DstVlan == 0 {
		f.DstVlan = uint16(postDot1q)
	}
	if f.EType == 0 {
		switch {
		case ipVersion == 4 || f.SrcAddr.Is4():
			f.EType = 0x0800
		case ipVersion == 6 || f.SrcAddr.Is6():
			f.EType = 0x86dd
		}
	}
	if hasICMPTC && !hasICMPSplit {
		f.ICMPType, f.ICMPCode = uint8(icmpTC>>8), uint8(icmpTC)
	}
	fixICMP(f)

	// times
	switch {
	case startMs > 0 || endMs > 0:
		f.TimeFlowStart, f.TimeFlowEnd = time.UnixMilli(int64(startMs)), time.UnixMilli(int64(endMs))
	case startS > 0 || endS > 0:
		f.TimeFlowStart, f.TimeFlowEnd = time.Unix(int64(startS), 0), time.Unix(int64(endS), 0)
	case ctx.version == 9 && (hasFirst || hasLast):
		// sysUpTime-relative milliseconds; uint32 arithmetic handles wrap
		rel := func(ms uint64) time.Time {
			return ctx.exportTime.Add(-time.Duration(int32(ctx.uptimeMs-uint32(ms))) * time.Millisecond)
		}
		f.TimeFlowStart, f.TimeFlowEnd = rel(first), rel(last)
	case ctx.version == 10 && sysInit > 0 && (hasFirst || hasLast):
		f.TimeFlowStart = time.UnixMilli(int64(sysInit + first))
		f.TimeFlowEnd = time.UnixMilli(int64(sysInit + last))
	}
	if f.TimeFlowStart.IsZero() || f.TimeFlowStart.Unix() <= 0 {
		f.TimeFlowStart = ctx.exportTime
	}
	if f.TimeFlowEnd.IsZero() || f.TimeFlowEnd.Unix() <= 0 {
		f.TimeFlowEnd = ctx.exportTime
	}

	// sampling: in-record rate, else the sampler named by the record, else
	// whatever the domain announced
	reported := s.rate()
	if reported == 0 {
		id := anySampler
		if s.hasSampler {
			id = s.samplerID
		}
		reported = ctx.exp.sampler(ctx.version, ctx.domain, id)
	}
	f.SamplingRate = ctx.exp.effectiveRate(reported, c.cfg.DefaultSamplingRate)
	return f, f.SamplingRate
}

func addrFrom(b []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// fixICMP fills ICMP type/code from the destination port, where many
// exporters put type*256+code, when they were not reported separately.
func fixICMP(f *flow.Flow) {
	if f.Proto != 1 && f.Proto != 58 {
		return
	}
	if f.ICMPType == 0 && f.ICMPCode == 0 && f.DstPort != 0 {
		f.ICMPType, f.ICMPCode = uint8(f.DstPort>>8), uint8(f.DstPort)
	}
	f.SrcPort, f.DstPort = 0, 0
}
