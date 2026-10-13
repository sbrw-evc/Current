package bmp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// BMP message types (RFC 7854 §4.1).
const (
	MsgRouteMonitoring = 0
	MsgStatistics      = 1
	MsgPeerDown        = 2
	MsgPeerUp          = 3
	MsgInitiation      = 4
	MsgTermination     = 5
	MsgRouteMirroring  = 6

	bmpVersion       = 3
	commonHeaderLen  = 6
	perPeerHeaderLen = 42
)

// Peer types (RFC 7854 §4.2, RFC 9069).
const (
	peerGlobal = 0
	peerRD     = 1
	peerLocal  = 2
	peerLocRIB = 3
)

// Per-peer header flags.
const (
	flagV = 0x80 // IPv6 peer address
	flagL = 0x40 // post-policy Adj-RIB-In
	flagA = 0x20 // legacy 2-byte AS_PATH
	flagO = 0x10 // Adj-RIB-Out (RFC 8671)
)

var msgNames = map[byte]string{
	MsgRouteMonitoring: "route_monitoring", MsgStatistics: "statistics", MsgPeerDown: "peer_down",
	MsgPeerUp: "peer_up", MsgInitiation: "initiation", MsgTermination: "termination", MsgRouteMirroring: "route_mirroring",
}

func msgName(t byte) string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return "unknown"
}

// peerHeader is the RFC 7854 §4.2 per-peer header.
type peerHeader struct {
	typ   byte
	flags byte
	rd    uint64
	addr  netip.Addr
	as    uint32
}

func (h peerHeader) post() bool { return h.typ == peerLocRIB || h.flags&flagL != 0 }

// out reports routes advertised to the peer (Adj-RIB-Out, RFC 8671) rather
// than received from it. The O flag is not defined for Loc-RIB peers.
func (h peerHeader) out() bool { return h.typ != peerLocRIB && h.flags&flagO != 0 }

// as4 reports 4-byte AS numbers in AS_PATH (the A flag is clear). The Loc-RIB
// peer type (RFC 9069) always uses 4-byte AS numbers.
func (h peerHeader) as4() bool { return h.typ == peerLocRIB || h.flags&flagA == 0 }

func (h peerHeader) key(router netip.Addr) PeerKey {
	return PeerKey{Router: router, Distinguisher: h.rd, Address: h.addr, AS: h.as, Post: h.post()}
}

func parsePeerHeader(b []byte) (peerHeader, []byte, error) {
	if len(b) < perPeerHeaderLen {
		return peerHeader{}, nil, fmt.Errorf("per-peer header: %w", errShort)
	}
	h := peerHeader{typ: b[0], flags: b[1], rd: binary.BigEndian.Uint64(b[2:10]), as: binary.BigEndian.Uint32(b[26:30])}
	if h.flags&flagV != 0 {
		h.addr = netip.AddrFrom16([16]byte(b[10:26]))
	} else {
		h.addr = netip.AddrFrom4([4]byte(b[22:26]))
	}
	return h, b[perPeerHeaderLen:], nil
}

// parseCommonHeader returns the message type and total length (header included).
func parseCommonHeader(b []byte) (typ byte, length int, err error) {
	if b[0] != bmpVersion {
		return 0, 0, fmt.Errorf("BMP version %d (only 3 is supported)", b[0])
	}
	length = int(binary.BigEndian.Uint32(b[1:5]))
	if length < commonHeaderLen {
		return 0, 0, fmt.Errorf("BMP message length %d", length)
	}
	return b[5], length, nil
}

// parseTLVs reads the information TLVs of Initiation / Peer Up messages.
func parseTLVs(b []byte) map[uint16]string {
	out := map[uint16]string{}
	for len(b) >= 4 {
		t, l := binary.BigEndian.Uint16(b[0:2]), int(binary.BigEndian.Uint16(b[2:4]))
		if 4+l > len(b) {
			break
		}
		out[t] = string(b[4 : 4+l])
		b = b[4+l:]
	}
	return out
}

// peerUp decodes the body of a Peer Up notification after the per-peer
// header: the session capabilities from both OPEN messages.
func parsePeerUp(b []byte) (*sessionCaps, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("peer up: %w", errShort)
	}
	b = b[20:] // local address, local port, remote port
	typ, sentBody, rest, err := bgpMessage(b)
	if err != nil || typ != bgpOpen {
		return nil, fmt.Errorf("peer up: sent OPEN: %v", orType(err, typ))
	}
	typ, recvBody, _, err := bgpMessage(rest)
	if err != nil || typ != bgpOpen {
		return nil, fmt.Errorf("peer up: received OPEN: %v", orType(err, typ))
	}
	sent, err := parseOpen(sentBody)
	if err != nil {
		return nil, err
	}
	recv, err := parseOpen(recvBody)
	if err != nil {
		return nil, err
	}
	return capsFromOpens(sent, recv), nil
}

func orType(err error, typ byte) any {
	if err != nil {
		return err
	}
	return fmt.Sprintf("BGP message type %d", typ)
}
