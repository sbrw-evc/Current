package bmp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Route distinguishers (RFC 4364 §4.2) are kept as their 8 wire bytes in a
// uint64; 0 is the global routing table.

// FormatRD returns the usual text of a route distinguisher: "65000:100"
// (type 0, 2-byte ASN), "192.0.2.1:100" (type 1) or "4200000000:100"
// (type 2, 4-byte ASN). Unknown types are printed as "type:hex".
func FormatRD(rd uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], rd)
	switch binary.BigEndian.Uint16(b[0:2]) {
	case 0:
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(b[2:4]), binary.BigEndian.Uint32(b[4:8]))
	case 1:
		return fmt.Sprintf("%s:%d", netip.AddrFrom4([4]byte(b[2:6])), binary.BigEndian.Uint16(b[6:8]))
	case 2:
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(b[2:6]), binary.BigEndian.Uint16(b[6:8]))
	}
	return fmt.Sprintf("%d:%x", binary.BigEndian.Uint16(b[0:2]), b[2:])
}

// ParseRD parses the text of a route distinguisher as written in Ledger
// VRFs ("65000:100", "192.0.2.1:100", "4200000000:100"). An ASN that
// fits in 2 bytes gives type 0, a larger one type 2.
func ParseRD(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return 0, fmt.Errorf("route distinguisher %q: want admin:number", s)
	}
	admin, num := s[:i], s[i+1:]
	var b [8]byte
	if a, err := netip.ParseAddr(admin); err == nil {
		n, err := strconv.ParseUint(num, 10, 16)
		if err != nil || !a.Is4() {
			return 0, fmt.Errorf("route distinguisher %q: want IPv4:0-65535", s)
		}
		binary.BigEndian.PutUint16(b[0:2], 1)
		a4 := a.As4()
		copy(b[2:6], a4[:])
		binary.BigEndian.PutUint16(b[6:8], uint16(n))
		return binary.BigEndian.Uint64(b[:]), nil
	}
	asn, err := strconv.ParseUint(admin, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("route distinguisher %q: bad administrator", s)
	}
	if asn <= 0xffff {
		n, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("route distinguisher %q: want ASN:0-4294967295", s)
		}
		binary.BigEndian.PutUint16(b[2:4], uint16(asn))
		binary.BigEndian.PutUint32(b[4:8], uint32(n))
		return binary.BigEndian.Uint64(b[:]), nil
	}
	n, err := strconv.ParseUint(num, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("route distinguisher %q: want 4-byte ASN:0-65535", s)
	}
	binary.BigEndian.PutUint16(b[0:2], 2)
	binary.BigEndian.PutUint32(b[2:6], uint32(asn))
	binary.BigEndian.PutUint16(b[6:8], uint16(n))
	return binary.BigEndian.Uint64(b[:]), nil
}
