package bmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// BGP message types (RFC 4271).
const (
	bgpOpen   = 1
	bgpUpdate = 2

	bgpHeaderLen = 19
)

// Path attribute type codes.
const (
	attrOrigin           = 1
	attrASPath           = 2
	attrNextHop          = 3
	attrCommunities      = 8
	attrMPReach          = 14
	attrMPUnreach        = 15
	attrAS4Path          = 17
	attrLargeCommunities = 32
)

// AS_PATH segment types.
const (
	segSet            = 1
	segSequence       = 2
	segConfedSequence = 3
	segConfedSet      = 4
)

// AFI / SAFI values handled: unicast IPv4 and IPv6.
const (
	afiIPv4     = 1
	afiIPv6     = 2
	safiUnicast = 1
)

// asTrans is AS_TRANS (RFC 6793), the 2-byte placeholder for 4-byte ASNs.
const asTrans = 23456

var errShort = errors.New("truncated")

// LargeCommunity is an RFC 8092 large community.
type LargeCommunity struct{ Global, Local1, Local2 uint32 }

func (c LargeCommunity) String() string { return fmt.Sprintf("%d:%d:%d", c.Global, c.Local1, c.Local2) }

// Attrs are the path attributes kept in the RIB. Slices are shared between
// routes and must not be modified.
type Attrs struct {
	ASPath           []uint32
	Communities      []uint32
	LargeCommunities []LargeCommunity
	NextHop          netip.Addr
}

// OriginAS is the last AS of the path (0 for a locally originated route).
func (a *Attrs) OriginAS() uint32 {
	if len(a.ASPath) == 0 {
		return 0
	}
	return a.ASPath[len(a.ASPath)-1]
}

// update is a decoded BGP UPDATE restricted to unicast IPv4 / IPv6.
type update struct {
	announced []netip.Prefix
	withdrawn []netip.Prefix
	attrs     Attrs
	// hasAttrs: path attributes were present (announcements are valid).
	hasAttrs bool
}

// sessionCaps are the per-peer decoding options learned from the OPEN
// messages of the Peer Up notification.
type sessionCaps struct {
	as4     bool // 4-byte AS numbers in AS_PATH
	addPath map[uint32]bool
}

func addPathKey(afi uint16, safi uint8) uint32 { return uint32(afi)<<8 | uint32(safi) }

func (c *sessionCaps) hasAddPath(afi uint16, safi uint8) bool {
	return c != nil && c.addPath[addPathKey(afi, safi)]
}

// bgpMessage checks the 19-byte BGP header and returns the type and body.
func bgpMessage(b []byte) (typ byte, body []byte, rest []byte, err error) {
	if len(b) < bgpHeaderLen {
		return 0, nil, nil, fmt.Errorf("BGP header: %w", errShort)
	}
	l := int(binary.BigEndian.Uint16(b[16:18]))
	if l < bgpHeaderLen || l > len(b) {
		return 0, nil, nil, fmt.Errorf("BGP message length %d (have %d)", l, len(b))
	}
	return b[18], b[bgpHeaderLen:l], b[l:], nil
}

// openCaps extracts the capabilities of a BGP OPEN body that matter for
// decoding: 4-byte AS (65) and ADD-PATH (69, mode per AFI/SAFI).
type openInfo struct {
	as4     bool
	addPath map[uint32]uint8 // afi<<8|safi → 1 receive, 2 send, 3 both
}

func parseOpen(body []byte) (openInfo, error) {
	var oi openInfo
	if len(body) < 10 {
		return oi, fmt.Errorf("OPEN: %w", errShort)
	}
	optLen := int(body[9])
	opts := body[10:]
	// RFC 9072 extended optional parameters length.
	ext := false
	if optLen == 255 && len(opts) >= 3 && opts[0] == 255 {
		optLen = int(binary.BigEndian.Uint16(opts[1:3]))
		opts = opts[3:]
		ext = true
	}
	if optLen > len(opts) {
		return oi, fmt.Errorf("OPEN optional parameters: %w", errShort)
	}
	opts = opts[:optLen]
	for len(opts) > 0 {
		hl := 2
		if ext {
			hl = 3
		}
		if len(opts) < hl {
			return oi, fmt.Errorf("OPEN parameter: %w", errShort)
		}
		ptype := opts[0]
		plen := int(opts[1])
		if ext {
			plen = int(binary.BigEndian.Uint16(opts[1:3]))
		}
		if hl+plen > len(opts) {
			return oi, fmt.Errorf("OPEN parameter: %w", errShort)
		}
		val := opts[hl : hl+plen]
		opts = opts[hl+plen:]
		if ptype != 2 { // capabilities
			continue
		}
		for len(val) >= 2 {
			code, clen := val[0], int(val[1])
			if 2+clen > len(val) {
				return oi, fmt.Errorf("OPEN capability: %w", errShort)
			}
			cv := val[2 : 2+clen]
			val = val[2+clen:]
			switch code {
			case 65:
				oi.as4 = true
			case 69:
				for len(cv) >= 4 {
					if oi.addPath == nil {
						oi.addPath = map[uint32]uint8{}
					}
					afi := binary.BigEndian.Uint16(cv[0:2])
					oi.addPath[addPathKey(afi, cv[2])] = cv[3]
					cv = cv[4:]
				}
			}
		}
	}
	return oi, nil
}

// capsFromOpens combines the OPEN sent by the monitored router (local) and
// the one received from the peer (remote): UPDATEs from the peer carry path
// identifiers when the peer may send them and the router receives them.
func capsFromOpens(sent, received openInfo) *sessionCaps {
	c := &sessionCaps{as4: sent.as4 && received.as4}
	for k, rmode := range received.addPath {
		if rmode&2 != 0 && sent.addPath[k]&1 != 0 {
			if c.addPath == nil {
				c.addPath = map[uint32]bool{}
			}
			c.addPath[k] = true
		}
	}
	return c
}

// parseUpdate decodes an UPDATE body. as4 selects the AS_PATH encoding.
func parseUpdate(body []byte, as4 bool, caps *sessionCaps) (*update, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("UPDATE: %w", errShort)
	}
	u := &update{}
	wl := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+wl+2 > len(body) {
		return nil, fmt.Errorf("UPDATE withdrawn routes: %w", errShort)
	}
	var err error
	if u.withdrawn, err = parseNLRI(body[2:2+wl], afiIPv4, caps.hasAddPath(afiIPv4, safiUnicast), u.withdrawn); err != nil {
		return nil, fmt.Errorf("UPDATE withdrawn routes: %w", err)
	}
	p := body[2+wl:]
	al := int(binary.BigEndian.Uint16(p[0:2]))
	if 2+al > len(p) {
		return nil, fmt.Errorf("UPDATE path attributes: %w", errShort)
	}
	attrs := p[2 : 2+al]
	nlri := p[2+al:]
	if err := u.parseAttrs(attrs, as4, caps); err != nil {
		return nil, err
	}
	if len(nlri) > 0 {
		if u.announced, err = parseNLRI(nlri, afiIPv4, caps.hasAddPath(afiIPv4, safiUnicast), u.announced); err != nil {
			return nil, fmt.Errorf("UPDATE NLRI: %w", err)
		}
	}
	return u, nil
}

func (u *update) parseAttrs(b []byte, as4 bool, caps *sessionCaps) error {
	var as4Path []uint32
	sawAS4 := false
	for len(b) > 0 {
		if len(b) < 3 {
			return fmt.Errorf("path attribute header: %w", errShort)
		}
		flags, code := b[0], b[1]
		hl, l := 3, int(b[2])
		if flags&0x10 != 0 { // extended length
			if len(b) < 4 {
				return fmt.Errorf("path attribute header: %w", errShort)
			}
			hl, l = 4, int(binary.BigEndian.Uint16(b[2:4]))
		}
		if hl+l > len(b) {
			return fmt.Errorf("path attribute %d: %w", code, errShort)
		}
		v := b[hl : hl+l]
		b = b[hl+l:]
		u.hasAttrs = true
		var err error
		switch code {
		case attrASPath:
			u.attrs.ASPath, err = parseASPath(v, as4)
		case attrAS4Path:
			as4Path, err = parseASPath(v, true)
			sawAS4 = true
		case attrNextHop:
			if len(v) == 4 {
				u.attrs.NextHop = netip.AddrFrom4([4]byte(v))
			}
		case attrCommunities:
			if len(v)%4 != 0 {
				err = errors.New("COMMUNITIES length")
				break
			}
			cs := make([]uint32, len(v)/4)
			for i := range cs {
				cs[i] = binary.BigEndian.Uint32(v[i*4:])
			}
			u.attrs.Communities = cs
		case attrLargeCommunities:
			if len(v)%12 != 0 {
				err = errors.New("LARGE_COMMUNITY length")
				break
			}
			ls := make([]LargeCommunity, len(v)/12)
			for i := range ls {
				o := v[i*12:]
				ls[i] = LargeCommunity{binary.BigEndian.Uint32(o), binary.BigEndian.Uint32(o[4:]), binary.BigEndian.Uint32(o[8:])}
			}
			u.attrs.LargeCommunities = ls
		case attrMPReach:
			err = u.parseMPReach(v, caps)
		case attrMPUnreach:
			err = u.parseMPUnreach(v, caps)
		}
		if err != nil {
			return fmt.Errorf("path attribute %d: %w", code, err)
		}
	}
	// RFC 6793 §4.2.3: merge AS4_PATH into a 2-byte AS_PATH.
	if !as4 && sawAS4 && len(as4Path) <= len(u.attrs.ASPath) {
		merged := make([]uint32, 0, len(u.attrs.ASPath))
		merged = append(merged, u.attrs.ASPath[:len(u.attrs.ASPath)-len(as4Path)]...)
		u.attrs.ASPath = append(merged, as4Path...)
	}
	return nil
}

// parseASPath flattens AS_SEQUENCE and AS_SET segments into one list;
// confederation segments are skipped (they are local to the confederation).
func parseASPath(b []byte, as4 bool) ([]uint32, error) {
	size := 2
	if as4 {
		size = 4
	}
	var out []uint32
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errShort
		}
		typ, n := b[0], int(b[1])
		if 2+n*size > len(b) {
			return nil, errShort
		}
		seg := b[2 : 2+n*size]
		b = b[2+n*size:]
		if typ == segConfedSequence || typ == segConfedSet {
			continue
		}
		if typ != segSequence && typ != segSet {
			return nil, fmt.Errorf("AS_PATH segment type %d", typ)
		}
		for i := 0; i < n; i++ {
			if as4 {
				out = append(out, binary.BigEndian.Uint32(seg[i*4:]))
			} else {
				out = append(out, uint32(binary.BigEndian.Uint16(seg[i*2:])))
			}
		}
	}
	return out, nil
}

func (u *update) parseMPReach(v []byte, caps *sessionCaps) error {
	if len(v) < 5 {
		return errShort
	}
	afi, safi := binary.BigEndian.Uint16(v[0:2]), v[2]
	nhl := int(v[3])
	if 4+nhl+1 > len(v) {
		return errShort
	}
	nh := v[4 : 4+nhl]
	nlri := v[4+nhl+1:] // one reserved byte
	if safi != safiUnicast || (afi != afiIPv4 && afi != afiIPv6) {
		return nil
	}
	switch nhl {
	case 4:
		u.attrs.NextHop = netip.AddrFrom4([4]byte(nh))
	case 16, 32: // global, or global + link-local
		u.attrs.NextHop = netip.AddrFrom16([16]byte(nh[:16])).Unmap()
	}
	var err error
	u.announced, err = parseNLRI(nlri, afi, caps.hasAddPath(afi, safi), u.announced)
	return err
}

func (u *update) parseMPUnreach(v []byte, caps *sessionCaps) error {
	if len(v) < 3 {
		return errShort
	}
	afi, safi := binary.BigEndian.Uint16(v[0:2]), v[2]
	if safi != safiUnicast || (afi != afiIPv4 && afi != afiIPv6) {
		return nil
	}
	var err error
	u.withdrawn, err = parseNLRI(v[3:], afi, caps.hasAddPath(afi, safi), u.withdrawn)
	return err
}

// parseNLRI decodes length-prefixed prefixes (RFC 4271 §4.3, RFC 4760),
// with 4-byte path identifiers when ADD-PATH is in use (RFC 7911).
func parseNLRI(b []byte, afi uint16, addPath bool, out []netip.Prefix) ([]netip.Prefix, error) {
	maxBits := 32
	if afi == afiIPv6 {
		maxBits = 128
	}
	for len(b) > 0 {
		if addPath {
			if len(b) < 4 {
				return out, errShort
			}
			b = b[4:]
		}
		if len(b) < 1 {
			return out, errShort
		}
		bits := int(b[0])
		if bits > maxBits {
			return out, fmt.Errorf("prefix length %d", bits)
		}
		n := (bits + 7) / 8
		if 1+n > len(b) {
			return out, errShort
		}
		var p netip.Prefix
		if afi == afiIPv6 {
			var a [16]byte
			copy(a[:], b[1:1+n])
			p = netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked()
		} else {
			var a [4]byte
			copy(a[:], b[1:1+n])
			p = netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
		}
		out = append(out, p)
		b = b[1+n:]
	}
	return out, nil
}
