package flowlogs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// Cloud flow logs have no exporter address. Each log source (AWS ENI or VPC,
// Azure NIC, GCP VM or subnet) gets a synthetic exporter address in
// fd75:666c::/32 so that the exporter columns, the exporters page and the
// detector work as for routers:
//
//	fd75:666c | kind (1 byte) | length (1 byte) | payload (10 bytes)
//
// AWS ENI / VPC ids (up to 17 hex digits) and Azure MACs are encoded in
// the payload, so any process can name them back (ExporterName); other
// sources use a hash of their name, which only the receiving process knows
// (role all), other processes show the address.
var Prefix = netip.MustParsePrefix("fd75:666c::/32")

const (
	kindAWSENI   = 1
	kindAWSVPC   = 2
	kindAzureMAC = 3
	kindHash     = 4
)

func synthetic(kind, length byte, payload []byte) netip.Addr {
	var b [16]byte
	copy(b[:4], Prefix.Addr().AsSlice()[:4])
	b[4], b[5] = kind, length
	copy(b[16-len(payload):], payload)
	return netip.AddrFrom16(b)
}

// awsAddr encodes "eni-0123…" / "vpc-0123…".
func awsAddr(id string) (netip.Addr, bool) {
	var kind byte
	switch {
	case strings.HasPrefix(id, "eni-"):
		kind = kindAWSENI
	case strings.HasPrefix(id, "vpc-"):
		kind = kindAWSVPC
	default:
		return netip.Addr{}, false
	}
	h := id[4:]
	if len(h) == 0 || len(h) > 17 {
		return netip.Addr{}, false
	}
	padded := h
	if len(padded)%2 == 1 {
		padded = "0" + padded
	}
	raw, err := hex.DecodeString(padded)
	if err != nil {
		return netip.Addr{}, false
	}
	return synthetic(kind, byte(len(h)), raw), true
}

// macAddr encodes an Azure MAC ("000D3AF87856" or "00-0D-3A-F8-78-56").
func macAddr(mac string) (netip.Addr, string, bool) {
	m := strings.ToUpper(strings.NewReplacer("-", "", ":", "").Replace(mac))
	raw, err := hex.DecodeString(m)
	if err != nil || len(raw) != 6 {
		return netip.Addr{}, "", false
	}
	return synthetic(kindAzureMAC, 6, raw), m, true
}

func hashAddr(name string) netip.Addr {
	sum := sha256.Sum256([]byte(name))
	return synthetic(kindHash, 0, sum[:10])
}

// decode names an address encoding an id.
func decode(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !Prefix.Contains(a) {
		return "", false
	}
	b := a.As16()
	switch b[4] {
	case kindAWSENI, kindAWSVPC:
		n := int(b[5])
		if n == 0 || n > 17 {
			return "", false
		}
		h := hex.EncodeToString(b[6:])
		p := "eni-"
		if b[4] == kindAWSVPC {
			p = "vpc-"
		}
		return p + h[len(h)-n:], true
	case kindAzureMAC:
		return fmt.Sprintf("mac-%X", b[10:]), true
	}
	return "", false
}

// names remembers the full names of the exporters seen by this process
// (e.g. "vpc-…/eni-…", GCP "project/vm").
var names = struct {
	sync.RWMutex
	m map[netip.Addr]string
}{m: map[netip.Addr]string{}}

const maxNames = 100_000

func remember(a netip.Addr, name string) {
	names.RLock()
	cur, ok := names.m[a]
	names.RUnlock()
	if ok && cur == name {
		return
	}
	names.Lock()
	if len(names.m) >= maxNames {
		clear(names.m)
	}
	names.m[a] = name
	names.Unlock()
}

// ExporterName names a synthetic cloud exporter address: the full name when
// this process received its logs, else the id encoded in the address. It is
// the enrich.Config.ExporterNames hook.
func ExporterName(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !Prefix.Contains(a) {
		return "", false
	}
	names.RLock()
	n, ok := names.m[a]
	names.RUnlock()
	if ok {
		return n, true
	}
	if n, ok := decode(a); ok {
		return n, true
	}
	return a.String(), true
}

// exporter returns the synthetic address of a source and remembers its name.
func exporter(addr netip.Addr, name string) netip.Addr {
	if name != "" {
		remember(addr, name)
	}
	return addr
}
