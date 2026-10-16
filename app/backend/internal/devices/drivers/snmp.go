package drivers

// SNMP v1 / v2c / v3: the driver of last resort for any switch, router, AP,
// NAS or printer with standard MIBs (SNMPv2-MIB, IF-MIB, IP-MIB,
// BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB). Used for consumer TP-Link / Netgear /
// D-Link / ASUS, RouterOS 6 and anything without an API.

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// SNMP OIDs.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"

	oidIPAddrIf    = "1.3.6.1.2.1.4.20.1.2"
	oidIPAddrMask  = "1.3.6.1.2.1.4.20.1.3"
	oidARP         = "1.3.6.1.2.1.4.22.1.2"
	oidFDBPort     = "1.3.6.1.2.1.17.4.3.1.2"
	oidQFDBPort    = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidBridgeIf    = "1.3.6.1.2.1.17.1.4.1.2"
	oidLLDPLocPort = "1.0.8802.1.1.2.1.3.7.1.3"
)

var ifCols = map[string]string{"descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "mtu": "1.3.6.1.2.1.2.2.1.4",
	"speed": "1.3.6.1.2.1.2.2.1.5", "mac": "1.3.6.1.2.1.2.2.1.6", "admin": "1.3.6.1.2.1.2.2.1.7",
	"oper": "1.3.6.1.2.1.2.2.1.8", "in": "1.3.6.1.2.1.2.2.1.10", "out": "1.3.6.1.2.1.2.2.1.16",
	"name": "1.3.6.1.2.1.31.1.1.1.1", "hcin": "1.3.6.1.2.1.31.1.1.1.6", "hcout": "1.3.6.1.2.1.31.1.1.1.10",
	"highspeed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18"}

var lldpRem = map[string]string{"chassis": "1.0.8802.1.1.2.1.4.1.1.5", "port": "1.0.8802.1.1.2.1.4.1.1.7",
	"portdesc": "1.0.8802.1.1.2.1.4.1.1.8", "name": "1.0.8802.1.1.2.1.4.1.1.9", "desc": "1.0.8802.1.1.2.1.4.1.1.10"}

// Enterprises maps a sysObjectID enterprise number to a vendor.
var Enterprises = map[int]string{9: "Cisco", 14988: "MikroTik", 11: "HP", 25506: "HPE (Comware)", 47196: "HPE Aruba",
	14823: "Aruba", 674: "Dell", 6027: "Dell (Force10)", 2636: "Juniper", 2011: "Huawei", 890: "Zyxel", 11863: "TP-Link",
	4526: "Netgear", 171: "D-Link", 41112: "Ubiquiti", 12356: "Fortinet", 35047: "Eltex", 8072: "Linux (net-snmp)",
	6574: "Synology", 30065: "Arista", 1916: "Extreme", 1991: "Brocade", 25053: "Ruckus", 2620: "Check Point",
	25461: "Palo Alto", 12325: "pfSense / FreeBSD", 4413: "Broadcom", 24681: "QNAP", 3955: "Linksys",
	2021: "UC Davis (net-snmp)", 9303: "Pulse", 17713: "Cambium", 10002: "Ubiquiti (UniFi)"}

// VendorFromOID names the vendor of a sysObjectID.
func VendorFromOID(oid string) string {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) > 6 && strings.Join(parts[:6], ".") == "1.3.6.1.4.1" {
		n, err := strconv.Atoi(parts[6])
		if err != nil {
			return ""
		}
		if v, ok := Enterprises[n]; ok {
			return v
		}
		return "enterprise " + parts[6]
	}
	return ""
}

// Var is one SNMP variable (OID without the leading dot).
type Var struct {
	OID   string
	Type  gosnmp.Asn1BER
	Value any
}

// SNMPClient is the SNMP access of the driver (gosnmp, a fake in tests).
type SNMPClient interface {
	Get(ctx context.Context, oids ...string) (map[string]Var, error)
	// Walk returns {index suffix: value} under the subtree.
	Walk(ctx context.Context, oid string) (map[string]Var, error)
	Set(ctx context.Context, v Var) error
	Close()
}

// NewSNMPClient builds the SNMP client of a target (replaceable in tests).
var NewSNMPClient = func(t Target, c Credentials) (SNMPClient, error) { return newGoSNMP(t, c) }

type goSNMP struct {
	g    *gosnmp.GoSNMP
	host string
	conn bool
}

func snmpAuth(s string) (gosnmp.SnmpV3AuthProtocol, bool) {
	p, ok := map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA1": gosnmp.SHA,
		"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}[strings.ToUpper(s)]
	return p, ok
}

func snmpPriv(s string) (gosnmp.SnmpV3PrivProtocol, bool) {
	p, ok := map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES, "AES128": gosnmp.AES,
		"AES192": gosnmp.AES192, "AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C}[strings.ToUpper(s)]
	return p, ok
}

// SNMPAuthProtocols / SNMPPrivProtocols are the accepted v3 protocols.
var (
	SNMPAuthProtocols = []string{"md5", "sha", "sha224", "sha256", "sha384", "sha512"}
	SNMPPrivProtocols = []string{"des", "aes", "aes192", "aes256", "aes192c", "aes256c"}
)

func newGoSNMP(t Target, c Credentials) (*goSNMP, error) {
	port := 161
	if t.Transport == "snmp" && t.Port > 0 {
		port = t.Port
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	g := &gosnmp.GoSNMP{Target: t.Host, Port: uint16(port), Transport: "udp", Timeout: timeout, Retries: 1,
		MaxRepetitions: 40, MaxOids: gosnmp.MaxOids, ExponentialTimeout: false}
	switch c.SNMPVersion {
	case "", "2c", "2":
		g.Version, g.Community = gosnmp.Version2c, or(c.SNMPCommunity, "public")
	case "1":
		g.Version, g.Community = gosnmp.Version1, or(c.SNMPCommunity, "public")
	case "3":
		g.Version, g.SecurityModel, g.ContextName = gosnmp.Version3, gosnmp.UserSecurityModel, c.SNMPContext
		usm := &gosnmp.UsmSecurityParameters{UserName: c.SNMPUser}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if c.SNMPAuthPassword != "" {
			ap, ok := snmpAuth(or(c.SNMPAuthProtocol, "sha"))
			if !ok {
				return nil, Errorf("SNMP: unknown authentication protocol %q", c.SNMPAuthProtocol)
			}
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationProtocol, usm.AuthenticationPassphrase = ap, c.SNMPAuthPassword
			if c.SNMPPrivPassword != "" {
				pp, ok := snmpPriv(or(c.SNMPPrivProtocol, "aes"))
				if !ok {
					return nil, Errorf("SNMP: unknown privacy protocol %q", c.SNMPPrivProtocol)
				}
				g.MsgFlags = gosnmp.AuthPriv
				usm.PrivacyProtocol, usm.PrivacyPassphrase = pp, c.SNMPPrivPassword
			}
		}
		g.SecurityParameters = usm
	default:
		return nil, Errorf("SNMP: unknown version %q", c.SNMPVersion)
	}
	return &goSNMP{g: g, host: t.Host}, nil
}

func (s *goSNMP) connect(ctx context.Context) error {
	s.g.Context = ctx
	if s.conn {
		return nil
	}
	if err := s.g.Connect(); err != nil {
		return Errorf("%s: SNMP: %v", s.host, err)
	}
	s.conn = true
	return nil
}

func toVar(p gosnmp.SnmpPDU) Var {
	return Var{OID: strings.TrimPrefix(p.Name, "."), Type: p.Type, Value: p.Value}
}

func absent(t gosnmp.Asn1BER) bool {
	return t == gosnmp.NoSuchObject || t == gosnmp.NoSuchInstance || t == gosnmp.EndOfMibView || t == gosnmp.Null
}

func (s *goSNMP) Get(ctx context.Context, oids ...string) (map[string]Var, error) {
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	r, err := s.g.Get(oids)
	if err != nil {
		return nil, Errorf("%s: SNMP: %v", s.host, err)
	}
	if r.Error != gosnmp.NoError {
		return nil, Errorf("%s: SNMP: %v", s.host, r.Error)
	}
	out := map[string]Var{}
	for _, p := range r.Variables {
		if !absent(p.Type) {
			v := toVar(p)
			out[v.OID] = v
		}
	}
	return out, nil
}

func (s *goSNMP) Walk(ctx context.Context, oid string) (map[string]Var, error) {
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	out := map[string]Var{}
	prefix := oid + "."
	walk := s.g.BulkWalk
	if s.g.Version == gosnmp.Version1 {
		walk = s.g.Walk
	}
	err := walk("."+oid, func(p gosnmp.SnmpPDU) error {
		if absent(p.Type) {
			return nil
		}
		v := toVar(p)
		if strings.HasPrefix(v.OID, prefix) {
			out[v.OID[len(prefix):]] = v
		}
		if len(out) >= 20000 {
			return errStopWalk
		}
		return nil
	})
	if err != nil && err != errStopWalk && len(out) == 0 {
		return nil, Errorf("%s: SNMP: %v", s.host, err)
	}
	return out, nil
}

var errStopWalk = fmt.Errorf("stop")

func (s *goSNMP) Set(ctx context.Context, v Var) error {
	if err := s.connect(ctx); err != nil {
		return err
	}
	r, err := s.g.Set([]gosnmp.SnmpPDU{{Name: "." + v.OID, Type: v.Type, Value: v.Value}})
	if err == nil && r.Error != gosnmp.NoError {
		err = fmt.Errorf("%v", r.Error)
	}
	if err != nil {
		return Errorf("%s: SNMP SET: %v (a community / user with write access is required)", s.host, err)
	}
	return nil
}

func (s *goSNMP) Close() {
	if s.conn && s.g.Conn != nil {
		_ = s.g.Conn.Close()
	}
}

// ---- value helpers ----

// SNMPText is a variable as text (hex when an octet string is not printable).
func SNMPText(v Var) string {
	switch x := v.Value.(type) {
	case nil:
		return ""
	case []byte:
		if utf8.Valid(x) {
			s := strings.TrimRight(string(x), "\x00")
			printable := true
			for _, r := range s {
				if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
					printable = false
					break
				}
			}
			if printable {
				return s
			}
		}
		return hex.EncodeToString(x)
	case string:
		return strings.TrimPrefix(x, ".")
	}
	return fmt.Sprint(v.Value)
}

// SNMPMAC reads a 6-byte octet string (or a textual MAC).
func SNMPMAC(v Var) string {
	if b, ok := v.Value.([]byte); ok && len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return NormMAC(SNMPText(v))
}

// SNMPInt reads a numeric variable.
func SNMPInt(v Var) *int64 {
	if v.Value == nil {
		return nil
	}
	if _, ok := v.Value.([]byte); ok {
		return IntP(SNMPText(v))
	}
	n := gosnmp.ToBigInt(v.Value)
	if n == nil || !n.IsInt64() {
		if n != nil && n.Cmp(big.NewInt(0)) > 0 {
			x := int64(^uint64(0) >> 1)
			return &x
		}
		return nil
	}
	x := n.Int64()
	return &x
}

func snmpUint(v Var) *uint64 {
	if v.Value == nil {
		return nil
	}
	n := gosnmp.ToBigInt(v.Value)
	if n == nil || n.Sign() < 0 || !n.IsUint64() {
		return nil
	}
	x := n.Uint64()
	return &x
}

// ---- driver ----

// SNMPCaps are the actions of the SNMP driver.
var SNMPCaps = []string{ActionHostname, ActionInterface}

// SNMPDriver reads the standard MIBs.
type SNMPDriver struct {
	base
	cl  SNMPClient
	err error
}

// NewSNMP returns the driver.
func NewSNMP(t Target, c Credentials, vendor string) *SNMPDriver {
	cl, err := NewSNMPClient(t, c)
	return &SNMPDriver{base: base{t, c, vendor}, cl: cl, err: err}
}

func (d *SNMPDriver) walk(ctx context.Context, oid string) map[string]Var {
	m, _ := d.cl.Walk(ctx, oid)
	if m == nil {
		return map[string]Var{}
	}
	return m
}

// Collect implements Driver.
func (d *SNMPDriver) Collect(ctx context.Context) (*Snapshot, error) {
	if d.err != nil {
		return nil, d.err
	}
	s, err := d.cl.Get(ctx, oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName)
	if err != nil {
		return nil, err
	}
	descr := SNMPText(s[oidSysDescr])
	oid := SNMPText(s[oidSysObjectID])
	model := strings.SplitN(descr, "\n", 2)[0]
	if len(model) > 120 {
		model = model[:120]
	}
	sd := descr
	if len(sd) > 500 {
		sd = sd[:500]
	}
	f := Facts{Hostname: SNMPText(s[oidSysName]), Vendor: or(d.vendor, VendorFromOID(oid)), Model: model, OS: "SNMP",
		Extra: map[string]any{"sysObjectID": oid, "sysDescr": sd}}
	if t := SNMPInt(s[oidSysUpTime]); t != nil {
		f.UptimeSeconds = P(*t / 100)
	}
	cols := map[string]map[string]Var{}
	for k, o := range ifCols {
		cols[k] = d.walk(ctx, o)
	}
	addrs := map[string][]string{}
	ipIf, ipMask := d.walk(ctx, oidIPAddrIf), d.walk(ctx, oidIPAddrMask)
	for ip, ifidx := range ipIf {
		bits := 32
		if m, ok := ipMask[ip]; ok {
			bits = MaskBits(SNMPText(m))
		}
		if n := SNMPInt(ifidx); n != nil {
			k := strconv.FormatInt(*n, 10)
			addrs[k] = append(addrs[k], addr(ip, bits))
		}
	}
	names := map[string]string{}
	idxs := make([]string, 0, len(cols["descr"]))
	for idx := range cols["descr"] {
		idxs = append(idxs, idx)
	}
	sortNumeric(idxs)
	snap := &Snapshot{Facts: f}
	for _, idx := range idxs {
		name := SNMPText(cols["descr"][idx])
		if v, ok := cols["name"][idx]; ok && SNMPText(v) != "" {
			name = SNMPText(v)
		}
		names[idx] = name
		i := Interface{Name: name, Index: IntP(idx), Addresses: addrs[idx]}
		if v, ok := cols["alias"][idx]; ok {
			i.Description = SNMPText(v)
		}
		if t := SNMPInt(cols["type"][idx]); t != nil {
			i.Type = strconv.FormatInt(*t, 10)
		}
		if v, ok := cols["mac"][idx]; ok {
			i.MAC = SNMPMAC(v)
		}
		if a := SNMPInt(cols["admin"][idx]); a != nil {
			i.AdminUp = P(*a == 1)
		}
		if o := SNMPInt(cols["oper"][idx]); o != nil {
			i.OperUp = P(*o == 1)
		}
		i.MTU = SNMPInt(cols["mtu"][idx])
		if hs := SNMPInt(cols["highspeed"][idx]); hs != nil && *hs > 0 {
			i.SpeedMbps = hs
		} else if sp := SNMPInt(cols["speed"][idx]); sp != nil && *sp >= 1_000_000 {
			i.SpeedMbps = P(*sp / 1_000_000)
		}
		if v, ok := cols["hcin"][idx]; ok {
			i.RxBytes = snmpUint(v)
		} else {
			i.RxBytes = snmpUint(cols["in"][idx])
		}
		if v, ok := cols["hcout"][idx]; ok {
			i.TxBytes = snmpUint(v)
		} else {
			i.TxBytes = snmpUint(cols["out"][idx])
		}
		snap.Interfaces = append(snap.Interfaces, i)
	}
	for _, i := range snap.Interfaces {
		if i.MAC != "" && i.Type == "6" {
			snap.Facts.MAC = i.MAC
			break
		}
	}

	loc := map[string]string{}
	for k, v := range d.walk(ctx, oidLLDPLocPort) {
		loc[k] = SNMPText(v)
	}
	rem := map[string]map[string]Var{}
	for k, o := range lldpRem {
		rem[k] = d.walk(ctx, o)
	}
	keys := make([]string, 0, len(rem["name"]))
	for k := range rem["name"] {
		keys = append(keys, k)
	}
	sortNumeric(keys)
	for _, key := range keys { // timemark.localPort.index
		parts := strings.Split(key, ".")
		local := ""
		if len(parts) >= 3 {
			local = or(loc[parts[1]], parts[1])
		}
		n := Neighbor{LocalInterface: local, RemoteName: SNMPText(rem["name"][key]), Protocol: "lldp"}
		if v, ok := rem["chassis"][key]; ok {
			n.RemoteMAC = SNMPMAC(v)
		}
		if v, ok := rem["port"][key]; ok {
			n.RemoteInterface = SNMPText(v)
		}
		if v, ok := rem["desc"][key]; ok {
			n.RemotePlatform = SNMPText(v)
			if len(n.RemotePlatform) > 120 {
				n.RemotePlatform = n.RemotePlatform[:120]
			}
		}
		snap.Neighbors = append(snap.Neighbors, n)
	}
	arp := d.walk(ctx, oidARP)
	akeys := make([]string, 0, len(arp))
	for k := range arp {
		akeys = append(akeys, k)
	}
	sortNumeric(akeys)
	for _, key := range akeys { // ifIndex.a.b.c.d
		parts := strings.Split(key, ".")
		if mac := SNMPMAC(arp[key]); len(parts) == 5 && mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(strings.Join(parts[1:], ".")),
				Interface: names[parts[0]], Source: SourceARP})
		}
	}
	bridgeIf := map[string]string{}
	for k, v := range d.walk(ctx, oidBridgeIf) {
		if n := SNMPInt(v); n != nil {
			bridgeIf[k] = strconv.FormatInt(*n, 10)
		}
	}
	uplinks := map[string]bool{}
	for _, n := range snap.Neighbors {
		uplinks[n.LocalInterface] = true
	}
	fdb := d.walk(ctx, oidQFDBPort)
	if len(fdb) == 0 {
		fdb = d.walk(ctx, oidFDBPort)
	}
	fkeys := make([]string, 0, len(fdb))
	for k := range fdb {
		fkeys = append(fkeys, k)
	}
	sortNumeric(fkeys)
	for _, key := range fkeys { // [vlan.]m1.m2.m3.m4.m5.m6
		parts := strings.Split(key, ".")
		if len(parts) < 6 {
			continue
		}
		var b [6]int
		ok := true
		for i, x := range parts[len(parts)-6:] {
			n, err := strconv.Atoi(x)
			if err != nil || n < 0 || n > 255 {
				ok = false
				break
			}
			b[i] = n
		}
		if !ok {
			continue
		}
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
		var vlan *int64
		if len(parts) == 7 {
			vlan = IntP(parts[0])
		}
		port := SNMPInt(fdb[key])
		if port == nil || *port == 0 {
			continue
		}
		iface := names[bridgeIf[strconv.FormatInt(*port, 10)]]
		if iface != "" && !uplinks[iface] {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, Interface: iface, VLAN: vlan, Source: SourceBridge})
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *SNMPDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	if d.err != nil {
		return "", d.err
	}
	vendor := or(d.vendor, "SNMP")
	switch {
	case action == ActionHostname:
		if err := d.cl.Set(ctx, Var{OID: oidSysName, Type: gosnmp.OctetString, Value: p.Name}); err != nil {
			return "", err
		}
		return "Done", nil
	case action == ActionInterface && p.Enabled != nil:
		idx := ""
		for _, col := range []string{ifCols["name"], ifCols["descr"]} {
			for k, v := range d.walk(ctx, col) {
				if SNMPText(v) == p.Name {
					idx = k
				}
			}
			if idx != "" {
				break
			}
		}
		if idx == "" {
			return "", Errorf("Interface %s not found", p.Name)
		}
		state := 2
		if *p.Enabled {
			state = 1
		}
		if err := d.cl.Set(ctx, Var{OID: ifCols["admin"] + "." + idx, Type: gosnmp.Integer, Value: state}); err != nil {
			return "", err
		}
		if p.Description != nil {
			if err := d.cl.Set(ctx, Var{OID: ifCols["alias"] + "." + idx, Type: gosnmp.OctetString, Value: *p.Description}); err != nil {
				return "", err
			}
		}
		return "Done", nil
	}
	return "", Unsupported(vendor, action)
}

// Close implements Driver.
func (d *SNMPDriver) Close() {
	if d.cl != nil {
		d.cl.Close()
	}
}

// sortNumeric sorts dotted numeric keys numerically.
func sortNumeric(keys []string) {
	less := func(a, b string) bool {
		pa, pb := strings.Split(a, "."), strings.Split(b, ".")
		for i := 0; i < len(pa) && i < len(pb); i++ {
			x, ex := strconv.ParseInt(pa[i], 10, 64)
			y, ey := strconv.ParseInt(pb[i], 10, 64)
			if ex != nil || ey != nil {
				if pa[i] != pb[i] {
					return pa[i] < pb[i]
				}
				continue
			}
			if x != y {
				return x < y
			}
		}
		return len(pa) < len(pb)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && less(keys[j], keys[j-1]); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}
