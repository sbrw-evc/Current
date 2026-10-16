package drivers

// Parsers of network OS CLI output (Cisco IOS / IOS-XE / NX-OS, Dell OS10 /
// N-series, HPE Comware, Huawei VRP, ArubaOS-Switch / CX, Zyxel, TP-Link
// JetStream, Eltex). They are deliberately tolerant: vendors and versions
// differ in spacing and wording, so each parser looks for patterns rather
// than exact layouts.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	ipv4Re     = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	ifaceToken = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z\-]*\s?\d[\w/.:\-]*|\d+(?:/\d+)*|[A-Za-z]+\d+[\w/.:\-]*|Po\d+|lag\d+)$`)
	notIface   = map[string]bool{"dynamic": true, "static": true, "learned": true, "arpa": true, "self": true, "cpu": true,
		"management": true, "permanent": true, "delete-on-reset": true, "secure": true, "drop": true, "router": true,
		"sticky": true, "d": true, "s": true, "l": true, "i": true, "igmp": true, "config": true, "mgmt": true}
	durationUnits = map[string]int64{"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}
	durationRe    = regexp.MustCompile(`(?i)(\d+)\s*(year|week|day|hour|minute|second)s?`)
	clockRe       = regexp.MustCompile(`(\d+):(\d{2}):(\d{2})`)
	reCache       sync.Map // pattern → *regexp.Regexp
)

// ParseUptime reads "1 year, 2 weeks, 3 days, 4 hours, 5 minutes" or
// "10 days 3:04:05" as seconds.
func ParseUptime(text string) *int64 {
	if text == "" {
		return nil
	}
	var total int64
	found := false
	for _, m := range durationRe.FindAllStringSubmatch(text, -1) {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		total += n * durationUnits[strings.ToLower(m[2])]
		found = true
	}
	if m := clockRe.FindStringSubmatch(text); m != nil {
		h, _ := strconv.ParseInt(m[1], 10, 64)
		mi, _ := strconv.ParseInt(m[2], 10, 64)
		s, _ := strconv.ParseInt(m[3], 10, 64)
		total += h*3600 + mi*60 + s
		found = true
	}
	if !found {
		return nil
	}
	return &total
}

var routerOSDur = regexp.MustCompile(`(\d+)(ms|w|d|h|m|s)`)

// ParseDuration reads a RouterOS duration ("1w2d03:04:05", "5h3m2s").
func ParseDuration(v string) *int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var total int64
	if loc := clockRe.FindStringSubmatchIndex(v); loc != nil {
		h, _ := strconv.ParseInt(v[loc[2]:loc[3]], 10, 64)
		m, _ := strconv.ParseInt(v[loc[4]:loc[5]], 10, 64)
		s, _ := strconv.ParseInt(v[loc[6]:loc[7]], 10, 64)
		total += h*3600 + m*60 + s
		v = v[:loc[0]]
	}
	units := map[string]int64{"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0}
	for _, m := range routerOSDur.FindAllStringSubmatch(v, -1) {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		total += n * units[m[2]]
	}
	return &total
}

func rx(pattern string) *regexp.Regexp {
	if r, ok := reCache.Load(pattern); ok {
		return r.(*regexp.Regexp)
	}
	r := regexp.MustCompile(pattern)
	reCache.Store(pattern, r)
	return r
}

// first returns group 1 of the first match (case-insensitive, multi-line).
func first(pattern, text string) string { return firstGroup(pattern, text, 1) }

func firstGroup(pattern, text string, group int) string {
	m := rx("(?im)" + pattern).FindStringSubmatch(text)
	if m == nil || len(m) <= group {
		return ""
	}
	return strings.TrimSpace(m[group])
}

func or(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Version are the facts of `show version` / `display version` / `show system`.
type Version struct {
	Hostname, Version, Model, Serial, MAC string
	Uptime                                *int64
}

// ParseVersion reads the facts of the common network OSes.
func ParseVersion(text string) Version {
	v := Version{
		Hostname: or(first(`^(\S+)\s+uptime is`, text), first(`^\s*(?:System Name|Hostname|Host Name|sysname)\s*[:=]\s*(.+)$`, text)),
		Version: or(first(`(?:Cisco IOS.*?|NX-OS.*?|Software)[, ]+Version\s+([^\s,]+)`, text),
			first(`^\s*(?:OS Version|Software Version|Firmware Version|Software revision|ROM Version|Version)\s*[:]\s*(\S+)`, text),
			first(`Version\s+(\d[\w.()\-]*)`, text)),
		Model: or(first(`^\s*(?:Model number|Model Number|Model Name|Product Name|Model|System Type|Device Type|Hardware)\s*[:]\s*(.+)$`, text),
			first(`^cisco\s+(\S+).*processor`, text), first(`^(?:HPE?|H3C|HUAWEI)\s+(\S+(?:\s\S+)?)\s+uptime is`, text)),
		Serial: first(`^\s*(?:System serial number|Serial Number|Serial No|Serial-Number|Processor board ID|Device serial number|Chassis Serial Number)\s*[:]?\s*(\S+)`, text),
		MAC:    NormMAC(first(`(?:Base (?:ethernet )?MAC (?:Address|Addr)|MAC Address|System MAC)\s*[:]\s*(\S+)`, text)),
	}
	up := or(first(`uptime is\s+(.+)$`, text), first(`^\s*(?:Up\s?Time|System Up Time|Uptime)\s*[:]\s*(.+)$`, text))
	v.Uptime = ParseUptime(up)
	return v
}

// splitBefore splits text at the start of every match of re (Python's
// re.split with a look-ahead).
func splitBefore(text string, re *regexp.Regexp) []string {
	locs := re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return []string{text}
	}
	var out []string
	prev := 0
	for _, l := range locs {
		if l[0] > prev {
			out = append(out, text[prev:l[0]])
		}
		prev = l[0]
	}
	return append(out, text[prev:])
}

var (
	ifBlockRe = regexp.MustCompile(`(?m)^\S+ is (?:administratively down|up|down|deleted|disabled)`)
	ifHeadRe  = regexp.MustCompile(`^(\S+) is (administratively down|up|down|disabled)(?:.*?line protocol is (\w+))?`)
	inetRe    = regexp.MustCompile(`Internet address is (\S+)`)
)

func atoi(s string) int64 {
	n, _ := ToInt(s)
	return n
}

// ParseShowInterfaces reads the full `show interface(s)` of IOS / IOS-XE /
// NX-OS / OS10 / Eltex / Aruba CX.
func ParseShowInterfaces(text string) []Interface {
	var out []Interface
	for _, b := range splitBefore(text, ifBlockRe) {
		head := ifHeadRe.FindStringSubmatch(b)
		if head == nil {
			continue
		}
		name, state, proto := head[1], head[2], head[3]
		adminState := first(`admin state is (\w+)`, b)
		adminUp := state != "administratively down" && strings.ToLower(adminState) != "down" && state != "disabled"
		operUp := or(proto, state) == "up"
		bw := atoi(first(`BW (\d+) Kbit`, b))
		speed := atoi(first(`(\d+)\s*(?:Mb/s|Mbps)`, b))
		if speed == 0 && bw > 0 {
			speed = bw / 1000
		}
		if speed == 0 {
			if g := first(`(\d+)\s*Gb/s`, b); g != "" {
				speed = atoi(g) * 1000
			}
		}
		rxb := or(firstGroup(`(\d+) packets input, (\d+) bytes`, b, 2), firstGroup(`(\d+) input packets\s+(\d+) bytes`, b, 2),
			firstGroup(`Input statistics:\s*\n?\s*(\d+) packets, (\d+) octets`, b, 2))
		txb := or(firstGroup(`(\d+) packets output, (\d+) bytes`, b, 2), firstGroup(`(\d+) output packets\s+(\d+) bytes`, b, 2),
			firstGroup(`Output statistics:\s*\n?\s*(\d+) packets, (\d+) octets`, b, 2))
		addrs := []string{}
		for _, m := range inetRe.FindAllStringSubmatch(b, -1) {
			addrs = append(addrs, m[1])
		}
		it := Interface{Name: name, Description: first(`^\s*Description:\s*(.*)$`, b), Type: first(`Hardware(?: is|:)\s*([^,\n]+)`, b),
			MAC: NormMAC(first(`address(?: is|:)\s*([0-9a-fA-F.:\-]{12,17})`, b)), AdminUp: P(adminUp), OperUp: P(operUp),
			Addresses: addrs}
		if speed > 0 {
			it.SpeedMbps = P(speed)
		}
		if mtu := atoi(first(`MTU (\d+)`, b)); mtu > 0 {
			it.MTU = P(mtu)
		}
		if rxb != "" {
			it.RxBytes = UintP(rxb)
		}
		if txb != "" {
			it.TxBytes = UintP(txb)
		}
		out = append(out, it)
	}
	return out
}

var (
	statusWords = []string{"up", "down", "connected", "notconnect", "notconnected", "disabled", "err-disabled", "*down", "adm",
		"admdown", "inactive", "yes", "no", "sfp-absent"}
	adminDownWords = []string{"disabled", "*down", "adm", "admdown", "administratively"}
	speedTokenRe   = regexp.MustCompile(`^(?:a-)?(\d+)(g|m)?(?:\(a\))?(?:fdx|hdx|-full|-half|bps|mbps)?$`)
	knownSpeeds    = map[int64]bool{10: true, 100: true, 1000: true, 2500: true, 5000: true, 10000: true, 25000: true, 40000: true,
		50000: true, 100000: true}
)

func hasAny(list []string, words []string) bool {
	for _, w := range words {
		for _, t := range list {
			if t == w {
				return true
			}
		}
	}
	return false
}

// ParseStatusTable reads brief tables: `show interfaces status`, `display
// interface brief`, `show interface brief`, `show interfaces brief`. The
// first token of a row is the port; state words anywhere in the row give the
// admin / oper state; a speed token (1000, 1G, 10G(a), a-1000, 1000FDx)
// gives the speed.
func ParseStatusTable(text string) []Interface {
	var out []Interface
	for _, line := range strings.Split(text, "\n") {
		tokens := strings.Fields(strings.ReplaceAll(line, "|", " "))
		if len(tokens) < 2 || !ifaceToken.MatchString(tokens[0]) {
			continue
		}
		if l := strings.ToLower(tokens[0]); l == "port" || l == "interface" {
			continue
		}
		low := make([]string, 0, len(tokens)-1)
		for _, t := range tokens[1:] {
			low = append(low, strings.ToLower(t))
		}
		if !hasAny(low, statusWords) {
			continue
		}
		adminUp := !hasAny(low, adminDownWords)
		operUp := hasAny(low, []string{"up", "connected"}) && adminUp
		it := Interface{Name: tokens[0], AdminUp: P(adminUp), OperUp: P(operUp), Addresses: []string{}}
		for _, t := range low {
			m := speedTokenRe.FindStringSubmatch(t)
			if m == nil {
				continue
			}
			n := atoi(m[1])
			if m[2] == "g" {
				n *= 1000
			}
			if knownSpeeds[n] {
				it.SpeedMbps = P(n)
				break
			}
		}
		out = append(out, it)
	}
	return out
}

var cdpSepRe = regexp.MustCompile(`(?m)^-{5,}\s*$`)

// ParseCDPDetail reads `show cdp neighbors detail`.
func ParseCDPDetail(text string) []Neighbor {
	var out []Neighbor
	for _, b := range cdpSepRe.Split(text, -1) {
		name := first(`Device ID:\s*(\S+)`, b)
		local := first(`Interface:\s*([^,\n]+),`, b)
		if name == "" || local == "" {
			continue
		}
		name, _, _ = strings.Cut(name, "(")
		out = append(out, Neighbor{LocalInterface: strings.TrimSpace(local), RemoteName: name,
			RemoteIP:        NormIP(first(`(?:IP(?:v4)? [Aa]ddress|IP address):\s*(\S+)`, b)),
			RemoteInterface: first(`Port ID \(outgoing port\):\s*(\S+)`, b),
			RemotePlatform:  first(`Platform:\s*([^,\n]+)`, b), Protocol: "cdp"})
	}
	return out
}

var lldpBlockRe = regexp.MustCompile(`(?mi)^\s*(?:-{5,}|Local Intf:|Local Port id:|Local Port\s*:|LLDP neighbor-information of port|` +
	`Interface\s+\S+ has \d+ neighbou?r|Port\s*:\s*\S+\s*$|Local Interface\s*:)`)

// ParseLLDPDetail reads `show lldp neighbors detail` (IOS, NX-OS, OS10,
// Eltex), `display lldp neighbor-information` (Comware, VRP), `show lldp
// neighbor-info detail` (Aruba CX), `show lldp info remote-device <port>`
// (ArubaOS-Switch).
func ParseLLDPDetail(text string) []Neighbor {
	var out []Neighbor
	for _, b := range splitBefore(text, lldpBlockRe) {
		local := or(first(`^\s*(?:Local Intf|Local Port id|Local Port|Local Interface)\s*:\s*(\S+)`, b),
			first(`LLDP neighbor-information of port \d+\[(\S+)\]`, b), first(`Interface\s+(\S+) has \d+ neighbou?r`, b),
			first(`^\s*Port\s*:\s*(\S+)\s*$`, b))
		chassis := first(`Chassis (?:id|ID)\s*:\s*(\S+)`, b)
		sysname := first(`(?:System Name|SysName|System name|Neighbor System Name)\s*:\s*(.+)$`, b)
		if local == "" || (chassis == "" && sysname == "") {
			continue
		}
		mgmt := first(`(?:Management Address(?:es)?|Mgmt address|Management address)\s*(?:\(\w+\))?\s*:?\s*(?:\n\s*)?(?:IP(?:v4)?\s*:\s*)?(\d{1,3}(?:\.\d{1,3}){3})`, b)
		platform := first(`System Description\s*:\s*(?:\n\s*)?(.+)$`, b)
		if len(platform) > 120 {
			platform = platform[:120]
		}
		out = append(out, Neighbor{LocalInterface: local, RemoteName: strings.Trim(sysname, `"`), RemoteMAC: NormMAC(chassis),
			RemoteIP: NormIP(mgmt), Protocol: "lldp", RemoteInterface: first(`^\s*Port (?:id|ID)\s*:\s*(\S+)`, b),
			RemotePlatform: platform})
	}
	return out
}

// col is a header label and the field it fills.
type col struct{ label, field string }

// ParseColumns reads a fixed-width table: it finds the header row holding the
// labels and slices the rows by the header positions.
func ParseColumns(text string, columns []col) []map[string]string {
	lines := strings.Split(text, "\n")
	need := max(2, len(columns)-1)
	for idx, line := range lines {
		low := strings.ToLower(line)
		type hit struct {
			pos   int
			label string
			field string
		}
		var found []hit
		for _, c := range columns {
			if p := strings.Index(low, strings.ToLower(c.label)); p >= 0 {
				found = append(found, hit{p, c.label, c.field})
			}
		}
		if len(found) < need {
			continue
		}
		sort.Slice(found, func(i, j int) bool {
			if found[i].pos != found[j].pos {
				return found[i].pos < found[j].pos
			}
			return found[i].label < found[j].label
		})
		var rows []map[string]string
		for _, row := range lines[idx+1:] {
			tr := strings.TrimSpace(row)
			if tr == "" || strings.Trim(tr, "-+= |") == "" {
				continue
			}
			rec := map[string]string{}
			for i, h := range found {
				end := len(row)
				if i+1 < len(found) && found[i+1].pos < end {
					end = found[i+1].pos
				}
				v := ""
				if len(row) > h.pos && end > h.pos {
					v = strings.Trim(row[h.pos:end], " |")
				}
				rec[h.field] = v
			}
			rows = append(rows, rec)
		}
		return rows
	}
	return nil
}

var lldpTables = [][]col{
	{{"System Name", "name"}, {"Local Interface", "local"}, {"Chassis ID", "chassis"}, {"Port ID", "port"}},
	{{"Local Intf", "local"}, {"Neighbor Dev", "name"}, {"Neighbor Intf", "port"}},
	{{"LocalPort", "local"}, {"ChassisId", "chassis"}, {"PortId", "port"}, {"SysName", "name"}},
	{{"Local Port", "local"}, {"Device ID", "name"}, {"Port ID", "port"}},
	{{"Port", "local"}, {"Device ID", "chassis"}, {"Port ID", "port"}, {"System Name", "name"}},
	{{"Local Port", "local"}, {"Chassis ID", "chassis"}, {"Port ID", "port"}, {"System Name", "name"}},
}

// ParseLLDPTable reads short LLDP tables (Comware list, VRP brief,
// ArubaOS-Switch remote-device, JetStream, Zyxel, Eltex).
func ParseLLDPTable(text string) []Neighbor {
	for _, cols := range lldpTables {
		rows := ParseColumns(text, cols)
		if len(rows) == 0 {
			continue
		}
		var out []Neighbor
		for _, r := range rows {
			if r["local"] == "" || (r["name"] == "" && r["chassis"] == "") {
				continue
			}
			out = append(out, Neighbor{LocalInterface: r["local"], RemoteName: r["name"], RemoteMAC: NormMAC(r["chassis"]),
				RemoteInterface: r["port"], Protocol: "lldp"})
		}
		return out
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func ifaceTokens(tokens []string, skip map[string]bool) []string {
	var out []string
	for _, t := range tokens {
		if skip[t] || notIface[strings.ToLower(t)] || !ifaceToken.MatchString(t) || ipv4Re.MatchString(t) || NormMAC(t) != "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ParseARP reads any ARP table: a row with an IPv4 address and a MAC; the
// interface is the last interface-like token.
func ParseARP(text string) []Endpoint {
	var out []Endpoint
	for _, line := range strings.Split(text, "\n") {
		tokens := strings.Fields(line)
		ip, mac := "", ""
		for _, t := range tokens {
			if ip == "" && ipv4Re.MatchString(t) {
				ip = t
			}
			if mac == "" {
				mac = NormMAC(t)
			}
		}
		if ip == "" || mac == "" || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
			continue
		}
		var ifs []string
		for _, t := range ifaceTokens(tokens, map[string]bool{ip: true}) {
			if !isDigits(t) || strings.Contains(t, "/") {
				ifs = append(ifs, t)
			}
		}
		e := Endpoint{MAC: mac, IP: NormIP(ip), Source: SourceARP}
		if len(ifs) > 0 {
			e.Interface = ifs[len(ifs)-1]
		}
		out = append(out, e)
	}
	return out
}

// ParseMACTable reads any MAC address table: a row with a MAC, a VLAN number
// and a port. Rows on uplink ports are dropped.
func ParseMACTable(text string, uplinks map[string]bool) []Endpoint {
	up := map[string]bool{}
	for u := range uplinks {
		up[strings.ToLower(u)] = true
	}
	var out []Endpoint
	for _, line := range strings.Split(text, "\n") {
		tokens := strings.Fields(line)
		macTok := ""
		for _, t := range tokens {
			if NormMAC(t) != "" {
				macTok = t
				break
			}
		}
		if macTok == "" {
			continue
		}
		mac := NormMAC(macTok)
		var rest []string
		for _, t := range tokens {
			if t != macTok {
				rest = append(rest, t)
			}
		}
		var vlan *int64
		for _, t := range rest {
			if isDigits(t) {
				if n := atoi(t); n > 0 && n < 4095 {
					vlan = P(n)
					break
				}
			}
		}
		var ports []string
		for _, t := range ifaceTokens(rest, nil) {
			if isDigits(t) && vlan != nil && atoi(t) == *vlan {
				continue
			}
			ports = append(ports, t)
		}
		if len(ports) == 0 {
			continue
		}
		port := ports[len(ports)-1]
		cpu := false
		for _, t := range strings.Fields(strings.ToLower(line)) {
			cpu = cpu || t == "cpu"
		}
		if up[strings.ToLower(port)] || cpu {
			continue
		}
		out = append(out, Endpoint{MAC: mac, Interface: port, VLAN: vlan, Source: SourceBridge})
	}
	return out
}

var shortNames = [][2]string{{"TenGigabitEthernet", "Te"}, {"GigabitEthernet", "Gi"}, {"FastEthernet", "Fa"},
	{"TwentyFiveGigE", "Twe"}, {"HundredGigE", "Hu"}, {"FortyGigabitEthernet", "Fo"}, {"Ethernet", "Eth"},
	{"Port-channel", "Po"}, {"Bridge-Aggregation", "BAGG"}, {"Ten-GigabitEthernet", "XGE"}}

// ShortenIface turns GigabitEthernet1/0/1 into Gi1/0/1, so the same port
// matches across LLDP, CDP and tables.
func ShortenIface(name string) string {
	for _, p := range shortNames {
		if strings.HasPrefix(name, p[0]) {
			return p[1] + name[len(p[0]):]
		}
	}
	return name
}
