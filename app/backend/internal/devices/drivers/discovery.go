package drivers

// Discovery finds network devices in a subnet and guesses their platform by
// SSH banner, web interface and SNMP sysObjectID.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type hint struct {
	re  *regexp.Regexp
	key string
}

func hints(pairs ...string) []hint {
	out := make([]hint, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, hint{regexp.MustCompile("(?i)" + pairs[i]), pairs[i+1]})
	}
	return out
}

var (
	sshHints = hints(`ROSSSH`, "mikrotik", `Cisco`, "cisco_ios", `HUAWEI|VRP`, "huawei", `Comware`, "hp_comware",
		`FortiSSH|Fortinet`, "fortigate", `Zyxel|ZyXEL`, "zyxel", `dropbear`, "openwrt",
		`OpenSSH.*(Debian|Ubuntu|Raspbian|FreeBSD)`, "linux", `lancom`, "snmp")
	webHints = hints(`RouterOS|mikrotik`, "mikrotik", `OPNsense`, "opnsense", `pfSense`, "pfsense", `LuCI|OpenWrt`, "openwrt",
		`Keenetic`, "keenetic", `Omada`, "omada", `UniFi|ubnt`, "unifi", `FortiGate|Fortinet`, "fortigate", `Zyxel|ZyXEL`, "zyxel",
		`TP-?Link|Archer|Deco`, "tplink", `iDRAC|Integrated Lights-Out|iLO|XClarity|Redfish`, "redfish", `Aruba|ArubaOS`, "aruba_cx",
		`ProCurve`, "aruba_os", `Netgear`, "netgear", `D-Link`, "dlink", `EdgeOS|EdgeRouter`, "edgeos", `Synology|DiskStation`, "linux",
		`Proxmox`, "linux", `Cisco`, "cisco_ios", `Huawei`, "huawei", `JUNOS|Juniper`, "juniper", `Eltex`, "eltex", `Dell`, "dell_os10")
	snmpHints = map[string]string{"MikroTik": "mikrotik", "Cisco": "cisco_ios", "HP": "aruba_os", "HPE (Comware)": "hp_comware",
		"HPE Aruba": "aruba_cx", "Aruba": "aruba_os", "Dell": "dell_nseries", "Dell (Force10)": "dell_os10", "Juniper": "juniper",
		"Huawei": "huawei", "Zyxel": "zyxel", "TP-Link": "tplink", "Netgear": "netgear", "D-Link": "dlink", "Fortinet": "fortigate",
		"Eltex": "eltex", "Ubiquiti": "edgeos", "Linux (net-snmp)": "linux", "Synology": "linux"}
)

// DiscoveryPorts are probed on every address.
var DiscoveryPorts = []int{22, 80, 443, 8043, 8443}

// MaxDiscoveryAddresses bounds a scan (a /22).
const MaxDiscoveryAddresses = 1024

// Found is one answering address.
type Found struct {
	Host      string            `json:"host"`
	Reachable bool              `json:"reachable"`
	Ports     []int             `json:"ports"`
	Evidence  []string          `json:"evidence"`
	SNMP      map[string]string `json:"snmp"`
	Platforms []string          `json:"platforms"` // best guesses first
	Name      string            `json:"name"`
}

// Prober probes one address (replaceable in tests).
type Prober struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Timeout time.Duration
	// SNMP builds the SNMP client of an address (NewSNMPClient by default).
	SNMP func(t Target, c Credentials) (SNMPClient, error)
	// Ports overrides DiscoveryPorts (tests).
	Ports []int
}

func (p *Prober) dial(ctx context.Context, addr string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial(ctx, "tcp", addr)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
}

// open reports whether a port answers and its banner (SSH).
func (p *Prober) open(ctx context.Context, host string, port int) (bool, string) {
	c, err := p.dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return false, ""
	}
	defer c.Close()
	if port != 22 {
		return true, ""
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := io.ReadAtLeast(c, buf, 1)
	line := strings.SplitN(string(buf[:n]), "\n", 2)[0]
	return true, strings.TrimSpace(line)
}

// web fingerprints the web interface of a port.
func (p *Prober) web(ctx context.Context, host string, port int) string {
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fingerprinting
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return p.dial(ctx, addr) }}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	base := scheme + "://" + net.JoinHostPort(host, fmt.Sprint(port))
	get := func(path string) (*http.Response, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return nil, "", err
		}
		r, err := cl.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4000))
		return r, string(b), nil
	}
	r, body, err := get("/")
	if err != nil {
		return ""
	}
	text := strings.Join([]string{r.Header.Get("Server"), r.Header.Get("WWW-Authenticate"), body}, " ")
	if rr, _, err := get("/auth"); err == nil && rr.Header.Get("X-NDM-Realm") != "" {
		text += " Keenetic"
	}
	if _, b, err := get("/api/info"); err == nil && strings.Contains(b, "omadacId") {
		text += " Omada"
	}
	if _, b, err := get("/redfish/v1"); err == nil && strings.Contains(b, "RedfishVersion") {
		text += " Redfish"
	}
	return text
}

// Probe returns open ports, banners and platform guesses for one address.
func (p *Prober) Probe(ctx context.Context, host, community string) Found {
	ports := p.Ports
	if ports == nil {
		ports = DiscoveryPorts
	}
	type res struct {
		port   int
		ok     bool
		banner string
	}
	results := make([]res, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			ok, b := p.open(ctx, host, port)
			results[i] = res{port, ok, b}
		}(i, port)
	}
	wg.Wait()
	f := Found{Host: host, Ports: []int{}, Evidence: []string{}, Platforms: []string{}}
	open := map[int]bool{}
	score := map[string]int{}
	for _, r := range results {
		if !r.ok {
			continue
		}
		open[r.port] = true
		f.Ports = append(f.Ports, r.port)
		if r.port == 22 && r.banner != "" {
			f.Evidence = append(f.Evidence, r.banner)
			for _, h := range sshHints {
				if h.re.MatchString(r.banner) {
					score[h.key] += 2
				}
			}
		}
	}
	sort.Ints(f.Ports)
	for _, port := range []int{443, 80, 8043, 8443} {
		if !open[port] {
			continue
		}
		text := p.web(ctx, host, port)
		for _, h := range webHints {
			if h.re.MatchString(text) {
				score[h.key] += 3
				f.Evidence = append(f.Evidence, fmt.Sprintf("web:%d %s", port, h.key))
				break
			}
		}
	}
	mk := p.SNMP
	if mk == nil {
		mk = NewSNMPClient
	}
	if cl, err := mk(Target{Host: host, Transport: "snmp", Port: 161, Timeout: time.Second}, Credentials{SNMPVersion: "2c", SNMPCommunity: or(community, "public")}); err == nil {
		got, err := cl.Get(ctx, oidSysDescr, oidSysObjectID, oidSysName)
		cl.Close()
		if err == nil && len(got) > 0 {
			descr := SNMPText(got[oidSysDescr])
			if len(descr) > 200 {
				descr = descr[:200]
			}
			vendor := VendorFromOID(SNMPText(got[oidSysObjectID]))
			f.SNMP = map[string]string{"descr": descr, "vendor": vendor, "name": SNMPText(got[oidSysName])}
			f.Name = f.SNMP["name"]
			if k, ok := snmpHints[vendor]; ok {
				score[k] += 3
			}
			for _, h := range webHints {
				if h.re.MatchString(descr) {
					score[h.key] += 2
					break
				}
			}
		}
	}
	keys := make([]string, 0, len(score))
	for k := range score {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if score[keys[i]] != score[keys[j]] {
			return score[keys[i]] > score[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) == 0 && f.SNMP != nil {
		keys = []string{"snmp"}
	}
	if len(keys) > 4 {
		keys = keys[:4]
	}
	f.Platforms = keys
	if len(f.Evidence) > 6 {
		f.Evidence = f.Evidence[:6]
	}
	f.Reachable = len(f.Ports) > 0 || f.SNMP != nil
	return f
}

// Hosts lists the addresses of a subnet (or one address), at most limit.
func Hosts(target string, limit int) ([]netip.Addr, error) {
	target = strings.TrimSpace(target)
	var pfx netip.Prefix
	if strings.Contains(target, "/") {
		p, err := netip.ParsePrefix(target)
		if err != nil {
			return nil, Errorf("Specify a network such as 192.168.1.0/24")
		}
		pfx = p.Masked()
	} else {
		a, err := netip.ParseAddr(target)
		if err != nil {
			return nil, Errorf("Specify a network such as 192.168.1.0/24")
		}
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	hostBits := pfx.Addr().BitLen() - pfx.Bits()
	if hostBits > 20 || 1<<hostBits > limit {
		return nil, Errorf("The network is too large: no more than %d addresses", limit)
	}
	n := 1 << hostBits
	out := make([]netip.Addr, 0, n)
	a := pfx.Addr()
	for i := 0; i < n; i++ {
		out = append(out, a)
		a = a.Next()
	}
	// The network and broadcast addresses of an IPv4 subnet are not hosts.
	if pfx.Addr().Is4() && n > 2 {
		out = out[1 : n-1]
	}
	return out, nil
}

// Scan probes every address of a subnet (at most /22) with 48 probes at a
// time and returns those that answered.
func (p *Prober) Scan(ctx context.Context, target, community string) ([]Found, error) {
	hosts, err := Hosts(target, MaxDiscoveryAddresses)
	if err != nil {
		return nil, err
	}
	found := make([]Found, len(hosts))
	sem := make(chan struct{}, 48)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() == nil {
				found[i] = p.Probe(ctx, h.String(), community)
			}
		}(i, h)
	}
	wg.Wait()
	out := []Found{}
	for _, f := range found {
		if f.Reachable {
			out = append(out, f)
		}
	}
	return out, ctx.Err()
}
