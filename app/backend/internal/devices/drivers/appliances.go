package drivers

// Firewalls and home / SMB routers with an HTTP API or a Linux shell:
// OPNsense, pfSense, FortiGate, Keenetic, OpenWrt and generic Linux
// (Debian / Ubuntu / VyOS / EdgeOS / Proxmox / ASUS Merlin / Synology).

import (
	"context"
	"crypto/md5" //nolint:gosec // the Keenetic login protocol is MD5 + SHA-256
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// httpDriver is the shared part of the HTTP API drivers.
type httpDriver struct {
	base
	http *HTTP
}

func (d *httpDriver) Close() { d.http.Close() }

func (d *httpDriver) text(ctx context.Context, path string, query map[string]string) (string, error) {
	var kv []string
	for k, v := range query {
		kv = append(kv, k, v)
	}
	return d.http.Text(ctx, path, q(kv...), 60*time.Second)
}

func addr(ip string, bits int) string { return ip + "/" + strconv.Itoa(bits) }

// ---------------- OPNsense ----------------

// OpnsenseCaps are the actions of OPNsense.
var OpnsenseCaps = []string{ActionFlowExport, ActionReboot, ActionBackup}

// OpnsenseDriver is the OPNsense REST API with an API key / secret
// (System → Access → Users → API keys).
type OpnsenseDriver struct{ httpDriver }

// NewOpnsense returns the driver.
func NewOpnsense(t Target, c Credentials, vendor string) *OpnsenseDriver {
	d := &OpnsenseDriver{httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)}}
	d.http.User, d.http.Pass = or(c.APIKey, c.Username), or(c.APISecret, c.Password)
	return d
}

// Collect implements Driver.
func (d *OpnsenseDriver) Collect(ctx context.Context) (*Snapshot, error) {
	cfg, err := d.http.GetObj(ctx, "/api/diagnostics/interface/getInterfaceConfig", false, nil)
	if err != nil {
		return nil, err
	}
	info, _ := d.http.GetObj(ctx, "/api/diagnostics/system/systemInformation", true, nil)
	tm, _ := d.http.GetObj(ctx, "/api/diagnostics/system/systemTime", true, nil)
	res, _ := d.http.GetObj(ctx, "/api/diagnostics/system/systemResources", true, nil)
	version := ""
	if vs, ok := info["versions"].([]any); ok && len(vs) > 0 {
		if parts := strings.SplitN(Str(vs[0]), " ", 3); len(parts) > 1 {
			version = parts[1]
		}
	}
	mem := O(res, "memory")
	total, _ := ToInt(mem["total"])
	used, _ := ToInt(mem["used"])
	snap := &Snapshot{Facts: Facts{Hostname: strings.Split(Str(info["name"]), ".")[0], Vendor: "Deciso", Model: "OPNsense",
		OS: "OPNsense", Version: version, UptimeSeconds: ParseUptime(Str(tm["uptime"])),
		MemoryPercent: Percent(float64(used), float64(total))}}
	names, _ := d.http.GetObj(ctx, "/api/diagnostics/interface/getInterfaceNames", true, nil)
	traffic, _ := d.http.GetObj(ctx, "/api/diagnostics/traffic/interface", true, nil)
	byDev := map[string]Obj{}
	for _, v := range O(traffic, "interfaces") {
		if m, ok := v.(map[string]any); ok {
			byDev[Str(m["device"])] = m
		}
	}
	devs := make([]string, 0, len(cfg))
	for k := range cfg {
		devs = append(devs, k)
	}
	sort.Strings(devs)
	for _, dev := range devs {
		c, ok := cfg[dev].(map[string]any)
		if !ok {
			continue
		}
		t := byDev[dev]
		flags := map[string]bool{}
		if fl, ok := c["flags"].([]any); ok {
			for _, f := range fl {
				flags[Str(f)] = true
			}
		}
		status := Str(c["status"])
		var addrs []string
		for _, a := range L(c["ipv4"]) {
			if ip := Str(a["ipaddr"]); ip != "" {
				addrs = append(addrs, ip+"/"+Str(a["subnetbits"]))
			}
		}
		i := Interface{Name: dev, Description: or(Str(names[dev]), Str(t["name"])), MAC: NormMAC(Str(c["macaddr"])),
			AdminUp: P(flags["up"]), OperUp: P((status == "" || status == "active" || status == "associated") && flags["up"]),
			MTU: IntP(c["mtu"]), Addresses: addrs}
		if t != nil {
			i.RxBytes, i.TxBytes = UintP(t["bytes received"]), UintP(t["bytes transmitted"])
		}
		snap.Interfaces = append(snap.Interfaces, i)
	}
	arp, _ := d.http.Get(ctx, "/api/diagnostics/interface/getArp", true, nil)
	for _, a := range L(arp) {
		if mac := NormMAC(Str(a["mac"])); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(a["ip"])), Hostname: Str(a["hostname"]),
				Interface: Str(a["intf"]), Source: SourceARP})
		}
	}
	for _, path := range []string{"/api/dhcpv4/leases/searchLease", "/api/kea/leases4/search", "/api/dnsmasq/leases/search"} {
		r, _ := d.http.GetObj(ctx, path, true, nil)
		for _, l := range L(r["rows"]) {
			if mac := NormMAC(S(l, "mac", "hwaddr")); mac != "" {
				snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(l["address"])), Hostname: Str(l["hostname"]),
					Interface: S(l, "if_descr", "if"), Source: SourceDHCP})
			}
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *OpnsenseDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	switch action {
	case ActionReboot:
		if _, err := d.http.Send(ctx, http.MethodPost, "/api/core/system/reboot", Obj{}, 0); err != nil {
			return "", err
		}
		return "Reboot started", nil
	case ActionFlowExport:
		if p.Protocol == "sflow" {
			return "", Unsupported("OPNsense", "flow_export (sflow)")
		}
		traffic, _ := d.http.GetObj(ctx, "/api/diagnostics/traffic/interface", true, nil)
		var names []string
		for k := range O(traffic, "interfaces") {
			names = append(names, k)
		}
		sort.Strings(names)
		ifaces := strings.Join(names, ",")
		if ifaces == "" {
			ifaces = "lan,wan"
		}
		version := map[string]string{"netflow5": "v5", "netflow9": "v9", "ipfix": "v9"}[p.Protocol]
		on := p.IsEnabled(true)
		capture := Obj{"interfaces": "", "egress_only": "", "version": version, "targets": ""}
		if on {
			capture["interfaces"], capture["targets"] = ifaces, fmt.Sprintf("%s:%d", p.Collector, p.Port)
		}
		if _, err := d.http.Send(ctx, http.MethodPost, "/api/diagnostics/netflow/setconfig", Obj{"netflow": Obj{"capture": capture}}, 0); err != nil {
			return "", err
		}
		if _, err := d.http.Send(ctx, http.MethodPost, "/api/diagnostics/netflow/reconfigure", Obj{}, 0); err != nil {
			return "", err
		}
		return fmt.Sprintf("NetFlow %s on interfaces %s", map[bool]string{true: "enabled", false: "disabled"}[on], ifaces), nil
	}
	return "", Unsupported("OPNsense", action)
}

// Backup implements Driver.
func (d *OpnsenseDriver) Backup(ctx context.Context) (string, error) {
	return d.text(ctx, "/api/core/backup/download/this", nil)
}

// ---------------- pfSense ----------------

// PfsenseCaps are the actions of pfSense.
var PfsenseCaps = []string{ActionHostname, ActionDNS, ActionReboot, ActionCommand, ActionBackup}

// PfsenseDriver is pfSense with the pfSense-pkg-RESTAPI package (v2): an
// API key in X-API-Key or a user and password.
type PfsenseDriver struct{ httpDriver }

// NewPfsense returns the driver.
func NewPfsense(t Target, c Credentials, vendor string) *PfsenseDriver {
	d := &PfsenseDriver{httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)}}
	if c.APIKey != "" {
		d.http.Header.Set("X-API-Key", c.APIKey)
	} else {
		d.http.User, d.http.Pass = c.Username, c.Password
	}
	return d
}

func (d *PfsenseDriver) data(ctx context.Context, path string, optional bool) (any, error) {
	v, err := d.http.Get(ctx, path, optional, nil)
	if m, ok := v.(map[string]any); ok {
		return m["data"], err
	}
	return v, err
}

// Collect implements Driver.
func (d *PfsenseDriver) Collect(ctx context.Context) (*Snapshot, error) {
	ifaces, err := d.data(ctx, "/api/v2/status/interfaces", false)
	if err != nil {
		return nil, err
	}
	stv, _ := d.data(ctx, "/api/v2/status/system", true)
	verv, _ := d.data(ctx, "/api/v2/system/version", true)
	hostv, _ := d.data(ctx, "/api/v2/system/hostname", true)
	st, ver, host := asObj(stv), asObj(verv), asObj(hostv)
	f := Facts{Hostname: Str(host["hostname"]), Vendor: "Netgate", Model: or(Str(st["platform"]), "pfSense"), OS: "pfSense",
		Version: Str(ver["version"]), Serial: Str(st["serial"]), UptimeSeconds: ParseUptime(Str(st["uptime"]))}
	if st["cpu_usage"] != nil {
		f.CPUPercent = floatP(st["cpu_usage"])
	}
	if st["mem_usage"] != nil {
		f.MemoryPercent = floatP(st["mem_usage"])
	}
	snap := &Snapshot{Facts: f}
	for _, i := range L(ifaces) {
		var addrs []string
		if ip := Str(i["ipaddr"]); ip != "" {
			addrs = []string{ip + "/" + or(Str(i["subnet"]), "32")}
		}
		enabled := true
		if v, ok := i["enable"]; ok {
			enabled = ToBool(v)
		}
		status := Str(i["status"])
		snap.Interfaces = append(snap.Interfaces, Interface{Name: S(i, "hwif", "name"), Description: Str(i["descr"]),
			MAC: NormMAC(Str(i["macaddr"])), AdminUp: P(enabled), OperUp: P(status == "up" || status == "associated"),
			Addresses: addrs, RxBytes: UintP(i["inbytes"]), TxBytes: UintP(i["outbytes"])})
	}
	arp, _ := d.data(ctx, "/api/v2/diagnostics/arp_table", true)
	for _, a := range L(arp) {
		if mac := NormMAC(Str(a["mac_address"])); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(a["ip_address"])), Hostname: Str(a["hostname"]),
				Interface: Str(a["interface"]), Source: SourceARP})
		}
	}
	leases, _ := d.data(ctx, "/api/v2/status/dhcp_server/leases", true)
	for _, l := range L(leases) {
		if mac := NormMAC(Str(l["mac"])); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(l["ip"])), Hostname: Str(l["hostname"]),
				Interface: Str(l["if"]), Source: SourceDHCP})
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *PfsenseDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	var err error
	switch action {
	case ActionHostname:
		_, err = d.http.Send(ctx, http.MethodPatch, "/api/v2/system/hostname", Obj{"hostname": p.Name}, 0)
	case ActionDNS:
		_, err = d.http.Send(ctx, http.MethodPatch, "/api/v2/system/dns", Obj{"dnsserver": p.Servers}, 0)
	case ActionReboot:
		_, _ = d.http.Send(ctx, http.MethodPost, "/api/v2/diagnostics/reboot", Obj{}, 10*time.Second)
		return "Reboot started", nil
	case ActionCommand:
		r, err := d.http.Send(ctx, http.MethodPost, "/api/v2/diagnostics/command_prompt", Obj{"command": p.Command}, 120*time.Second)
		if err != nil {
			return "", err
		}
		if m, ok := r.(map[string]any); ok {
			return Str(O(m, "data")["output"]), nil
		}
		return Str(r), nil
	default:
		return "", Unsupported("pfSense", action)
	}
	if err != nil {
		return "", err
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *PfsenseDriver) Backup(ctx context.Context) (string, error) {
	return d.Apply(ctx, ActionCommand, Params{Command: "cat /cf/conf/config.xml"})
}

func asObj(v any) Obj {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return Obj{}
}

func floatP(v any) *float64 {
	switch x := v.(type) {
	case float64:
		return &x
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return &f
		}
	}
	return nil
}

// ---------------- FortiGate ----------------

// FortigateCaps are the actions of FortiOS.
var FortigateCaps = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionFlowExport, ActionReboot, ActionBackup}

// FortigateDriver is the Fortinet FortiGate (FortiOS 6.4+) REST API with a
// REST API administrator token.
type FortigateDriver struct{ httpDriver }

// NewFortigate returns the driver.
func NewFortigate(t Target, c Credentials, vendor string) *FortigateDriver {
	d := &FortigateDriver{httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)}}
	d.http.Header.Set("Authorization", "Bearer "+c.APIKey)
	return d
}

func (d *FortigateDriver) results(ctx context.Context, path string, optional bool) (any, error) {
	r, err := d.http.GetObj(ctx, path, optional, nil)
	return r["results"], err
}

// Collect implements Driver.
func (d *FortigateDriver) Collect(ctx context.Context) (*Snapshot, error) {
	st, err := d.http.GetObj(ctx, "/api/v2/monitor/system/status", false, nil)
	if err != nil {
		return nil, err
	}
	res := O(st, "results")
	perfv, _ := d.results(ctx, "/api/v2/monitor/system/performance/status", true)
	perf := asObj(perfv)
	mem := O(perf, "mem")
	used, _ := ToInt(mem["used"])
	total, _ := ToInt(mem["total"])
	snap := &Snapshot{Facts: Facts{Hostname: Str(res["hostname"]), Vendor: "Fortinet", Model: S(res, "model_name", "model"),
		OS: "FortiOS", Version: Str(st["version"]), Serial: Str(st["serial"]), UptimeSeconds: IntP(perf["uptime"]),
		MemoryPercent: Percent(float64(used), float64(total))}}
	ifv, err := d.results(ctx, "/api/v2/monitor/system/interface", false)
	if err != nil {
		return nil, err
	}
	ifs := asObj(ifv)
	names := make([]string, 0, len(ifs))
	for k := range ifs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		i := asObj(ifs[name])
		var addrs []string
		if ip := Str(i["ip"]); ip != "" && ip != "0.0.0.0" {
			addrs = []string{addr(ip, MaskBits(or(Str(i["mask"]), "32")))}
		}
		speed := IntP(i["speed"])
		if speed != nil && *speed == 0 {
			speed = nil
		}
		snap.Interfaces = append(snap.Interfaces, Interface{Name: name, Description: Str(i["alias"]), MAC: NormMAC(Str(i["mac"])),
			OperUp: P(ToBool(i["link"])), SpeedMbps: speed, Addresses: addrs, RxBytes: UintP(i["rx_bytes"]), TxBytes: UintP(i["tx_bytes"])})
	}
	lldp, _ := d.results(ctx, "/api/v2/monitor/network/lldp/neighbors", true)
	for _, n := range L(lldp) {
		ip := ""
		if as := L(n["addresses"]); len(as) > 0 {
			ip = NormIP(Str(as[0]["address"]))
		}
		snap.Neighbors = append(snap.Neighbors, Neighbor{LocalInterface: Str(n["port_name"]), RemoteName: Str(n["system_name"]),
			RemoteMAC: NormMAC(Str(n["chassis_id"])), RemoteInterface: Str(n["port_id"]), RemoteIP: ip, Protocol: "lldp"})
	}
	arp, _ := d.results(ctx, "/api/v2/monitor/network/arp", true)
	for _, a := range L(arp) {
		if mac := NormMAC(Str(a["mac"])); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(a["ip"])), Interface: Str(a["interface"]), Source: SourceARP})
		}
	}
	dhcp, _ := d.results(ctx, "/api/v2/monitor/system/dhcp", true)
	for _, l := range L(dhcp) {
		if mac := NormMAC(Str(l["mac"])); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(l["ip"])), Hostname: Str(l["hostname"]),
				Interface: Str(l["interface"]), Source: SourceDHCP})
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *FortigateDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	var err error
	put := func(path string, body any) error { _, e := d.http.Send(ctx, http.MethodPut, path, body, 0); return e }
	switch action {
	case ActionHostname:
		err = put("/api/v2/cmdb/system/global", Obj{"hostname": p.Name})
	case ActionInterface:
		body := Obj{}
		if p.Enabled != nil {
			body["status"] = map[bool]string{true: "up", false: "down"}[*p.Enabled]
		}
		if p.Description != nil {
			body["description"] = *p.Description
		}
		err = put("/api/v2/cmdb/system/interface/"+urlPath(p.Name), body)
	case ActionDNS:
		sec := ""
		if len(p.Servers) > 1 {
			sec = p.Servers[1]
		}
		err = put("/api/v2/cmdb/system/dns", Obj{"primary": p.Servers[0], "secondary": sec})
	case ActionNTP:
		var srv []Obj
		for i, s := range p.Servers {
			srv = append(srv, Obj{"id": i + 1, "server": s})
		}
		err = put("/api/v2/cmdb/system/ntp", Obj{"ntpsync": "enable", "type": "custom", "ntpserver": srv})
	case ActionFlowExport:
		path := "/api/v2/cmdb/system/netflow"
		if p.Protocol == "sflow" {
			path = "/api/v2/cmdb/system/sflow"
		}
		if !p.IsEnabled(true) {
			err = put(path, Obj{"collectors": []any{}})
		} else if e := put(path, Obj{"collectors": []Obj{{"id": 1, "collector-ip": p.Collector, "collector-port": p.Port}}}); e != nil {
			err = put(path, Obj{"collector-ip": p.Collector, "collector-port": p.Port})
		}
		if err != nil {
			return "", err
		}
		return "Collector set; enable netflow-sampler / sflow-sampler on the interfaces you need", nil
	case ActionReboot:
		_, _ = d.http.Send(ctx, http.MethodPost, "/api/v2/monitor/system/os/reboot", Obj{"event_log_message": "Current"}, 10*time.Second)
		return "Reboot started", nil
	default:
		return "", Unsupported("FortiGate", action)
	}
	if err != nil {
		return "", err
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *FortigateDriver) Backup(ctx context.Context) (string, error) {
	return d.text(ctx, "/api/v2/monitor/system/config/backup", map[string]string{"scope": "global"})
}

func urlPath(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "/", "%2F"), " ", "%20")
}

// ---------------- Keenetic ----------------

// KeeneticCaps are the actions of KeeneticOS.
var KeeneticCaps = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionReboot, ActionEndpointBlock,
	ActionCommand, ActionBackup}

// KeeneticDriver is Keenetic (KeeneticOS 3.x / 4.x) RCI over the web
// interface; CLI commands are sent as {"parse": ...}.
type KeeneticDriver struct {
	httpDriver
	logged bool
}

// NewKeenetic returns the driver (plain HTTP by default).
func NewKeenetic(t Target, c Credentials, vendor string) *KeeneticDriver {
	scheme := "https"
	if t.Transport == "" || t.Transport == "http" {
		scheme = "http"
	}
	return &KeeneticDriver{httpDriver: httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, scheme, 0)}}
}

// KeeneticPassword is the answer to the NDM challenge:
// sha256(challenge + md5(login:realm:password)).
func KeeneticPassword(login, realm, password, challenge string) string {
	m := md5.Sum([]byte(login + ":" + realm + ":" + password)) //nolint:gosec // protocol
	s := sha256.Sum256([]byte(challenge + hex.EncodeToString(m[:])))
	return hex.EncodeToString(s[:])
}

func (d *KeeneticDriver) login(ctx context.Context) error {
	if d.logged {
		return nil
	}
	_, hdr, err := d.http.Do(ctx, http.MethodGet, "/auth", nil, nil, 0)
	if err == nil {
		d.logged = true
		return nil
	}
	if hdr == nil {
		return d.http.Error(err)
	}
	realm, challenge := hdr.Get("X-NDM-Realm"), hdr.Get("X-NDM-Challenge")
	if challenge == "" {
		return Errorf("%s: this is not a Keenetic web interface", d.t.Host)
	}
	_, _, err = d.http.Do(ctx, http.MethodPost, "/auth", nil,
		Obj{"login": d.c.Username, "password": KeeneticPassword(d.c.Username, realm, d.c.Password, challenge)}, 0)
	if err != nil {
		return Errorf("%s: Keenetic: wrong login or password", d.t.Host)
	}
	d.logged = true
	return nil
}

func (d *KeeneticDriver) rci(ctx context.Context, path string, optional bool) (any, error) {
	if err := d.login(ctx); err != nil {
		return nil, err
	}
	return d.http.Get(ctx, "/rci/"+path, optional, nil)
}

func (d *KeeneticDriver) parse(ctx context.Context, commands ...string) ([]any, error) {
	if err := d.login(ctx); err != nil {
		return nil, err
	}
	body := make([]Obj, 0, len(commands))
	for _, c := range commands {
		body = append(body, Obj{"parse": c})
	}
	r, err := d.http.Send(ctx, http.MethodPost, "/rci/", body, 60*time.Second)
	if err != nil {
		return nil, err
	}
	out, ok := r.([]any)
	if !ok {
		out = []any{r}
	}
	for _, item := range out {
		for _, st := range L(O(asObj(item), "parse")["status"]) {
			if Str(st["status"]) == "error" {
				return nil, Errorf("Keenetic: %s", Str(st["message"]))
			}
		}
	}
	return out, nil
}

// Collect implements Driver.
func (d *KeeneticDriver) Collect(ctx context.Context) (*Snapshot, error) {
	verv, err := d.rci(ctx, "show/version", false)
	if err != nil {
		return nil, err
	}
	ver := asObj(verv)
	sysv, _ := d.rci(ctx, "show/system", true)
	sys := asObj(sysv)
	used, total, _ := strings.Cut(Str(sys["memory"]), "/")
	u, _ := ToInt(used)
	t, _ := ToInt(total)
	f := Facts{Hostname: Str(sys["hostname"]), Vendor: "Keenetic", Model: S(ver, "model", "device"), OS: "KeeneticOS",
		Version: S(ver, "release", "title"), Serial: Str(ver["serial"]), UptimeSeconds: IntP(sys["uptime"]),
		MemoryPercent: Percent(float64(u), float64(t))}
	if sys["cpuload"] != nil {
		if n, ok := ToInt(sys["cpuload"]); ok {
			f.CPUPercent = P(float64(n))
		}
	}
	snap := &Snapshot{Facts: f}
	ifv, err := d.rci(ctx, "show/interface", false)
	if err != nil {
		return nil, err
	}
	ifs := asObj(ifv)
	names := make([]string, 0, len(ifs))
	for k := range ifs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		i, ok := ifs[name].(map[string]any)
		if !ok {
			continue
		}
		var addrs []string
		if a := Str(i["address"]); a != "" {
			addrs = []string{addr(a, MaskBits(or(Str(i["mask"]), "32")))}
		}
		state := or(Str(i["state"]), "up")
		snap.Interfaces = append(snap.Interfaces, Interface{Name: or(Str(i["id"]), name), Description: Str(i["description"]),
			Type: Str(i["type"]), MAC: NormMAC(Str(i["mac"])), AdminUp: P(state == "up"),
			OperUp: P(Str(i["link"]) == "up" || Str(i["connected"]) == "yes"), MTU: IntP(i["mtu"]), Addresses: addrs})
	}
	hs, _ := d.rci(ctx, "show/ip/hotspot", true)
	for _, h := range L(asObj(hs)["host"]) {
		mac := NormMAC(Str(h["mac"]))
		if mac == "" {
			continue
		}
		src := SourceDHCP
		if Str(h["ssid"]) != "" {
			src = SourceWiFi
		}
		e := Endpoint{MAC: mac, IP: NormIP(Str(h["ip"])), Hostname: S(h, "name", "hostname"), Interface: Str(O(h, "interface")["id"]),
			Source: src, SSID: Str(h["ssid"]), Signal: IntP(h["rssi"]), Blocked: or(Str(h["access"]), "permit") == "deny"}
		snap.Endpoints = append(snap.Endpoints, e)
	}
	return snap, nil
}

// Apply implements Driver.
func (d *KeeneticDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	var cmds []string
	switch action {
	case ActionHostname:
		cmds = []string{"system name " + p.Name}
	case ActionInterface:
		if p.Enabled != nil {
			cmds = append(cmds, fmt.Sprintf("interface %s %s", p.Name, map[bool]string{true: "up", false: "down"}[*p.Enabled]))
		}
		if p.Description != nil {
			cmds = append(cmds, fmt.Sprintf("interface %s description %s", p.Name, quote(*p.Description)))
		}
	case ActionDNS:
		for _, s := range p.Servers {
			cmds = append(cmds, "ip name-server "+s)
		}
	case ActionNTP:
		for _, s := range p.Servers {
			cmds = append(cmds, "ntp server "+s)
		}
	case ActionReboot:
		_, _ = d.parse(ctx, "system reboot")
		return "Reboot started", nil
	case ActionEndpointBlock:
		cmds = []string{fmt.Sprintf("ip hotspot host %s %s", p.MAC, map[bool]string{true: "deny", false: "permit"}[p.IsBlocked()])}
	case ActionCommand:
		out, err := d.parse(ctx, p.Command)
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(out, "", " ")
		return string(b), nil
	default:
		return "", Unsupported("Keenetic", action)
	}
	if _, err := d.parse(ctx, append(cmds, "system configuration save")...); err != nil {
		return "", err
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *KeeneticDriver) Backup(ctx context.Context) (string, error) {
	out, err := d.parse(ctx, "show running-config")
	if err != nil {
		return "", err
	}
	if len(out) > 0 {
		if msg, ok := O(asObj(out[0]), "parse")["message"].([]any); ok {
			lines := make([]string, 0, len(msg))
			for _, m := range msg {
				lines = append(lines, Str(m))
			}
			return strings.Join(lines, "\n"), nil
		}
	}
	b, _ := json.MarshalIndent(out, "", " ")
	return string(b), nil
}

// ---------------- Linux / OpenWrt over SSH ----------------

// LinuxScript collects everything in one exec.
const LinuxScript = `echo '#HOST'; hostname; echo '#OS'; cat /etc/os-release 2>/dev/null; cat /etc/openwrt_release 2>/dev/null
echo '#UPTIME'; cat /proc/uptime; echo '#MODEL'; cat /tmp/sysinfo/model 2>/dev/null || cat /sys/class/dmi/id/product_name 2>/dev/null
echo '#MEM'; grep -E '^(MemTotal|MemAvailable|MemFree):' /proc/meminfo; echo '#LOAD'; cat /proc/loadavg; nproc 2>/dev/null
echo '#LINK'; ip -o link 2>/dev/null; echo '#ADDR'; ip -o -4 addr 2>/dev/null; echo '#DEV'; cat /proc/net/dev
echo '#SPEED'; for f in /sys/class/net/*/speed; do echo "$f $(cat $f 2>/dev/null)"; done
echo '#ARP'; cat /proc/net/arp; echo '#LEASES'; cat /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases 2>/dev/null
echo '#LLDP'; lldpcli -f json show neighbors 2>/dev/null`

var sectionRe = regexp.MustCompile(`^#[A-Z]+$`)

// SplitSections splits the script output by its #SECTION markers.
func SplitSections(text string) map[string]string {
	out := map[string][]string{}
	cur := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if t := strings.TrimSpace(line); sectionRe.MatchString(t) {
			cur = t[1:]
			out[cur] = []string{}
		} else if cur != "" {
			out[cur] = append(out[cur], line)
		}
	}
	res := make(map[string]string, len(out))
	for k, v := range out {
		res[k] = strings.Join(v, "\n")
	}
	return res
}

var (
	linuxKVRe    = regexp.MustCompile(`(?m)^(\w+)=["']?(.*?)["']?$`)
	linuxMemRe   = regexp.MustCompile(`(?m)^(\w+):\s+(\d+)`)
	linuxSpeedRe = regexp.MustCompile(`/sys/class/net/([^/\s]+)/speed (-?\d+)`)
	linuxAddrRe  = regexp.MustCompile(`(?m)^\d+:\s+(\S+)\s+inet\s+(\S+)`)
	linuxLinkRe  = regexp.MustCompile(`(?m)^\d+:\s+([^:@\s]+)(?:@\S+)?:\s+<([^>]*)>.*?mtu (\d+)(?:.*?link/\w+\s+([0-9a-f:]{17}))?`)
)

// ParseLinux reads the output of LinuxScript.
func ParseLinux(text string) *Snapshot {
	s := SplitSections(text)
	osr := map[string]string{}
	for _, m := range linuxKVRe.FindAllStringSubmatch(s["OS"], -1) {
		osr[m[1]] = m[2]
	}
	mem := map[string]int64{}
	for _, m := range linuxMemRe.FindAllStringSubmatch(s["MEM"], -1) {
		mem[m[1]] = atoi(m[2])
	}
	total := mem["MemTotal"]
	avail := mem["MemAvailable"]
	if avail == 0 {
		avail = mem["MemFree"]
	}
	f := Facts{Hostname: strings.TrimSpace(s["HOST"]), OS: or(osr["DISTRIB_ID"], osr["NAME"], "Linux"),
		Version: or(osr["DISTRIB_RELEASE"], osr["VERSION_ID"]), Model: strings.TrimSpace(s["MODEL"]),
		MemoryPercent: Percent(float64(total-avail), float64(total))}
	if up := strings.Fields(s["UPTIME"]); len(up) > 0 {
		if v, err := strconv.ParseFloat(up[0], 64); err == nil {
			f.UptimeSeconds = P(int64(v))
		}
	}
	if load := strings.Fields(s["LOAD"]); len(load) > 0 {
		cpus := int64(1)
		if len(load) > 5 {
			if n, ok := ToInt(load[len(load)-1]); ok && n > 0 {
				cpus = n
			}
		}
		if l, err := strconv.ParseFloat(load[0], 64); err == nil {
			v := l * 100 / float64(cpus)
			if v > 100 {
				v = 100
			}
			f.CPUPercent = P(float64(int64(v*10+0.5)) / 10)
		}
	}
	type ctr struct{ rx, tx uint64 }
	counters := map[string]ctr{}
	var order []string
	devLines := strings.Split(s["DEV"], "\n")
	for i, line := range devLines {
		if i < 2 {
			continue
		}
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v := strings.Fields(rest)
		if len(v) >= 9 {
			rx, _ := strconv.ParseUint(v[0], 10, 64)
			tx, _ := strconv.ParseUint(v[8], 10, 64)
			n := strings.TrimSpace(name)
			counters[n] = ctr{rx, tx}
			order = append(order, n)
		}
	}
	speeds := map[string]int64{}
	for _, m := range linuxSpeedRe.FindAllStringSubmatch(s["SPEED"], -1) {
		speeds[m[1]] = atoi(m[2])
	}
	addrs := map[string][]string{}
	for _, m := range linuxAddrRe.FindAllStringSubmatch(s["ADDR"], -1) {
		addrs[m[1]] = append(addrs[m[1]], m[2])
	}
	snap := &Snapshot{Facts: f}
	for _, m := range linuxLinkRe.FindAllStringSubmatch(s["LINK"], -1) {
		name := m[1]
		if name == "lo" {
			continue
		}
		flags := map[string]bool{}
		for _, fl := range strings.Split(m[2], ",") {
			flags[fl] = true
		}
		i := Interface{Name: name, MAC: NormMAC(m[4]), AdminUp: P(flags["UP"]), OperUp: P(flags["LOWER_UP"]), MTU: P(atoi(m[3])),
			Addresses: addrs[name]}
		if sp := speeds[name]; sp > 0 {
			i.SpeedMbps = P(sp)
		}
		if c, ok := counters[name]; ok {
			i.RxBytes, i.TxBytes = P(c.rx), P(c.tx)
		}
		snap.Interfaces = append(snap.Interfaces, i)
	}
	if len(snap.Interfaces) == 0 {
		for _, n := range order {
			if n == "lo" {
				continue
			}
			c := counters[n]
			snap.Interfaces = append(snap.Interfaces, Interface{Name: n, RxBytes: P(c.rx), TxBytes: P(c.tx), Addresses: addrs[n]})
		}
	}
	for i, line := range strings.Split(s["ARP"], "\n") {
		v := strings.Fields(line)
		if i == 0 || len(v) < 6 {
			continue
		}
		if mac := NormMAC(v[3]); mac != "" && mac != "00:00:00:00:00:00" && v[2] != "0x0" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(v[0]), Interface: v[5], Source: SourceARP})
		}
	}
	for _, line := range strings.Split(s["LEASES"], "\n") {
		v := strings.Fields(line)
		if len(v) >= 4 && NormMAC(v[1]) != "" {
			host := v[3]
			if host == "*" {
				host = ""
			}
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: NormMAC(v[1]), IP: NormIP(v[2]), Hostname: host, Source: SourceDHCP})
		}
	}
	snap.Neighbors = parseLLDPCli(s["LLDP"])
	if snap.Facts.MAC == "" {
		for _, i := range snap.Interfaces {
			if i.MAC != "" {
				snap.Facts.MAC = i.MAC
				break
			}
		}
	}
	return snap
}

// parseLLDPCli reads `lldpcli -f json show neighbors`.
func parseLLDPCli(text string) []Neighbor {
	var doc Obj
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &doc) != nil {
		return nil
	}
	var out []Neighbor
	for _, item := range L(O(doc, "lldp")["interface"]) {
		locals := make([]string, 0, len(item))
		for k := range item {
			locals = append(locals, k)
		}
		sort.Strings(locals)
		for _, local := range locals {
			n := asObj(item[local])
			var name string
			chassis := Obj{}
			if ch := O(n, "chassis"); len(ch) > 0 {
				for k, v := range ch {
					name, chassis = k, asObj(v)
					break
				}
			}
			ip := ""
			switch m := chassis["mgmt-ip"].(type) {
			case []any:
				if len(m) > 0 {
					ip = NormIP(Str(m[0]))
				}
			default:
				ip = NormIP(Str(m))
			}
			descr := Str(chassis["descr"])
			if len(descr) > 120 {
				descr = descr[:120]
			}
			out = append(out, Neighbor{LocalInterface: local, RemoteName: name, RemoteMAC: NormMAC(Str(O(chassis, "id")["value"])),
				RemoteIP: ip, RemoteInterface: Str(O(O(n, "port"), "id")["value"]), RemotePlatform: descr, Protocol: "lldp"})
		}
	}
	return out
}

// LinuxCaps are the actions of a Linux host.
var LinuxCaps = []string{ActionHostname, ActionInterface, ActionReboot, ActionCommand}

// LinuxDriver is a Linux host over SSH (exec channel).
type LinuxDriver struct {
	base
	ssh    *SSH
	osName string
}

// NewLinux returns the driver.
func NewLinux(t Target, c Credentials, vendor string) *LinuxDriver {
	return &LinuxDriver{base: base{t, c, vendor}, ssh: NewSSH(t, c, false), osName: "Linux"}
}

func (d *LinuxDriver) run(ctx context.Context, cmd string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return d.ssh.Run(ctx, cmd, timeout)
}

// Collect implements Driver.
func (d *LinuxDriver) Collect(ctx context.Context) (*Snapshot, error) {
	out, err := d.run(ctx, LinuxScript, 0)
	if err != nil {
		return nil, err
	}
	snap := ParseLinux(out)
	if snap.Facts.Vendor == "" {
		snap.Facts.Vendor = d.vendor
	}
	return snap, nil
}

// Apply implements Driver.
func (d *LinuxDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	switch action {
	case ActionHostname:
		if _, err := d.run(ctx, fmt.Sprintf("hostnamectl set-hostname %s 2>/dev/null || hostname %s", p.Name, p.Name), 0); err != nil {
			return "", err
		}
	case ActionInterface:
		if p.Enabled == nil {
			return "", Unsupported(d.osName, "interface description")
		}
		dev := strings.Fields(p.Name)[0]
		if _, err := d.run(ctx, fmt.Sprintf("ip link set dev %s %s", dev, map[bool]string{true: "up", false: "down"}[*p.Enabled]), 0); err != nil {
			return "", err
		}
	case ActionReboot:
		_, _ = d.run(ctx, "(sleep 1; reboot) >/dev/null 2>&1 &", 10*time.Second)
		return "Reboot started", nil
	case ActionCommand:
		return d.run(ctx, p.Command, 120*time.Second)
	default:
		return "", Unsupported(d.osName, action)
	}
	return "Done", nil
}

// HostKey implements Driver.
func (d *LinuxDriver) HostKey() string { return d.ssh.HostKey() }

// Close implements Driver.
func (d *LinuxDriver) Close() { d.ssh.Close() }

// OpenWrtCaps are the actions of OpenWrt.
var OpenWrtCaps = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionFlowExport, ActionReboot, ActionCommand,
	ActionBackup}

// OpenWrtDriver is OpenWrt (and GL.iNet, Turris, Cudy, Xiaomi / TP-Link on
// OpenWrt) over SSH with ubus and uci.
type OpenWrtDriver struct{ LinuxDriver }

// NewOpenWrt returns the driver.
func NewOpenWrt(t Target, c Credentials, vendor string) *OpenWrtDriver {
	d := &OpenWrtDriver{*NewLinux(t, c, vendor)}
	d.osName = "OpenWrt"
	return d
}

var hostapdSplitRe = regexp.MustCompile(`(?m)^#`)

// Collect implements Driver.
func (d *OpenWrtDriver) Collect(ctx context.Context) (*Snapshot, error) {
	snap, err := d.LinuxDriver.Collect(ctx)
	if err != nil {
		return nil, err
	}
	snap.Facts.OS = "OpenWrt"
	if out, err := d.run(ctx, "ubus call system board", 0); err == nil {
		var board Obj
		if json.Unmarshal([]byte(out), &board) == nil {
			snap.Facts.Model = or(Str(board["model"]), snap.Facts.Model)
			snap.Facts.Version = or(Str(O(board, "release")["version"]), snap.Facts.Version)
			snap.Facts.Hostname = or(Str(board["hostname"]), snap.Facts.Hostname)
		}
	}
	raw, _ := d.run(ctx, `for i in $(ubus list 'hostapd.*' 2>/dev/null); do echo "#$i"; `+
		`ubus call $i get_clients; ubus call $i get_status 2>/dev/null | grep '"ssid"'; done`, 0)
	snap.Endpoints = append(snap.Endpoints, ParseHostapd(raw)...)
	return snap, nil
}

// ParseHostapd reads the hostapd client lists of OpenWrt.
func ParseHostapd(raw string) []Endpoint {
	var out []Endpoint
	blocks := hostapdSplitRe.Split(raw, -1)
	for _, block := range blocks[1:] {
		name, body, _ := strings.Cut(block, "\n")
		ssid := first(`"ssid"\s*:\s*"([^"]*)"`, body)
		var doc Obj
		if i := strings.LastIndex(body, "}"); i >= 0 {
			_ = json.Unmarshal([]byte(body[:i+1]), &doc)
		}
		clients := O(doc, "clients")
		macs := make([]string, 0, len(clients))
		for m := range clients {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		for _, m := range macs {
			mac := NormMAC(m)
			if mac == "" {
				continue
			}
			out = append(out, Endpoint{MAC: mac, Interface: strings.TrimPrefix(strings.TrimSpace(name), "hostapd."), Source: SourceWiFi,
				SSID: ssid, Signal: IntP(asObj(clients[m])["signal"])})
		}
	}
	return out
}

// Apply implements Driver.
func (d *OpenWrtDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	var cmd string
	switch action {
	case ActionHostname:
		cmd = fmt.Sprintf("uci set system.@system[0].hostname='%s' && uci commit system && /etc/init.d/system reload", p.Name)
	case ActionDNS:
		parts := []string{"uci -q delete dhcp.@dnsmasq[0].server"}
		for _, s := range p.Servers {
			parts = append(parts, fmt.Sprintf("uci add_list dhcp.@dnsmasq[0].server='%s'", s))
		}
		cmd = strings.Join(parts, "; ") + "; uci commit dhcp && /etc/init.d/dnsmasq restart"
	case ActionNTP:
		parts := []string{"uci -q delete system.ntp.server"}
		for _, s := range p.Servers {
			parts = append(parts, fmt.Sprintf("uci add_list system.ntp.server='%s'", s))
		}
		cmd = strings.Join(parts, "; ") + "; uci commit system && /etc/init.d/sysntpd restart"
	case ActionFlowExport:
		if p.Protocol == "sflow" {
			return "", Unsupported("OpenWrt", "flow_export (sflow)")
		}
		version := map[string]string{"netflow5": "5", "netflow9": "9", "ipfix": "10"}[p.Protocol]
		on := map[bool]string{true: "1", false: "0"}[p.IsEnabled(true)]
		out, err := d.run(ctx, "[ -f /etc/config/softflowd ] || { echo NOPKG; exit 0; }; "+
			fmt.Sprintf("uci set softflowd.@softflowd[0].enabled='%s'; ", on)+
			fmt.Sprintf("uci set softflowd.@softflowd[0].host_port='%s:%d'; ", p.Collector, p.Port)+
			fmt.Sprintf("uci set softflowd.@softflowd[0].export_version='%s'; ", version)+
			`uci set softflowd.@softflowd[0].interface="$(uci -q get network.lan.device || echo br-lan)"; `+
			"uci commit softflowd && /etc/init.d/softflowd enable && /etc/init.d/softflowd restart", 0)
		if err != nil {
			return "", err
		}
		if strings.Contains(out, "NOPKG") {
			return "", Errorf("softflowd is not installed on OpenWrt: run 'opkg update && opkg install softflowd'")
		}
		return fmt.Sprintf("softflowd %s: %s:%d", map[bool]string{true: "enabled", false: "disabled"}[p.IsEnabled(true)],
			p.Collector, p.Port), nil
	case ActionBackup:
		return d.Backup(ctx)
	default:
		return d.LinuxDriver.Apply(ctx, action, p)
	}
	if _, err := d.run(ctx, cmd, 0); err != nil {
		return "", err
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *OpenWrtDriver) Backup(ctx context.Context) (string, error) {
	return d.run(ctx, "uci export", 0)
}
