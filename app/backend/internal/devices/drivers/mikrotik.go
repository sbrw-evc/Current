package drivers

// MikroTik RouterOS 7 (also CHR and RouterOS on any RouterBOARD / CRS / hAP
// / cAP). Two transports with the same data: the REST API (/rest, service
// www-ssl or www) and SSH, where RouterOS 7.13+ serialises `print as-value`
// to JSON. RouterOS 6 has neither and is polled over SNMP.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var mikrotikFlowVersions = map[string]string{"netflow5": "5", "netflow9": "9", "ipfix": "IPFIX"}

// MikrotikCaps are the actions of RouterOS.
var MikrotikCaps = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionFlowExport, ActionReboot,
	ActionCommand, ActionBackup}

// rosQuote quotes a RouterOS string.
func rosQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// MikrotikDriver talks to RouterOS over REST or SSH.
type MikrotikDriver struct {
	base
	http *HTTP
	ssh  *SSH
}

// NewMikrotik returns the driver of a target (transport api / http / ssh).
func NewMikrotik(t Target, c Credentials, vendor string) *MikrotikDriver {
	d := &MikrotikDriver{base: base{t, c, vendor}}
	if t.Transport == "ssh" {
		d.ssh = NewSSH(t, c, false)
	} else {
		d.http = NewHTTP(t, "https", 0)
		d.http.User, d.http.Pass = c.Username, c.Password
	}
	return d
}

var (
	rosBadCmdRe = regexp.MustCompile(`(?i)bad command|syntax error|no such command`)
	rosFailRe   = regexp.MustCompile(`(?m)^\s*(failure:|syntax error|bad command|expected |input does not match|no such item)`)
)

func (d *MikrotikDriver) list(ctx context.Context, path string, optional bool) ([]Obj, error) {
	var data any
	if d.http != nil {
		raw, _, err := d.http.Do(ctx, http.MethodGet, "/rest/"+path, nil, nil, 0)
		if err != nil {
			if optional {
				return nil, nil
			}
			return nil, d.http.Error(err)
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			if optional {
				return nil, nil
			}
			return nil, Errorf("%s: unexpected RouterOS response", d.t.Host)
		}
	} else {
		out, err := d.ssh.Run(ctx, fmt.Sprintf(":put [:serialize to=json value=[/%s print detail as-value]]",
			strings.ReplaceAll(path, "/", " ")), 30*time.Second)
		if err != nil {
			if optional {
				return nil, nil
			}
			return nil, err
		}
		if rosBadCmdRe.MatchString(out) {
			if optional {
				return nil, nil
			}
			return nil, Errorf("%s: RouterOS does not support :serialize; it needs 7.13+ or the REST API transport", d.t.Host)
		}
		out = strings.TrimSpace(out)
		if out == "" {
			out = "[]"
		}
		if err := json.Unmarshal([]byte(out), &data); err != nil {
			if optional {
				return nil, nil
			}
			return nil, Errorf("%s: unexpected RouterOS response", d.t.Host)
		}
	}
	return L(data), nil
}

func (d *MikrotikDriver) one(ctx context.Context, path string) Obj {
	rows, _ := d.list(ctx, path, true)
	if len(rows) == 0 {
		return Obj{}
	}
	return rows[0]
}

func (d *MikrotikDriver) cli(ctx context.Context, script string) (string, error) {
	if d.ssh != nil {
		out, err := d.ssh.Run(ctx, script, 60*time.Second)
		if err != nil {
			return "", err
		}
		if rosFailRe.MatchString(out) {
			return "", Errorf("RouterOS: %s", strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
		}
		return out, nil
	}
	v, err := d.http.Send(ctx, http.MethodPost, "/rest/execute", Obj{"script": script, "as-string": true}, 60*time.Second)
	if err != nil {
		return "", err
	}
	if m, ok := v.(map[string]any); ok {
		return Str(m["ret"]), nil
	}
	return Str(v), nil
}

// Collect implements Driver.
func (d *MikrotikDriver) Collect(ctx context.Context) (*Snapshot, error) {
	// The interface list is mandatory: it proves that the API answers and
	// the credentials work.
	ifaces, err := d.list(ctx, "interface", false)
	if err != nil {
		return nil, err
	}
	res := d.one(ctx, "system/resource")
	ident := d.one(ctx, "system/identity")
	board := d.one(ctx, "system/routerboard")
	total, _ := ToInt(res["total-memory"])
	free, _ := ToInt(res["free-memory"])
	f := Facts{Hostname: Str(ident["name"]), Vendor: "MikroTik", Model: or(Str(board["model"]), Str(res["board-name"])),
		OS: "RouterOS", Version: strings.Split(Str(res["version"]), " ")[0], Serial: Str(board["serial-number"]),
		UptimeSeconds: ParseDuration(Str(res["uptime"])), MemoryPercent: Percent(float64(total-free), float64(total))}
	if cpu, ok := ToInt(res["cpu-load"]); ok {
		f.CPUPercent = P(float64(cpu))
	}
	if a := Str(res["architecture-name"]); a != "" {
		f.Extra = map[string]any{"architecture": a}
	}
	snap := &Snapshot{Facts: f}

	addrs := map[string][]string{}
	rows, _ := d.list(ctx, "ip/address", true)
	for _, a := range rows {
		if !ToBool(a["disabled"]) {
			addrs[Str(a["interface"])] = append(addrs[Str(a["interface"])], Str(a["address"]))
		}
	}
	for _, i := range ifaces {
		name := Str(i["name"])
		mtu := IntP(i["actual-mtu"])
		if mtu == nil || *mtu == 0 {
			mtu = IntP(i["mtu"])
		}
		if mtu != nil && *mtu == 0 {
			mtu = nil
		}
		snap.Interfaces = append(snap.Interfaces, Interface{Name: name, Description: Str(i["comment"]), Type: Str(i["type"]),
			MAC: NormMAC(Str(i["mac-address"])), AdminUp: P(!ToBool(i["disabled"])), OperUp: P(ToBool(i["running"])),
			MTU: mtu, Addresses: addrs[name], RxBytes: UintP(i["rx-byte"]), TxBytes: UintP(i["tx-byte"])})
	}
	for _, i := range snap.Interfaces {
		if snap.Facts.MAC == "" && i.MAC != "" && (i.Type == "ether" || i.Type == "bridge") {
			snap.Facts.MAC = i.MAC
		}
	}

	rows, _ = d.list(ctx, "ip/neighbor", true)
	for _, n := range rows {
		proto := strings.Split(or(Str(n["discovered-by"]), "mndp"), ",")[0]
		plat := strings.TrimSpace(Str(n["platform"]) + " " + Str(n["board"]))
		snap.Neighbors = append(snap.Neighbors, Neighbor{LocalInterface: strings.Split(Str(n["interface"]), ",")[0],
			RemoteName: Str(n["identity"]), RemoteIP: NormIP(Str(n["address"])), RemoteMAC: NormMAC(Str(n["mac-address"])),
			RemoteInterface: Str(n["interface-name"]), RemotePlatform: plat, Protocol: proto})
	}

	rows, _ = d.list(ctx, "ip/arp", true)
	for _, a := range rows {
		if mac := NormMAC(Str(a["mac-address"])); mac != "" && !ToBool(a["invalid"]) {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(a["address"])),
				Interface: Str(a["interface"]), Source: SourceARP})
		}
	}
	rows, _ = d.list(ctx, "ip/dhcp-server/lease", true)
	for _, l := range rows {
		if mac := NormMAC(S(l, "active-mac-address", "mac-address")); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(S(l, "active-address", "address")),
				Hostname: S(l, "host-name", "comment"), Interface: Str(l["server"]), Source: SourceDHCP,
				Blocked: ToBool(l["block-access"])})
		}
	}
	for _, path := range []string{"interface/wifi/registration-table", "interface/wireless/registration-table",
		"caps-man/registration-table"} {
		rows, _ = d.list(ctx, path, true)
		for _, w := range rows {
			if mac := NormMAC(Str(w["mac-address"])); mac != "" {
				sig := strings.Split(S(w, "signal", "signal-strength"), "@")[0]
				snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, Interface: Str(w["interface"]), Source: SourceWiFi,
					SSID: Str(w["ssid"]), Signal: IntP(sig)})
			}
		}
	}
	uplinks := map[string]bool{}
	for _, n := range snap.Neighbors {
		uplinks[n.LocalInterface] = true
	}
	rows, _ = d.list(ctx, "interface/bridge/host", true)
	for _, h := range rows {
		mac := NormMAC(Str(h["mac-address"]))
		port := S(h, "on-interface", "interface")
		if mac != "" && !ToBool(h["local"]) && !uplinks[port] {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, Interface: port, Source: SourceBridge, VLAN: IntP(h["vid"])})
		}
	}
	caps, _ := d.list(ctx, "caps-man/remote-cap", true)
	caps2, _ := d.list(ctx, "interface/wifi/capsman/remote-cap", true)
	for _, c := range append(caps, caps2...) {
		if mac := NormMAC(S(c, "radio-mac", "mac-address")); mac != "" {
			snap.Children = append(snap.Children, Child{MAC: mac, Name: Str(c["identity"]), Model: Str(c["board"]), Kind: "ap",
				IP: NormIP(Str(c["address"])), Online: true, Version: Str(c["version"])})
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *MikrotikDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	var err error
	switch action {
	case ActionHostname:
		_, err = d.cli(ctx, "/system identity set name="+rosQuote(p.Name))
	case ActionInterface:
		var parts []string
		if p.Enabled != nil {
			parts = append(parts, "disabled="+map[bool]string{true: "no", false: "yes"}[*p.Enabled])
		}
		if p.Description != nil {
			parts = append(parts, "comment="+rosQuote(*p.Description))
		}
		_, err = d.cli(ctx, fmt.Sprintf("/interface set [find name=%s] %s", rosQuote(p.Name), strings.Join(parts, " ")))
	case ActionDNS:
		_, err = d.cli(ctx, "/ip dns set servers="+strings.Join(p.Servers, ","))
	case ActionNTP:
		_, err = d.cli(ctx, "/system ntp client set enabled=yes servers="+strings.Join(p.Servers, ","))
	case ActionFlowExport:
		ver, ok := mikrotikFlowVersions[p.Protocol]
		if !ok {
			return "", Unsupported(d.vendor, action)
		}
		find := fmt.Sprintf("[find dst-address=%s port=%d]", p.Collector, p.Port)
		if p.IsEnabled(true) {
			_, err = d.cli(ctx, fmt.Sprintf("/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s; "+
				":if ([:len [/ip traffic-flow target find dst-address=%s port=%d]] = 0) "+
				"do={/ip traffic-flow target add dst-address=%s port=%d version=%s} else={/ip traffic-flow target set %s version=%s}",
				p.Collector, p.Port, p.Collector, p.Port, ver, find, ver))
		} else {
			_, err = d.cli(ctx, "/ip traffic-flow target remove "+find)
		}
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Flow export %s: %s:%d", map[bool]string{true: "enabled", false: "disabled"}[p.IsEnabled(true)],
			p.Collector, p.Port), nil
	case ActionReboot:
		if d.ssh != nil {
			_, _ = d.ssh.Run(ctx, `:execute "/system reboot"`, 10*time.Second)
		} else {
			// the router drops the connection while rebooting
			_, _, _ = d.http.Do(ctx, http.MethodPost, "/rest/system/reboot", nil, Obj{}, 10*time.Second)
		}
		return "Reboot started", nil
	case ActionCommand:
		return d.cli(ctx, p.Command)
	default:
		return "", Unsupported(d.vendor, action)
	}
	if err != nil {
		return "", err
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *MikrotikDriver) Backup(ctx context.Context) (string, error) {
	return d.cli(ctx, "/export terse")
}

// HostKey implements Driver.
func (d *MikrotikDriver) HostKey() string {
	if d.ssh != nil {
		return d.ssh.HostKey()
	}
	return ""
}

// Close implements Driver.
func (d *MikrotikDriver) Close() {
	if d.ssh != nil {
		d.ssh.Close()
	}
	if d.http != nil {
		d.http.Close()
	}
}
