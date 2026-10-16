package drivers

// SSH CLI drivers of switch / router families. A profile lists the commands
// of one network OS; the parsers turn the output into the common model.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Driver talks to one device for one poll or action and is closed afterwards.
type Driver interface {
	Collect(ctx context.Context) (*Snapshot, error)
	Apply(ctx context.Context, action string, p Params) (string, error)
	Backup(ctx context.Context) (string, error)
	// HostKey is the SSH host key learned during the session (trust on
	// first use), saved by the service.
	HostKey() string
	Close()
}

// base implements the optional parts of Driver.
type base struct {
	t      Target
	c      Credentials
	vendor string
}

func (b *base) Apply(_ context.Context, action string, _ Params) (string, error) {
	return "", Unsupported(b.vendor, action)
}

func (b *base) Backup(context.Context) (string, error) {
	return "", Unsupported(b.vendor, ActionBackup)
}
func (b *base) HostKey() string { return "" }
func (b *base) Close()          {}

var cliErrorRe = regexp.MustCompile(`(?im)^\s*(%\s*(invalid|incomplete|ambiguous|unknown|unrecognized)|invalid input|unrecognized command|` +
	`unknown command|error:|syntax error|command not found|\^$)`)

// template builds the configuration lines of an action; errUnsupportedVariant
// marks a variant (e.g. sFlow on a NetFlow-only OS).
type template func(p Params) ([]string, error)

var errVariant = errors.New("variant not supported")

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, "") + `"` }

func ciscoIface(p Params) ([]string, error) {
	cmds := []string{"interface " + p.Name}
	if p.Enabled != nil {
		if *p.Enabled {
			cmds = append(cmds, "no shutdown")
		} else {
			cmds = append(cmds, "shutdown")
		}
	}
	if p.Description != nil {
		if *p.Description != "" {
			cmds = append(cmds, "description "+*p.Description)
		} else {
			cmds = append(cmds, "no description")
		}
	}
	return append(cmds, "exit"), nil
}

func iosFlow(p Params) ([]string, error) {
	if !p.IsEnabled(true) {
		return []string{"no flow exporter FLOW-EXPORT"}, nil
	}
	proto := map[string]string{"netflow9": "netflow-v9", "ipfix": "ipfix", "netflow5": "netflow-v5"}[p.Protocol]
	if proto == "" {
		return nil, errVariant
	}
	cmds := []string{"flow exporter FLOW-EXPORT", " destination " + p.Collector, fmt.Sprintf(" transport udp %d", p.Port),
		" export-protocol " + proto, " template data timeout 60", "exit",
		"flow monitor FLOW-MONITOR", " exporter FLOW-EXPORT", " record netflow ipv4 original-input", " cache timeout active 60", "exit",
		"flow monitor FLOW-MONITOR6", " exporter FLOW-EXPORT", " record netflow ipv6 original-input", " cache timeout active 60", "exit"}
	for _, i := range p.Interfaces {
		cmds = append(cmds, "interface "+i, " ip flow monitor FLOW-MONITOR input", " ipv6 flow monitor FLOW-MONITOR6 input", "exit")
	}
	return cmds, nil
}

func arubaIface(p Params) ([]string, error) {
	cmds := []string{"interface " + p.Name}
	if p.Enabled != nil {
		if *p.Enabled {
			cmds = append(cmds, "enable")
		} else {
			cmds = append(cmds, "disable")
		}
	}
	if p.Description != nil {
		if *p.Description != "" {
			cmds = append(cmds, "name "+quote(*p.Description))
		} else {
			cmds = append(cmds, "no name")
		}
	}
	return append(cmds, "exit"), nil
}

func comwareIface(p Params) ([]string, error) {
	cmds := []string{"interface " + p.Name}
	if p.Enabled != nil {
		if *p.Enabled {
			cmds = append(cmds, "undo shutdown")
		} else {
			cmds = append(cmds, "shutdown")
		}
	}
	if p.Description != nil {
		if *p.Description != "" {
			cmds = append(cmds, "description "+*p.Description)
		} else {
			cmds = append(cmds, "undo description")
		}
	}
	return append(cmds, "quit"), nil
}

func each(prefix string, servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, prefix+s)
	}
	return out
}

func lines(f func(p Params) []string) template {
	return func(p Params) ([]string, error) { return f(p), nil }
}

// CLIProfile is the command set of one network OS.
type CLIProfile struct {
	Key, Vendor, OS string
	Setup           []string
	Version         []string
	Interfaces      []string
	LLDP            []string
	CDP             []string
	ARP             []string
	MAC             []string
	Running         string
	Enter, Leave    []string
	Save            []string
	Reboot          []string
	Templates       map[string]template
	LegacySSH       bool
	Answers         []Answer
}

var defaultAnswers = Answers(`\[confirm\]\s*$`, "", `\[y/n\]:?\s*$`, "y", `\[yes/no\]:?\s*$`, "yes", `destination filename \[.*\]\?\s*$`, "")

func profile(p CLIProfile) CLIProfile {
	def := func(v *[]string, d ...string) {
		if *v == nil {
			*v = d
		}
	}
	def(&p.Setup, "terminal length 0")
	def(&p.Version, "show version")
	def(&p.Interfaces, "show interfaces", "show interfaces status")
	def(&p.LLDP, "show lldp neighbors detail")
	def(&p.ARP, "show ip arp", "show arp")
	def(&p.MAC, "show mac address-table")
	def(&p.Enter, "configure terminal")
	def(&p.Leave, "end")
	def(&p.Save, "write memory")
	if p.Running == "" {
		p.Running = "show running-config"
	}
	if p.Answers == nil {
		p.Answers = defaultAnswers
	}
	return p
}

func ciscoLike(extra map[string]template) map[string]template {
	t := map[string]template{
		ActionHostname:  lines(func(p Params) []string { return []string{"hostname " + p.Name} }),
		ActionInterface: ciscoIface,
		ActionDNS:       lines(func(p Params) []string { return []string{"ip name-server " + strings.Join(p.Servers, " ")} }),
		ActionNTP:       lines(func(p Params) []string { return each("ntp server ", p.Servers) }),
	}
	for k, v := range extra {
		t[k] = v
	}
	return t
}

func sflowOnly(on func(p Params) []string, off []string) template {
	return func(p Params) ([]string, error) {
		if p.Protocol != "sflow" {
			return nil, errVariant
		}
		if !p.IsEnabled(true) {
			return off, nil
		}
		return on(p), nil
	}
}

func priority(prefix string, servers []string) []string {
	var out []string
	for i, s := range servers {
		if i >= 3 {
			break
		}
		out = append(out, fmt.Sprintf("%s%d %s", prefix, i+1, s))
	}
	return out
}

// CLIProfiles are the supported network OSes.
var CLIProfiles = map[string]CLIProfile{}

func init() {
	for _, p := range []CLIProfile{
		{Key: "cisco_ios", Vendor: "Cisco", OS: "IOS / IOS-XE", CDP: []string{"show cdp neighbors detail"},
			Templates: ciscoLike(map[string]template{ActionFlowExport: iosFlow}), Reboot: []string{"reload"}, LegacySSH: true},
		{Key: "cisco_nxos", Vendor: "Cisco", OS: "NX-OS", Interfaces: []string{"show interface", "show interface brief"},
			CDP: []string{"show cdp neighbors detail"}, Save: []string{"copy running-config startup-config"},
			Templates: ciscoLike(map[string]template{
				ActionNTP: lines(func(p Params) []string {
					out := []string{}
					for _, s := range p.Servers {
						out = append(out, "ntp server "+s+" use-vrf management")
					}
					return out
				})}), Reboot: []string{"reload"}},
		{Key: "dell_os10", Vendor: "Dell", OS: "OS10", Interfaces: []string{"show interface", "show interface status"},
			ARP: []string{"show ip arp"}, Templates: ciscoLike(nil), Reboot: []string{"reload"}},
		{Key: "dell_nseries", Vendor: "Dell", OS: "PowerSwitch N / PowerConnect", Interfaces: []string{"show interfaces status", "show interfaces"},
			LLDP: []string{"show lldp remote-device detail all", "show lldp remote-device all"}, ARP: []string{"show arp"},
			Templates: ciscoLike(nil), Reboot: []string{"reload"}, LegacySSH: true},
		{Key: "aruba_cx", Vendor: "HPE Aruba", OS: "AOS-CX", Setup: []string{"no page"}, Interfaces: []string{"show interface", "show interface brief"},
			LLDP: []string{"show lldp neighbor-info detail", "show lldp neighbor-info"}, ARP: []string{"show arp"},
			MAC: []string{"show mac-address-table"},
			Templates: ciscoLike(map[string]template{
				ActionDNS: lines(func(p Params) []string { return each("ip dns server-address ", p.Servers) })}),
			Reboot: []string{"boot system"}},
		{Key: "aruba_os", Vendor: "HP / HPE Aruba", OS: "ArubaOS-Switch / ProCurve", Setup: []string{"no page"},
			Version: []string{"show system", "show version"}, Interfaces: []string{"show interfaces brief"},
			LLDP: []string{"show lldp info remote-device"}, ARP: []string{"show arp"}, MAC: []string{"show mac-address"},
			Enter: []string{"configure"}, Leave: []string{"end"}, Save: []string{"write memory"}, Reboot: []string{"boot"}, LegacySSH: true,
			Templates: map[string]template{
				ActionHostname:  lines(func(p Params) []string { return []string{"hostname " + quote(p.Name)} }),
				ActionInterface: arubaIface,
				ActionDNS:       lines(func(p Params) []string { return priority("ip dns server-address priority ", p.Servers) }),
				ActionNTP: lines(func(p Params) []string {
					return append([]string{"timesync sntp", "sntp unicast"}, priority("sntp server priority ", p.Servers)...)
				}),
				ActionFlowExport: sflowOnly(func(p Params) []string {
					return []string{fmt.Sprintf("sflow 1 destination %s %d", p.Collector, p.Port), "sflow 1 sampling all 1024", "sflow 1 polling all 30"}
				}, []string{"no sflow 1 destination"}),
			}},
		{Key: "hp_comware", Vendor: "HPE / H3C", OS: "Comware", Setup: []string{"screen-length disable"}, Version: []string{"display version"},
			Interfaces: []string{"display interface brief"}, LLDP: []string{"display lldp neighbor-information verbose", "display lldp neighbor-information list"},
			ARP: []string{"display arp"}, MAC: []string{"display mac-address"}, Running: "display current-configuration",
			Enter: []string{"system-view"}, Leave: []string{"return"}, Save: []string{"save force"}, Reboot: []string{"reboot"}, LegacySSH: true,
			Templates: map[string]template{
				ActionHostname:  lines(func(p Params) []string { return []string{"sysname " + p.Name} }),
				ActionInterface: comwareIface,
				ActionDNS:       lines(func(p Params) []string { return each("dns server ", p.Servers) }),
				ActionNTP: lines(func(p Params) []string {
					return append([]string{"ntp-service enable"}, each("ntp-service unicast-server ", p.Servers)...)
				}),
				ActionFlowExport: sflowOnly(func(p Params) []string {
					return []string{fmt.Sprintf("sflow collector 1 ip %s port %d", p.Collector, p.Port)}
				}, []string{"undo sflow collector 1"}),
			}},
		{Key: "huawei_vrp", Vendor: "Huawei", OS: "VRP", Setup: []string{"screen-length 0 temporary"}, Version: []string{"display version"},
			Interfaces: []string{"display interface brief"}, LLDP: []string{"display lldp neighbor", "display lldp neighbor brief"},
			ARP: []string{"display arp"}, MAC: []string{"display mac-address"}, Running: "display current-configuration",
			Enter: []string{"system-view"}, Leave: []string{"return"}, Save: []string{"save"}, Reboot: []string{"reboot"}, LegacySSH: true,
			Templates: map[string]template{
				ActionHostname:  lines(func(p Params) []string { return []string{"sysname " + p.Name} }),
				ActionInterface: comwareIface,
				ActionDNS:       lines(func(p Params) []string { return append([]string{"dns resolve"}, each("dns server ", p.Servers)...) }),
				ActionNTP:       lines(func(p Params) []string { return each("ntp-service unicast-server ", p.Servers) }),
			}},
		{Key: "zyxel", Vendor: "Zyxel", OS: "Zyxel switch / ZLD", Setup: []string{}, Version: []string{"show system-information", "show version"},
			Interfaces: []string{"show interfaces status", "show interface all"}, LLDP: []string{"show lldp info remote", "show lldp neighbor"},
			ARP: []string{"show ip arp", "show arp-table"}, MAC: []string{"show mac address-table all"}, Enter: []string{"configure"},
			Leave: []string{"exit"}, Save: []string{"write memory"}, Reboot: []string{"reload config"}, LegacySSH: true,
			Templates: map[string]template{
				ActionHostname:  lines(func(p Params) []string { return []string{"hostname " + p.Name} }),
				ActionInterface: ciscoIface,
				ActionNTP:       lines(func(p Params) []string { return []string{"time timezone 0", "time ntp-server " + p.Servers[0]} }),
			}},
		{Key: "tplink_jetstream", Vendor: "TP-Link", OS: "JetStream / Omada switch (standalone)", Setup: []string{"enable"},
			Version: []string{"show system-info"}, Interfaces: []string{"show interface status"},
			LLDP: []string{"show lldp neighbor-information interface"}, ARP: []string{"show arp"}, MAC: []string{"show mac address-table all"},
			Enter: []string{"configure"}, Leave: []string{"end"}, Save: []string{"copy running-config startup-config"}, Reboot: []string{"reboot"},
			LegacySSH: true,
			Templates: map[string]template{
				ActionHostname:  lines(func(p Params) []string { return []string{"hostname " + p.Name} }),
				ActionInterface: ciscoIface,
				ActionNTP: lines(func(p Params) []string {
					second := p.Servers[0]
					if len(p.Servers) > 1 {
						second = p.Servers[1]
					}
					return []string{fmt.Sprintf("system-time ntp UTC+00:00 %s %s 12", p.Servers[0], second)}
				}),
			}},
		{Key: "eltex", Vendor: "Eltex", OS: "MES", Setup: []string{"terminal datadump"}, Interfaces: []string{"show interfaces status"},
			LLDP: []string{"show lldp neighbors"}, ARP: []string{"show arp"}, Templates: ciscoLike(nil), Reboot: []string{"reload"}, LegacySSH: true},
	} {
		CLIProfiles[p.Key] = profile(p)
	}
}

// CLIDriver drives a network OS over an interactive SSH session.
type CLIDriver struct {
	base
	p   CLIProfile
	ssh *SSH
}

// NewCLI returns the driver of a profile.
func NewCLI(t Target, c Credentials, vendor, profileKey string) *CLIDriver {
	p := CLIProfiles[profileKey]
	return &CLIDriver{base: base{t, c, vendor}, p: p, ssh: NewSSH(t, c, p.LegacySSH)}
}

// Capabilities of a profile: its templates, command, backup and reboot.
func (p CLIProfile) Capabilities() map[string]bool {
	caps := map[string]bool{ActionCommand: true, ActionBackup: true}
	for k := range p.Templates {
		caps[k] = true
	}
	if len(p.Reboot) > 0 {
		caps[ActionReboot] = true
	}
	return caps
}

func (d *CLIDriver) session(ctx context.Context, commands []string, timeout time.Duration, answers []Answer) ([]string, error) {
	cmds := append(append([]string{}, d.p.Setup...), commands...)
	out, err := d.ssh.Shell(ctx, cmds, ShellOptions{Timeout: timeout, Enable: d.c.EnablePassword, Answers: answers})
	if err != nil {
		return nil, err
	}
	if len(out) < len(d.p.Setup) {
		return nil, Errorf("%s: the CLI session ended early", d.t.Host)
	}
	return out[len(d.p.Setup):], nil
}

func cliOK(text string) string {
	head := text
	if len(head) > 400 {
		head = head[:400]
	}
	if cliErrorRe.MatchString(head) {
		return ""
	}
	return text
}

// Collect implements Driver.
func (d *CLIDriver) Collect(ctx context.Context) (*Snapshot, error) {
	var flat []string
	for _, g := range [][]string{d.p.Version, d.p.Interfaces, d.p.LLDP, d.p.CDP, d.p.ARP, d.p.MAC} {
		flat = append(flat, g...)
	}
	res, err := d.session(ctx, flat, 60*time.Second, nil)
	if err != nil {
		return nil, err
	}
	outs := map[string]string{}
	for i, c := range flat {
		if i < len(res) {
			outs[c] = res[i]
		}
	}
	var versions []string
	for _, c := range d.p.Version {
		versions = append(versions, cliOK(outs[c]))
	}
	v := ParseVersion(strings.Join(versions, "\n"))
	snap := &Snapshot{Facts: Facts{Hostname: v.Hostname, Vendor: d.p.Vendor, Model: v.Model, OS: d.p.OS, Version: v.Version,
		Serial: v.Serial, MAC: v.MAC, UptimeSeconds: v.Uptime}}
	for _, c := range d.p.Interfaces {
		if t := cliOK(outs[c]); t != "" {
			ifs := ParseShowInterfaces(t)
			if len(ifs) == 0 {
				ifs = ParseStatusTable(t)
			}
			if len(ifs) > 0 {
				snap.Interfaces = ifs
				break
			}
		}
	}
	for _, c := range d.p.LLDP {
		if t := cliOK(outs[c]); t != "" {
			n := ParseLLDPDetail(t)
			if len(n) == 0 {
				n = ParseLLDPTable(t)
			}
			if len(n) > 0 {
				snap.Neighbors = n
				break
			}
		}
	}
	seen := map[string]bool{}
	for _, n := range snap.Neighbors {
		seen[ShortenIface(n.LocalInterface)+"\x00"+strings.ToLower(n.RemoteName)] = true
	}
	for _, c := range d.p.CDP {
		if t := cliOK(outs[c]); t != "" {
			if cdp := ParseCDPDetail(t); len(cdp) > 0 {
				for _, n := range cdp {
					if !seen[ShortenIface(n.LocalInterface)+"\x00"+strings.ToLower(n.RemoteName)] {
						snap.Neighbors = append(snap.Neighbors, n)
					}
				}
				break
			}
		}
	}
	uplinks := map[string]bool{}
	for _, n := range snap.Neighbors {
		uplinks[ShortenIface(n.LocalInterface)] = true
		uplinks[n.LocalInterface] = true
	}
	for _, c := range d.p.ARP {
		if t := cliOK(outs[c]); t != "" {
			if e := ParseARP(t); len(e) > 0 {
				snap.Endpoints = append(snap.Endpoints, e...)
				break
			}
		}
	}
	for _, c := range d.p.MAC {
		if t := cliOK(outs[c]); t != "" {
			if e := ParseMACTable(t, uplinks); len(e) > 0 {
				snap.Endpoints = append(snap.Endpoints, e...)
				break
			}
		}
	}
	if snap.Facts.MAC == "" {
		for _, i := range snap.Interfaces {
			if i.MAC != "" {
				snap.Facts.MAC = i.MAC
				break
			}
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *CLIDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	vendor := or(d.vendor, d.p.Vendor)
	if action == ActionCommand {
		out, err := d.session(ctx, []string{p.Command}, 120*time.Second, nil)
		if err != nil {
			return "", err
		}
		return out[0], nil
	}
	if action == ActionReboot && len(d.p.Reboot) > 0 {
		// The device closes the session while rebooting.
		_, _ = d.session(ctx, append(append([]string{}, d.p.Save...), d.p.Reboot...), 30*time.Second, d.p.Answers)
		return "Reboot started", nil
	}
	tpl := d.p.Templates[action]
	if tpl == nil {
		return "", Unsupported(vendor, action)
	}
	body, err := tpl(p)
	if err != nil {
		return "", Unsupported(vendor, action+" ("+p.Protocol+")")
	}
	cmds := append(append(append(append([]string{}, d.p.Enter...), body...), d.p.Leave...), d.p.Save...)
	outs, err := d.session(ctx, cmds, 60*time.Second, d.p.Answers)
	if err != nil {
		return "", err
	}
	for _, o := range outs {
		if cliErrorRe.MatchString(o) {
			first := strings.Split(strings.TrimSpace(o), "\n")[0]
			return "", Errorf("%s: %s", d.t.Host, first)
		}
	}
	return "Done", nil
}

// Backup implements Driver.
func (d *CLIDriver) Backup(ctx context.Context) (string, error) {
	out, err := d.session(ctx, []string{d.p.Running}, 120*time.Second, nil)
	if err != nil {
		return "", err
	}
	return out[0], nil
}

// HostKey implements Driver.
func (d *CLIDriver) HostKey() string { return d.ssh.HostKey() }

// Close implements Driver.
func (d *CLIDriver) Close() { d.ssh.Close() }

// JunosDriver: Juniper Junos (EX / SRX / MX / QFX), operational commands
// with `| display json` on an exec channel.
type JunosDriver struct {
	base
	ssh *SSH
}

// JunosCaps are the actions of the Junos driver.
var JunosCaps = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionReboot, ActionCommand, ActionBackup}

// NewJunos returns the Junos driver.
func NewJunos(t Target, c Credentials, vendor string) *JunosDriver {
	return &JunosDriver{base: base{t, c, vendor}, ssh: NewSSH(t, c, false)}
}

func (d *JunosDriver) json(ctx context.Context, cmd string) Obj {
	out, err := d.ssh.Run(ctx, cmd+" | display json | no-more", 60*time.Second)
	if err != nil {
		return Obj{}
	}
	i := strings.Index(out, "{")
	if i < 0 {
		return Obj{}
	}
	var v Obj
	if json.Unmarshal([]byte(out[i:]), &v) != nil {
		return Obj{}
	}
	return v
}

// jd walks Junos JSON, which wraps every value as [{"data": v}] / [{...}].
func jd(node any, path ...string) any {
	for _, key := range path {
		if l, ok := node.([]any); ok {
			if len(l) == 0 {
				return nil
			}
			node = l[0]
		}
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[key]
	}
	if l, ok := node.([]any); ok {
		if len(l) == 0 {
			return nil
		}
		node = l[0]
	}
	if m, ok := node.(map[string]any); ok {
		if v, ok := m["data"]; ok {
			return v
		}
	}
	return node
}

func js(node any, path ...string) string { return Str(jd(node, path...)) }

// jl is a list under node[key] (Junos lists of objects).
func jl(node any, key string) []Obj {
	if l, ok := node.([]any); ok {
		if len(l) == 0 {
			return nil
		}
		node = l[0]
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	return L(m[key])
}

var junosSpeedRe = regexp.MustCompile(`(\d+)\s*([mg])`)

// Collect implements Driver.
func (d *JunosDriver) Collect(ctx context.Context) (*Snapshot, error) {
	if _, err := d.ssh.Connect(ctx); err != nil {
		return nil, err
	}
	info := d.json(ctx, "show system information")
	si := jd(info, "system-information")
	up := d.json(ctx, "show system uptime")
	uptime := js(up, "system-uptime-information", "uptime-information", "up-time")
	if uptime == "" {
		uptime = js(up, "multi-routing-engine-results", "multi-routing-engine-item", "system-uptime-information", "uptime-information", "up-time")
	}
	snap := &Snapshot{Facts: Facts{Hostname: js(si, "host-name"), Vendor: "Juniper", Model: js(si, "hardware-model"), OS: "Junos",
		Version: js(si, "os-version"), Serial: js(si, "serial-number"), UptimeSeconds: ParseUptime(uptime)}}
	ifs := d.json(ctx, "show interfaces extensive")
	for _, phy := range jl(ifs["interface-information"], "physical-interface") {
		it := Interface{Name: js(phy, "name"), Description: js(phy, "description"), MAC: NormMAC(js(phy, "current-physical-address")),
			AdminUp: P(js(phy, "admin-status") == "up"), OperUp: P(js(phy, "oper-status") == "up"), MTU: IntP(jd(phy, "mtu")),
			Addresses: []string{}}
		if m := junosSpeedRe.FindStringSubmatch(strings.ToLower(js(phy, "speed"))); m != nil {
			n := atoi(m[1])
			if m[2] == "g" {
				n *= 1000
			}
			it.SpeedMbps = P(n)
		}
		if stats, ok := jd(phy, "traffic-statistics").(map[string]any); ok {
			it.RxBytes, it.TxBytes = UintP(jd(stats, "input-bytes")), UintP(jd(stats, "output-bytes"))
		}
		for _, lif := range L(phy["logical-interface"]) {
			for _, af := range L(lif["address-family"]) {
				if js(af, "address-family-name") != "inet" {
					continue
				}
				for _, a := range L(af["interface-address"]) {
					dst := js(a, "ifa-destination")
					it.Addresses = append(it.Addresses, js(a, "ifa-local")+"/"+dst[strings.LastIndex(dst, "/")+1:])
				}
			}
		}
		snap.Interfaces = append(snap.Interfaces, it)
	}
	lldp := d.json(ctx, "show lldp neighbors")
	for _, n := range jl(lldp["lldp-neighbors-information"], "lldp-neighbor-information") {
		snap.Neighbors = append(snap.Neighbors, Neighbor{LocalInterface: or(js(n, "lldp-local-port-id"), js(n, "lldp-local-interface")),
			RemoteName: js(n, "lldp-remote-system-name"), RemoteMAC: NormMAC(js(n, "lldp-remote-chassis-id")),
			RemoteInterface: or(js(n, "lldp-remote-port-id"), js(n, "lldp-remote-port-description")), Protocol: "lldp"})
	}
	arp := d.json(ctx, "show arp no-resolve")
	for _, a := range jl(arp["arp-table-information"], "arp-table-entry") {
		if mac := NormMAC(js(a, "mac-address")); mac != "" {
			snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(js(a, "ip-address")), Interface: js(a, "interface-name"), Source: SourceARP})
		}
	}
	uplinks := map[string]bool{}
	for _, n := range snap.Neighbors {
		uplinks[n.LocalInterface] = true
	}
	eth := d.json(ctx, "show ethernet-switching table")
	tables := L(eth["l2ng-l2ald-rtb-macdb"])
	if len(tables) == 0 {
		tables = L(eth["ethernet-switching-table-information"])
	}
	for _, t := range tables {
		vl := t["l2ng-l2ald-mac-entry-vlan"]
		if vl == nil {
			vl = t["ethernet-switching-table"]
		}
		for _, e := range jl(vl, "l2ng-mac-entry") {
			mac := NormMAC(js(e, "l2ng-l2-mac-address"))
			port, _, _ := strings.Cut(js(e, "l2ng-l2-mac-logical-interface"), ".")
			if mac != "" && port != "" && !uplinks[port] {
				snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, Interface: port, Source: SourceBridge})
			}
		}
	}
	return snap, nil
}

var junosErrRe = regexp.MustCompile(`(?i)error:|syntax error|unknown command`)

func (d *JunosDriver) configure(ctx context.Context, cfg []string) (string, error) {
	out, err := d.ssh.Shell(ctx, append(append([]string{"configure private"}, cfg...), "commit and-quit"), ShellOptions{Timeout: 120 * time.Second})
	if err != nil {
		return "", err
	}
	text := strings.Join(out, "\n")
	if junosErrRe.MatchString(text) {
		ls := strings.Split(strings.TrimSpace(text), "\n")
		return "", Errorf("Junos: %s", ls[len(ls)-1])
	}
	return "Done", nil
}

// Apply implements Driver.
func (d *JunosDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	switch action {
	case ActionHostname:
		return d.configure(ctx, []string{"set system host-name " + p.Name})
	case ActionInterface:
		var cfg []string
		if p.Enabled != nil {
			verb := "set"
			if *p.Enabled {
				verb = "delete"
			}
			cfg = append(cfg, verb+" interfaces "+p.Name+" disable")
		}
		if p.Description != nil {
			cfg = append(cfg, "set interfaces "+p.Name+` description "`+*p.Description+`"`)
		}
		return d.configure(ctx, cfg)
	case ActionDNS:
		return d.configure(ctx, append([]string{"delete system name-server"}, each("set system name-server ", p.Servers)...))
	case ActionNTP:
		return d.configure(ctx, each("set system ntp server ", p.Servers))
	case ActionReboot:
		_, _ = d.ssh.Shell(ctx, []string{"request system reboot"}, ShellOptions{Timeout: 20 * time.Second, Answers: Answers(`\[yes,no\].*$`, "yes")})
		return "Reboot started", nil
	case ActionCommand:
		return d.ssh.Run(ctx, p.Command+" | no-more", 120*time.Second)
	}
	return "", Unsupported("Juniper", action)
}

// Backup implements Driver.
func (d *JunosDriver) Backup(ctx context.Context) (string, error) {
	return d.ssh.Run(ctx, "show configuration | display set | no-more", 120*time.Second)
}

// HostKey implements Driver.
func (d *JunosDriver) HostKey() string { return d.ssh.HostKey() }

// Close implements Driver.
func (d *JunosDriver) Close() { d.ssh.Close() }
