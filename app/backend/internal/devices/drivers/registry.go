package drivers

import (
	"context"
	"slices"
)

// Transport is a way to reach a platform and its default port.
type Transport struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// Factory builds the driver of a platform.
type Factory func(t Target, c Credentials, vendor string) Driver

// Platform is a supported device family.
type Platform struct {
	Key         string      `json:"key"`
	Vendor      string      `json:"vendor"`
	Title       string      `json:"title"`
	Segment     string      `json:"segment"` // home | smb | enterprise | any
	Kind        string      `json:"kind"`    // router | switch | firewall | controller | ap | server | other
	Transports  []Transport `json:"transports"`
	Credentials []string    `json:"credentials"` // fields shown in the form
	Hint        string      `json:"hint"`
	Aliases     []string    `json:"aliases,omitempty"`

	factory Factory
	caps    func(transport string) []string
	native  string // the transport handled by the factory itself when it is snmp / gnmi
}

// Describe is the platform with its capabilities per transport (the API).
type Describe struct {
	Platform
	Capabilities map[string][]string `json:"capabilities"`
}

// DefaultTransport is the first transport.
func (p *Platform) DefaultTransport() string { return p.Transports[0].Name }

// HasTransport reports whether the platform supports a transport.
func (p *Platform) HasTransport(t string) bool {
	for _, x := range p.Transports {
		if x.Name == t {
			return true
		}
	}
	return false
}

// Port is the default port of a transport.
func (p *Platform) Port(t string) int {
	for _, x := range p.Transports {
		if x.Name == t {
			return x.Port
		}
	}
	return 0
}

// Driver returns the driver of a target; the transport defaults to the
// first one, and SNMP on a non-SNMP platform uses the SNMP driver.
func (p *Platform) Driver(t Target, c Credentials) (Driver, error) {
	if t.Transport == "" {
		t.Transport = p.DefaultTransport()
	}
	if !p.HasTransport(t.Transport) {
		return nil, Errorf("%s: transport %s is not supported", p.Title, t.Transport)
	}
	if t.Port == 0 {
		t.Port = p.Port(t.Transport)
	}
	if t.Transport == "snmp" && p.native != "snmp" {
		return NewSNMP(t, c, p.Vendor), nil
	}
	return p.factory(t, c, p.Vendor), nil
}

// Capabilities are the actions of a transport, in display order.
func (p *Platform) Capabilities(transport string) []string {
	if transport == "" {
		transport = p.DefaultTransport()
	}
	var caps []string
	if transport == "snmp" && p.native != "snmp" {
		caps = SNMPCaps
	} else {
		caps = p.caps(transport)
	}
	out := []string{}
	for _, a := range Actions {
		if slices.Contains(caps, a) {
			out = append(out, a)
		}
	}
	return out
}

// Describe returns the API view of the platform.
func (p *Platform) Describe() Describe {
	caps := map[string][]string{}
	for _, t := range p.Transports {
		caps[t.Name] = p.Capabilities(t.Name)
	}
	return Describe{Platform: *p, Capabilities: caps}
}

// Credential field sets.
var (
	fieldsSSH  = []string{FieldUsername, FieldPassword, FieldPrivateKey}
	fieldsCLI  = []string{FieldUsername, FieldPassword, FieldPrivateKey, FieldEnablePassword}
	fieldsSNMP = []string{FieldSNMPVersion, FieldSNMPCommunity, FieldSNMPUser, FieldSNMPAuthProtocol, FieldSNMPAuthPassword,
		FieldSNMPPrivProtocol, FieldSNMPPrivPassword}
)

func join(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func fixed(caps []string) func(string) []string { return func(string) []string { return caps } }

func capsOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func cliPlatform(key, vendor, title, segment, kind, profileKey, hint string) *Platform {
	return &Platform{Key: key, Vendor: vendor, Title: title, Segment: segment, Kind: kind,
		Transports: []Transport{{"ssh", 22}, {"snmp", 161}}, Credentials: join(fieldsCLI, fieldsSNMP), Hint: hint,
		factory: func(t Target, c Credentials, v string) Driver { return NewCLI(t, c, v, profileKey) },
		caps:    func(string) []string { return capsOf(CLIProfiles[profileKey].Capabilities()) }}
}

func snmpPlatform(key, vendor, title, segment, kind, hint string) *Platform {
	return &Platform{Key: key, Vendor: vendor, Title: title, Segment: segment, Kind: kind, Transports: []Transport{{"snmp", 161}},
		Credentials: fieldsSNMP, Hint: hint, native: "snmp",
		factory: func(t Target, c Credentials, v string) Driver { return NewSNMP(t, c, v) }, caps: fixed(SNMPCaps)}
}

// Platforms lists the supported families in display order.
var Platforms = []*Platform{
	{Key: "mikrotik", Vendor: "MikroTik", Title: "MikroTik RouterOS 7", Segment: "any", Kind: "router",
		Transports:  []Transport{{"api", 443}, {"http", 80}, {"ssh", 22}, {"snmp", 161}},
		Credentials: join([]string{FieldUsername, FieldPassword, FieldPrivateKey}, fieldsSNMP),
		Hint:        "REST API (www-ssl / www service) or SSH with RouterOS 7.13+; RouterOS 6 via SNMP", Aliases: []string{"routeros", "mikrotik"},
		factory: func(t Target, c Credentials, v string) Driver { return NewMikrotik(t, c, v) }, caps: fixed(MikrotikCaps)},
	cliPlatform("tplink_jetstream", "TP-Link", "TP-Link JetStream / Omada switch (standalone)", "smb", "switch", "tplink_jetstream",
		"Managed T / SG / SX series switches in standalone mode"),
	snmpPlatform("tplink", "TP-Link", "TP-Link (Archer, Deco, Easy Smart, etc.)", "home", "router",
		"Home models without an open API are polled over SNMP; use Omada or OpenWrt for management"),
	{Key: "omada", Vendor: "TP-Link", Title: "TP-Link Omada SDN Controller", Segment: "smb", Kind: "controller",
		Transports: []Transport{{"https", 8043}, {"http", 8088}}, Credentials: []string{FieldAPIKey, FieldAPISecret},
		Hint:    "Open API: Client ID and Client Secret; the Site field is the Omada site name",
		factory: func(t Target, c Credentials, v string) Driver { return NewOmada(t, c, v) }, caps: fixed(ControllerCaps)},
	{Key: "opnsense", Vendor: "Deciso", Title: "OPNsense", Segment: "smb", Kind: "firewall",
		Transports: []Transport{{"https", 443}, {"http", 80}, {"snmp", 161}}, Credentials: join([]string{FieldAPIKey, FieldAPISecret}, fieldsSNMP),
		Hint:    "API key / secret of a user with diagnostics rights",
		factory: func(t Target, c Credentials, v string) Driver { return NewOpnsense(t, c, v) }, caps: fixed(OpnsenseCaps)},
	{Key: "pfsense", Vendor: "Netgate", Title: "pfSense", Segment: "smb", Kind: "firewall",
		Transports:  []Transport{{"https", 443}, {"http", 80}, {"snmp", 161}},
		Credentials: join([]string{FieldAPIKey, FieldUsername, FieldPassword}, fieldsSNMP), Hint: "Requires the pfSense-pkg-RESTAPI package (v2)",
		factory: func(t Target, c Credentials, v string) Driver { return NewPfsense(t, c, v) }, caps: fixed(PfsenseCaps)},
	{Key: "openwrt", Vendor: "OpenWrt", Title: "OpenWrt (GL.iNet, Turris, Cudy, etc.)", Segment: "home", Kind: "router",
		Transports: []Transport{{"ssh", 22}, {"snmp", 161}}, Credentials: join(fieldsSSH, fieldsSNMP),
		Hint:    "SSH (dropbear); flow export needs the softflowd package",
		factory: func(t Target, c Credentials, v string) Driver { return NewOpenWrt(t, c, v) }, caps: fixed(OpenWrtCaps)},
	{Key: "keenetic", Vendor: "Keenetic", Title: "Keenetic", Segment: "home", Kind: "router",
		Transports: []Transport{{"http", 80}, {"https", 443}}, Credentials: []string{FieldUsername, FieldPassword},
		Hint:    "A user with web interface and RCI rights",
		factory: func(t Target, c Credentials, v string) Driver { return NewKeenetic(t, c, v) }, caps: fixed(KeeneticCaps)},
	cliPlatform("cisco_ios", "Cisco", "Cisco IOS / IOS-XE (Catalyst, ISR, ASR)", "enterprise", "switch", "cisco_ios", ""),
	cliPlatform("cisco_nxos", "Cisco", "Cisco NX-OS (Nexus)", "enterprise", "switch", "cisco_nxos", ""),
	{Key: "meraki", Vendor: "Cisco", Title: "Cisco Meraki Dashboard", Segment: "enterprise", Kind: "controller",
		Transports: []Transport{{"https", 443}}, Credentials: []string{FieldAPIKey},
		Hint:    "Host api.meraki.com; the Site field is the organization ID or name",
		factory: func(t Target, c Credentials, v string) Driver { return NewMeraki(t, c, v) }, caps: fixed(MerakiCaps)},
	{Key: "unifi", Vendor: "Ubiquiti", Title: "Ubiquiti UniFi Network (UDM, UCG, Cloud Key, controller)", Segment: "smb", Kind: "controller",
		Transports: []Transport{{"https", 443}}, Credentials: []string{FieldUsername, FieldPassword, FieldAPIKey},
		Hint:    "Local console user; a self-hosted controller uses port 8443; Site is default or the site name",
		factory: func(t Target, c Credentials, v string) Driver { return NewUnifi(t, c, v) }, caps: fixed(ControllerCaps)},
	{Key: "edgeos", Vendor: "Ubiquiti", Title: "Ubiquiti EdgeRouter / VyOS", Segment: "smb", Kind: "router",
		Transports: []Transport{{"ssh", 22}, {"snmp", 161}}, Credentials: join(fieldsSSH, fieldsSNMP),
		factory: func(t Target, c Credentials, v string) Driver { return NewLinux(t, c, v) }, caps: fixed(LinuxCaps)},
	cliPlatform("zyxel", "Zyxel", "Zyxel (GS / XGS / XS switches, USG / ATP / USG FLEX)", "smb", "switch", "zyxel", ""),
	cliPlatform("aruba_os", "HP", "HP ProCurve / HPE Aruba ArubaOS-Switch", "enterprise", "switch", "aruba_os", ""),
	cliPlatform("aruba_cx", "HPE Aruba", "HPE Aruba AOS-CX", "enterprise", "switch", "aruba_cx", ""),
	cliPlatform("hp_comware", "HPE", "HPE FlexNetwork / OfficeConnect / H3C (Comware)", "enterprise", "switch", "hp_comware", ""),
	cliPlatform("dell_os10", "Dell", "Dell EMC PowerSwitch (OS10)", "enterprise", "switch", "dell_os10", ""),
	cliPlatform("dell_nseries", "Dell", "Dell PowerSwitch N / PowerConnect", "smb", "switch", "dell_nseries", ""),
	{Key: "juniper", Vendor: "Juniper", Title: "Juniper Junos (EX, SRX, MX, QFX)", Segment: "enterprise", Kind: "router",
		Transports: []Transport{{"ssh", 22}, {"snmp", 161}}, Credentials: join(fieldsSSH, fieldsSNMP),
		factory: func(t Target, c Credentials, v string) Driver { return NewJunos(t, c, v) }, caps: fixed(JunosCaps)},
	cliPlatform("huawei", "Huawei", "Huawei VRP (S / CE / AR)", "enterprise", "switch", "huawei_vrp", ""),
	{Key: "fortigate", Vendor: "Fortinet", Title: "Fortinet FortiGate", Segment: "enterprise", Kind: "firewall",
		Transports: []Transport{{"https", 443}, {"snmp", 161}}, Credentials: join([]string{FieldAPIKey}, fieldsSNMP),
		Hint:    "REST API administrator: API token",
		factory: func(t Target, c Credentials, v string) Driver { return NewFortigate(t, c, v) }, caps: fixed(FortigateCaps)},
	cliPlatform("eltex", "Eltex", "Eltex MES", "enterprise", "switch", "eltex", ""),
	{Key: "redfish", Vendor: "Redfish", Title: "Servers: Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro (Redfish)", Segment: "enterprise",
		Kind: "server", Transports: []Transport{{"https", 443}}, Credentials: []string{FieldUsername, FieldPassword},
		factory: func(t Target, c Credentials, v string) Driver { return NewRedfish(t, c, v) }, caps: fixed(RedfishCaps)},
	{Key: "linux", Vendor: "Linux", Title: "Linux / Proxmox / Synology / ASUS Merlin (SSH)", Segment: "any", Kind: "server",
		Transports: []Transport{{"ssh", 22}, {"snmp", 161}}, Credentials: join(fieldsSSH, fieldsSNMP),
		factory: func(t Target, c Credentials, v string) Driver { return NewLinux(t, c, v) }, caps: fixed(LinuxCaps)},
	snmpPlatform("netgear", "Netgear", "Netgear (SNMP)", "smb", "switch", ""),
	snmpPlatform("dlink", "D-Link", "D-Link (SNMP)", "smb", "switch", ""),
	snmpPlatform("snmp", "", "Any device (SNMP v1 / v2c / v3)", "any", "other", "Standard MIBs: interfaces, LLDP, ARP, MAC table"),
	{Key: "gnmi", Vendor: "", Title: "Any device (gNMI, OpenConfig)", Segment: "enterprise", Kind: "other",
		Transports: []Transport{{"gnmi", 0}}, Credentials: []string{}, native: "gnmi",
		Hint:    "Interfaces over gNMI with the gNMI profile of Flow that covers the address (Settings → Interface names)",
		factory: func(t Target, c Credentials, v string) Driver { return NewGNMI(t, c, v) }, caps: fixed(nil)},
}

var byKey = func() map[string]*Platform {
	m := map[string]*Platform{}
	for _, p := range Platforms {
		m[p.Key] = p
	}
	return m
}()

// Lookup returns a platform by key.
func Lookup(key string) (*Platform, error) {
	if p, ok := byKey[key]; ok {
		return p, nil
	}
	return nil, Errorf("Unknown platform %s", key)
}

// ---------------- gNMI ----------------

// GNMIDriver reads OpenConfig interfaces through Flow's gNMI profiles.
type GNMIDriver struct{ base }

// NewGNMI returns the driver.
func NewGNMI(t Target, c Credentials, vendor string) *GNMIDriver {
	return &GNMIDriver{base{t, c, vendor}}
}

// Collect implements Driver.
func (d *GNMIDriver) Collect(ctx context.Context) (*Snapshot, error) {
	if d.c.GNMI == nil {
		return nil, Errorf("%s: no gNMI profile of Flow covers this address (Settings → Interface names → gNMI)", d.t.Host)
	}
	ifs, err := d.c.GNMI(ctx)
	if err != nil {
		return nil, Errorf("%s: gNMI: %v", d.t.Host, err)
	}
	return &Snapshot{Facts: Facts{Vendor: d.vendor, OS: "gNMI"}, Interfaces: ifs}, nil
}
