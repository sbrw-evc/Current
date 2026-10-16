// Package drivers talks to managed network equipment: one driver per vendor
// family turns its REST API, CLI over SSH, SNMP or gNMI answers into the same
// Snapshot (facts, interfaces with counters, LLDP / CDP / MNDP neighbours,
// clients from ARP, DHCP, Wi-Fi and MAC tables, devices behind a controller)
// and applies the same small set of settings (Actions). Parameters of the
// settings end up in vendor commands, so ValidateAction checks them once,
// strictly, for every vendor.
//
// The registry (registry.go) lists the supported platforms with their
// transports, credential fields and capabilities.
package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Facts are the identity and health of a device.
type Facts struct {
	Hostname      string         `json:"hostname"`
	Vendor        string         `json:"vendor"`
	Model         string         `json:"model"`
	OS            string         `json:"os"`
	Version       string         `json:"version"`
	Serial        string         `json:"serial"`
	MAC           string         `json:"mac"`
	UptimeSeconds *int64         `json:"uptime_seconds"`
	CPUPercent    *float64       `json:"cpu_percent"`
	MemoryPercent *float64       `json:"memory_percent"`
	Extra         map[string]any `json:"extra,omitempty"`
}

// Interface is a port, a VLAN interface, a bridge or a tunnel.
type Interface struct {
	Name        string   `json:"name"`
	Index       *int64   `json:"index"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	MAC         string   `json:"mac"`
	AdminUp     *bool    `json:"admin_up"`
	OperUp      *bool    `json:"oper_up"`
	SpeedMbps   *int64   `json:"speed_mbps"`
	MTU         *int64   `json:"mtu"`
	Addresses   []string `json:"addresses"`
	RxBytes     *uint64  `json:"rx_bytes"`
	TxBytes     *uint64  `json:"tx_bytes"`
	VLAN        *int64   `json:"vlan"`
}

// Neighbor is a device seen over LLDP, CDP or MNDP on a local port.
type Neighbor struct {
	LocalInterface  string `json:"local_interface"`
	RemoteName      string `json:"remote_name"`
	RemoteIP        string `json:"remote_ip"`
	RemoteMAC       string `json:"remote_mac"`
	RemoteInterface string `json:"remote_interface"`
	RemotePlatform  string `json:"remote_platform"`
	Protocol        string `json:"protocol"` // lldp | cdp | mndp | controller
}

// Endpoint sources, from the least to the most specific attachment point.
const (
	SourceARP        = "arp"
	SourceDHCP       = "dhcp"
	SourceBridge     = "bridge"
	SourceController = "controller"
	SourceWiFi       = "wifi"
)

// Endpoint is a consumer seen by the device: a host in ARP, a DHCP lease, a
// Wi-Fi client, a MAC learned on a port, a client of a controller.
type Endpoint struct {
	MAC        string   `json:"mac"`
	IP         string   `json:"ip"`
	Hostname   string   `json:"hostname"`
	Interface  string   `json:"interface"`
	Source     string   `json:"source"`
	SSID       string   `json:"ssid"`
	Signal     *int64   `json:"signal"`
	VLAN       *int64   `json:"vlan"`
	AttachedTo string   `json:"attached_to"` // controllers: MAC of the AP / switch the client is on
	Port       string   `json:"port"`
	RxRate     *float64 `json:"rx_rate"`
	TxRate     *float64 `json:"tx_rate"`
	Blocked    bool     `json:"blocked"`
}

// Child is a device managed by a controller (Omada, UniFi, Meraki, CAPsMAN).
type Child struct {
	MAC        string `json:"mac"`
	Name       string `json:"name"`
	Model      string `json:"model"`
	Kind       string `json:"kind"` // ap | switch | gateway | other
	IP         string `json:"ip"`
	Online     bool   `json:"online"`
	Version    string `json:"version"`
	UplinkMAC  string `json:"uplink_mac"`
	UplinkPort string `json:"uplink_port"`
	Clients    *int64 `json:"clients"`
}

// Snapshot is everything one poll collects.
type Snapshot struct {
	Facts      Facts       `json:"facts"`
	Interfaces []Interface `json:"interfaces"`
	Neighbors  []Neighbor  `json:"neighbors"`
	Endpoints  []Endpoint  `json:"endpoints"`
	Children   []Child     `json:"children"`
}

// Target is where and how to reach a device.
type Target struct {
	Host       string
	Port       int    // 0 = the default port of the transport
	Transport  string // api | ssh | snmp | https | http | gnmi
	VerifyTLS  bool
	Site       string // controllers: site / organisation
	SSHHostKey string // pinned key (authorized_keys format), "" = trust on first use
	// Timeout of one request (HTTP, SNMP); 0 = the driver's default.
	Timeout time.Duration
}

// Credentials of a device; secrets are resolved from OpenBao by the caller.
type Credentials struct {
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
	APISecret      string `json:"api_secret,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	EnablePassword string `json:"enable_password,omitempty"`

	SNMPVersion      string `json:"snmp_version,omitempty"` // 1 | 2c | 3
	SNMPCommunity    string `json:"snmp_community,omitempty"`
	SNMPUser         string `json:"snmp_user,omitempty"`
	SNMPAuthProtocol string `json:"snmp_auth_protocol,omitempty"`
	SNMPAuthPassword string `json:"snmp_auth_password,omitempty"`
	SNMPPrivProtocol string `json:"snmp_priv_protocol,omitempty"`
	SNMPPrivPassword string `json:"snmp_priv_password,omitempty"`
	SNMPContext      string `json:"snmp_context,omitempty"`

	// GNMI reads the OpenConfig interfaces with the gNMI profile of Current
	// that covers the device (set by the caller for the gnmi transport).
	GNMI func(ctx context.Context) ([]Interface, error) `json:"-"`
}

// Credential fields shown in the forms.
const (
	FieldUsername         = "username"
	FieldPassword         = "password"
	FieldAPIKey           = "api_key"
	FieldAPISecret        = "api_secret"
	FieldPrivateKey       = "private_key"
	FieldEnablePassword   = "enable_password"
	FieldSNMPVersion      = "snmp_version"
	FieldSNMPCommunity    = "snmp_community"
	FieldSNMPUser         = "snmp_user"
	FieldSNMPAuthProtocol = "snmp_auth_protocol"
	FieldSNMPAuthPassword = "snmp_auth_password"
	FieldSNMPPrivProtocol = "snmp_priv_protocol"
	FieldSNMPPrivPassword = "snmp_priv_password"
)

// SecretFields are the credential fields kept only in OpenBao; the API
// tells only whether they are set.
var SecretFields = []string{FieldPassword, FieldAPIKey, FieldAPISecret, FieldPrivateKey, FieldEnablePassword,
	FieldSNMPCommunity, FieldSNMPAuthPassword, FieldSNMPPrivPassword}

// PlainFields are the non-secret credential fields (returned by the API).
var PlainFields = []string{FieldUsername, FieldSNMPVersion, FieldSNMPUser, FieldSNMPAuthProtocol, FieldSNMPPrivProtocol}

// IsSecret reports whether a credential field is a secret.
func IsSecret(field string) bool {
	for _, f := range SecretFields {
		if f == field {
			return true
		}
	}
	return false
}

// Fields maps credential field names to the struct (for the service).
func (c *Credentials) Fields() map[string]*string {
	return map[string]*string{
		FieldUsername: &c.Username, FieldPassword: &c.Password, FieldAPIKey: &c.APIKey, FieldAPISecret: &c.APISecret,
		FieldPrivateKey: &c.PrivateKey, FieldEnablePassword: &c.EnablePassword, FieldSNMPVersion: &c.SNMPVersion,
		FieldSNMPCommunity: &c.SNMPCommunity, FieldSNMPUser: &c.SNMPUser, FieldSNMPAuthProtocol: &c.SNMPAuthProtocol,
		FieldSNMPAuthPassword: &c.SNMPAuthPassword, FieldSNMPPrivProtocol: &c.SNMPPrivProtocol,
		FieldSNMPPrivPassword: &c.SNMPPrivPassword,
	}
}

// Actions, in display order.
const (
	ActionHostname      = "hostname"
	ActionInterface     = "interface"
	ActionDNS           = "dns"
	ActionNTP           = "ntp"
	ActionFlowExport    = "flow_export"
	ActionReboot        = "reboot"
	ActionEndpointBlock = "endpoint_block"
	ActionCommand       = "command"
	ActionBackup        = "backup"
)

// Actions lists every setting a driver may support.
var Actions = []string{ActionHostname, ActionInterface, ActionDNS, ActionNTP, ActionFlowExport, ActionReboot,
	ActionEndpointBlock, ActionCommand, ActionBackup}

// ActionTitles are the English names of the actions.
var ActionTitles = map[string]string{
	ActionHostname: "Device name", ActionInterface: "Interface state / description", ActionDNS: "DNS servers",
	ActionNTP: "NTP servers", ActionFlowExport: "NetFlow / IPFIX / sFlow export to a collector", ActionReboot: "Reboot",
	ActionEndpointBlock: "Client blocking", ActionCommand: "Custom CLI command", ActionBackup: "Configuration backup",
}

// Params are the parameters of an action (fields unused by an action are ignored).
type Params struct {
	Name        string   `json:"name,omitempty"`        // hostname, interface
	Enabled     *bool    `json:"enabled,omitempty"`     // interface, flow_export
	Description *string  `json:"description,omitempty"` // interface
	Servers     []string `json:"servers,omitempty"`     // dns, ntp
	Collector   string   `json:"collector,omitempty"`   // flow_export
	Port        int      `json:"port,omitempty"`        // flow_export
	Protocol    string   `json:"protocol,omitempty"`    // flow_export: netflow5 | netflow9 | ipfix | sflow
	Interfaces  []string `json:"interfaces,omitempty"`  // flow_export (Cisco IOS)
	MAC         string   `json:"mac,omitempty"`         // endpoint_block; reboot of a controller child
	Blocked     *bool    `json:"blocked,omitempty"`     // endpoint_block
	Command     string   `json:"command,omitempty"`     // command
}

// IsEnabled is Enabled with a default.
func (p Params) IsEnabled(def bool) bool {
	if p.Enabled == nil {
		return def
	}
	return *p.Enabled
}

// IsBlocked is Blocked, true by default.
func (p Params) IsBlocked() bool { return p.Blocked == nil || *p.Blocked }

// Error is a message meant for the user (a wrong parameter, an unreachable
// device, a refused login).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Errorf returns an *Error.
func Errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// ErrUnsupported marks an action a driver does not implement.
var ErrUnsupported = errors.New("not supported")

// Unsupported is the error of an action a driver does not implement.
func Unsupported(vendor, action string) error {
	title := ActionTitles[action]
	if title == "" {
		title = action
	}
	return fmt.Errorf("%w: %s: action '%s'", ErrUnsupported, vendor, title)
}

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,62}$`)
	ifaceRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:\- ]{0,63}$`)
	descRe   = regexp.MustCompile("^[^\"'`$;|&<>\\\\\r\n]{0,120}$")
	serverRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$`)
)

// Flow export protocols.
var FlowProtocols = []string{"netflow5", "netflow9", "ipfix", "sflow"}

// ValidateAction checks and normalises the parameters of an action. Values
// end up in vendor commands, so they are strict.
func ValidateAction(action string, p Params) (Params, error) {
	known := false
	for _, a := range Actions {
		known = known || a == action
	}
	if !known {
		return p, Errorf("Unknown action %s", action)
	}
	switch action {
	case ActionHostname:
		if !nameRe.MatchString(p.Name) {
			return p, Errorf("Name: Latin letters, digits, '.', '_', '-', up to 63 characters")
		}
	case ActionInterface:
		if !ifaceRe.MatchString(p.Name) {
			return p, Errorf("Invalid interface name")
		}
		if p.Description != nil && !descRe.MatchString(*p.Description) {
			return p, Errorf("Description: up to 120 characters, no quotes or special characters")
		}
		if p.Enabled == nil && p.Description == nil {
			return p, Errorf("Specify the interface state or description")
		}
	case ActionDNS, ActionNTP:
		var servers []string
		for _, s := range p.Servers {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		if len(servers) == 0 || len(servers) > 4 {
			return p, Errorf("Specify 1 to 4 servers")
		}
		for _, s := range servers {
			if NormIP(s) == "" && !serverRe.MatchString(s) {
				return p, Errorf("'%s' is neither an address nor a host name", s)
			}
		}
		p.Servers = servers
	case ActionFlowExport:
		ip := NormIP(p.Collector)
		if ip == "" {
			return p, Errorf("The collector address must be an IP address")
		}
		p.Collector = ip
		if p.Port == 0 {
			p.Port = 2055
		}
		if p.Port < 1 || p.Port > 65535 {
			return p, Errorf("Invalid collector port")
		}
		if p.Protocol == "" {
			p.Protocol = "netflow9"
		}
		ok := false
		for _, f := range FlowProtocols {
			ok = ok || f == p.Protocol
		}
		if !ok {
			return p, Errorf("Protocol: netflow5, netflow9, ipfix or sflow")
		}
		on := p.IsEnabled(true)
		p.Enabled = &on
		var ifs []string
		for _, i := range p.Interfaces {
			if i = strings.TrimSpace(i); i == "" {
				continue
			}
			if !ifaceRe.MatchString(i) {
				return p, Errorf("Invalid interface name")
			}
			ifs = append(ifs, i)
		}
		p.Interfaces = ifs
	case ActionEndpointBlock:
		p.MAC = NormMAC(p.MAC)
		if p.MAC == "" {
			return p, Errorf("Invalid MAC address")
		}
		b := p.IsBlocked()
		p.Blocked = &b
	case ActionCommand:
		p.Command = strings.TrimSpace(p.Command)
		if p.Command == "" || len(p.Command) > 2000 {
			return p, Errorf("The command is empty or too long")
		}
	case ActionReboot:
		if p.MAC != "" {
			if p.MAC = NormMAC(p.MAC); p.MAC == "" {
				return p, Errorf("Invalid MAC address")
			}
		}
	}
	return p, nil
}

var nonHex = regexp.MustCompile(`[^0-9a-fA-F]`)

// NormMAC turns any MAC notation (aa-bb-.., aabb.ccdd.eeff, AABBCCDDEEFF)
// into aa:bb:cc:dd:ee:ff; "" when it is not a MAC.
func NormMAC(v string) string {
	if v == "" {
		return ""
	}
	h := nonHex.ReplaceAllString(v, "")
	if len(h) != 12 {
		return ""
	}
	h = strings.ToLower(h)
	return h[0:2] + ":" + h[2:4] + ":" + h[4:6] + ":" + h[6:8] + ":" + h[8:10] + ":" + h[10:12]
}

// macToken reports whether a whole token is a MAC (stricter than NormMAC:
// the separators must be regular).
var macToken = regexp.MustCompile(`(?i)^([0-9a-f]{2}[:\-.]?){5}[0-9a-f]{2}$|^([0-9a-f]{4}\.){2}[0-9a-f]{4}$|^([0-9a-f]{4}-){2}[0-9a-f]{4}$`)

// MACToken returns the normalised MAC when the token is one.
func MACToken(t string) string {
	if !macToken.MatchString(t) {
		return ""
	}
	return NormMAC(t)
}

// NormIP returns the canonical text of an address ("" when not one); a
// prefix length or zone is dropped.
func NormIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v, _, _ = strings.Cut(v, "/")
	v, _, _ = strings.Cut(v, "%")
	a, err := netip.ParseAddr(v)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// P returns a pointer to v.
func P[T any](v T) *T { return &v }

// ToInt parses a number from a JSON value or text ("7", "7.5", 7).
func ToInt(v any) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case bool:
		return 0, false
	case string:
		s := strings.TrimSpace(x)
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f), true
		}
		return 0, false
	}
	return ToInt(fmt.Sprint(v))
}

// IntP is ToInt as a pointer (nil when not a number).
func IntP(v any) *int64 {
	if n, ok := ToInt(v); ok {
		return &n
	}
	return nil
}

// UintP is a non-negative counter as a pointer.
func UintP(v any) *uint64 {
	if s, ok := v.(string); ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
			return &n
		}
	}
	if n, ok := ToInt(v); ok && n >= 0 {
		u := uint64(n)
		return &u
	}
	return nil
}

// ToBool reads true / yes / 1 / up / on / enabled / running.
func ToBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case nil:
		return false
	case float64:
		return x == 1
	}
	switch strings.ToLower(strings.TrimSpace(fmt.Sprint(v))) {
	case "true", "yes", "1", "up", "on", "enabled", "running":
		return true
	}
	return false
}

// Str is the text of a JSON value ("" for null).
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// Obj is a JSON object.
type Obj = map[string]any

// S returns the first non-empty text among the keys of o.
func S(o Obj, keys ...string) string {
	for _, k := range keys {
		if s := Str(o[k]); s != "" {
			return s
		}
	}
	return ""
}

// O returns o[key] as an object (empty when it is not one).
func O(o Obj, key string) Obj {
	if m, ok := o[key].(map[string]any); ok {
		return m
	}
	return Obj{}
}

// L returns v as a list of objects.
func L(v any) []Obj {
	arr, ok := v.([]any)
	if !ok {
		if m, ok := v.(map[string]any); ok {
			return []Obj{m}
		}
		return nil
	}
	out := make([]Obj, 0, len(arr))
	for _, x := range arr {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Percent rounds a share to one decimal.
func Percent(part, total float64) *float64 {
	if total <= 0 {
		return nil
	}
	v := float64(int64(part*1000/total+0.5)) / 10
	return &v
}

// MaskBits converts a dotted mask or a number of bits.
func MaskBits(mask string) int {
	mask = strings.TrimSpace(mask)
	if !strings.Contains(mask, ".") {
		if n, err := strconv.Atoi(mask); err == nil {
			return n
		}
		return 32
	}
	a, err := netip.ParseAddr(mask)
	if err != nil || !a.Is4() {
		return 32
	}
	b := a.As4()
	n := 0
	for _, x := range b {
		for ; x != 0; x &= x - 1 {
			n++
		}
	}
	return n
}
