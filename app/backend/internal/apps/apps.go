// Package apps names the application of a flow from its protocol and ports
// using a compact table of well-known services.
package apps

import (
	"strconv"
	"sync"
)

// IP protocol numbers.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoGRE    = 47
	ProtoESP    = 50
	ProtoICMPv6 = 58
	ProtoSCTP   = 132
)

// Service is a well-known (proto, port) → name entry. Proto 0 means TCP and UDP.
type Service struct {
	Proto uint8
	Port  uint16
	Name  string
}

// Builtin is the default table.
var Builtin = []Service{
	{0, 20, "ftp-data"}, {ProtoTCP, 21, "ftp"}, {ProtoTCP, 22, "ssh"}, {ProtoTCP, 23, "telnet"},
	{ProtoTCP, 25, "smtp"}, {0, 49, "tacacs"}, {0, 53, "dns"}, {ProtoUDP, 67, "dhcp"}, {ProtoUDP, 68, "dhcp"},
	{ProtoUDP, 69, "tftp"}, {ProtoTCP, 80, "http"}, {0, 88, "kerberos"}, {ProtoTCP, 110, "pop3"},
	{ProtoUDP, 123, "ntp"}, {0, 135, "msrpc"}, {0, 137, "netbios"}, {0, 138, "netbios"}, {0, 139, "netbios"},
	{ProtoTCP, 143, "imap"}, {ProtoUDP, 161, "snmp"}, {ProtoUDP, 162, "snmp-trap"}, {ProtoTCP, 179, "bgp"},
	{0, 389, "ldap"}, {0, 443, "https"}, {ProtoTCP, 445, "smb"}, {ProtoUDP, 500, "ike"}, {ProtoUDP, 514, "syslog"},
	{ProtoTCP, 587, "smtp"}, {ProtoTCP, 636, "ldaps"}, {ProtoTCP, 853, "dns-over-tls"}, {ProtoTCP, 989, "ftps"},
	{ProtoTCP, 990, "ftps"}, {ProtoTCP, 993, "imaps"}, {ProtoTCP, 995, "pop3s"}, {ProtoUDP, 1194, "openvpn"},
	{ProtoTCP, 1433, "mssql"}, {ProtoTCP, 1521, "oracle"}, {ProtoUDP, 1812, "radius"}, {ProtoUDP, 1813, "radius"},
	{ProtoTCP, 1883, "mqtt"}, {ProtoUDP, 1900, "ssdp"}, {ProtoTCP, 2049, "nfs"}, {ProtoTCP, 2181, "zookeeper"},
	{ProtoUDP, 2055, "netflow"}, {ProtoTCP, 2375, "docker"}, {ProtoTCP, 2376, "docker"}, {ProtoTCP, 2379, "etcd"},
	{ProtoTCP, 3268, "ldap-gc"}, {ProtoTCP, 3269, "ldap-gc"}, {ProtoTCP, 3306, "mysql"}, {0, 3389, "rdp"},
	{ProtoUDP, 3478, "stun"}, {ProtoUDP, 4500, "ipsec-nat-t"}, {ProtoUDP, 4789, "vxlan"}, {ProtoTCP, 5044, "beats"},
	{0, 5060, "sip"}, {0, 5061, "sips"}, {ProtoTCP, 5222, "xmpp"}, {ProtoTCP, 5432, "postgres"},
	{ProtoTCP, 5671, "amqps"}, {ProtoTCP, 5672, "amqp"}, {0, 5353, "mdns"}, {ProtoUDP, 6343, "sflow"},
	{ProtoTCP, 5900, "vnc"}, {ProtoTCP, 5985, "winrm"}, {ProtoTCP, 5986, "winrm"}, {ProtoTCP, 6379, "redis"},
	{ProtoTCP, 6443, "kubernetes-api"}, {ProtoTCP, 6514, "syslog-tls"}, {ProtoTCP, 8080, "http-alt"},
	{ProtoTCP, 8443, "https-alt"}, {ProtoTCP, 8200, "openbao"}, {ProtoTCP, 8123, "clickhouse"}, {ProtoTCP, 9000, "clickhouse"},
	{ProtoTCP, 9092, "kafka"}, {ProtoTCP, 9090, "prometheus"}, {ProtoTCP, 9100, "node-exporter"},
	{ProtoTCP, 9200, "elasticsearch"}, {ProtoUDP, 9995, "netflow"}, {ProtoUDP, 9996, "netflow"}, {ProtoTCP, 4222, "nats"},
	{ProtoTCP, 11211, "memcached"}, {ProtoTCP, 27017, "mongodb"}, {ProtoTCP, 3000, "grafana"}, {ProtoTCP, 10050, "zabbix"},
	{ProtoTCP, 10051, "zabbix"}, {ProtoTCP, 830, "netconf"}, {ProtoTCP, 57400, "gnmi"}, {ProtoUDP, 4739, "ipfix"},
	{ProtoTCP, 4739, "ipfix"}, {ProtoUDP, 443, "quic"}, {ProtoTCP, 853, "dns-over-tls"},
}

// Table resolves application names. The zero value is not usable; use New.
type Table struct {
	tcp, udp, sctp [65536]string
}

// New builds a table from Builtin plus extra entries (extra wins).
func New(extra ...Service) *Table {
	t := &Table{}
	for _, list := range [][]Service{Builtin, extra} {
		for _, s := range list {
			switch s.Proto {
			case 0:
				t.tcp[s.Port], t.udp[s.Port], t.sctp[s.Port] = s.Name, s.Name, s.Name
			case ProtoTCP:
				t.tcp[s.Port] = s.Name
			case ProtoUDP:
				t.udp[s.Port] = s.Name
			case ProtoSCTP:
				t.sctp[s.Port] = s.Name
			}
		}
	}
	return t
}

var defaultTable = sync.OnceValue(func() *Table { return New() })

// Default returns the built-in table (built on first use).
func Default() *Table { return defaultTable() }

// Lookup names the application: the well-known port among src/dst (the
// lower one first, as the server side usually has the lower port), else
// protocol-level names for portless protocols, else "".
func (t *Table) Lookup(proto uint8, srcPort, dstPort uint16) string {
	var ports *[65536]string
	switch proto {
	case ProtoTCP:
		ports = &t.tcp
	case ProtoUDP:
		ports = &t.udp
	case ProtoSCTP:
		ports = &t.sctp
	case ProtoICMP, ProtoICMPv6:
		return "icmp"
	case ProtoGRE:
		return "gre"
	case ProtoESP:
		return "ipsec"
	default:
		return ""
	}
	lo, hi := srcPort, dstPort
	if lo > hi || lo == 0 {
		lo, hi = hi, lo
	}
	if lo != 0 {
		if n := ports[lo]; n != "" {
			return n
		}
	}
	if hi != 0 {
		if n := ports[hi]; n != "" {
			return n
		}
	}
	return ""
}

// Server returns which side is the server by the same heuristic: true when
// the destination is the server (its port is well-known, or lower).
func (t *Table) Server(proto uint8, srcPort, dstPort uint16) (dstIsServer bool) {
	var ports *[65536]string
	switch proto {
	case ProtoTCP:
		ports = &t.tcp
	case ProtoUDP:
		ports = &t.udp
	case ProtoSCTP:
		ports = &t.sctp
	default:
		return true
	}
	sk, dk := ports[srcPort] != "", ports[dstPort] != ""
	if sk != dk {
		return dk
	}
	return dstPort <= srcPort
}

// ProtoName returns the IANA keyword of common IP protocols, else the number.
func ProtoName(p uint8) string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoGRE:
		return "gre"
	case ProtoESP:
		return "esp"
	case 51:
		return "ah"
	case ProtoICMPv6:
		return "ipv6-icmp"
	case 89:
		return "ospf"
	case 103:
		return "pim"
	case 112:
		return "vrrp"
	case ProtoSCTP:
		return "sctp"
	case 2:
		return "igmp"
	}
	return strconv.Itoa(int(p))
}
