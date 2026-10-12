package apps

import "testing"

func TestLookup(t *testing.T) {
	tb := Default()
	cases := []struct {
		proto        uint8
		sport, dport uint16
		want         string
	}{
		{ProtoTCP, 51515, 443, "https"},
		{ProtoTCP, 443, 51515, "https"},
		{ProtoUDP, 443, 51515, "quic"},
		{ProtoUDP, 40000, 53, "dns"},
		{ProtoTCP, 40000, 53, "dns"},
		{ProtoUDP, 123, 123, "ntp"},
		{ProtoTCP, 22, 60000, "ssh"},
		{ProtoTCP, 50000, 5432, "postgres"},
		{ProtoTCP, 50000, 9092, "kafka"},
		{ProtoTCP, 50000, 6379, "redis"},
		{ProtoTCP, 50000, 1433, "mssql"},
		{ProtoTCP, 50000, 3306, "mysql"},
		{ProtoTCP, 179, 50000, "bgp"},
		{ProtoUDP, 50000, 514, "syslog"},
		{ProtoUDP, 50000, 161, "snmp"},
		{ProtoTCP, 50000, 3389, "rdp"},
		{ProtoTCP, 50000, 993, "imaps"},
		{ProtoTCP, 50000, 389, "ldap"},
		{ProtoTCP, 25, 50000, "smtp"},
		{ProtoTCP, 80, 8080, "http"},
		{ProtoTCP, 0, 8080, "http-alt"},
		{ProtoTCP, 40000, 40001, ""},
		{ProtoICMP, 0, 0, "icmp"},
		{ProtoICMPv6, 0, 0, "icmp"},
		{ProtoESP, 0, 0, "ipsec"},
		{89, 0, 0, ""},
	}
	for _, c := range cases {
		if got := tb.Lookup(c.proto, c.sport, c.dport); got != c.want {
			t.Errorf("Lookup(%d, %d, %d) = %q, want %q", c.proto, c.sport, c.dport, got, c.want)
		}
	}
	custom := New(Service{ProtoTCP, 40001, "my-app"}, Service{ProtoTCP, 443, "web"})
	if got := custom.Lookup(ProtoTCP, 40000, 40001); got != "my-app" {
		t.Errorf("custom = %q", got)
	}
	if got := custom.Lookup(ProtoTCP, 50000, 443); got != "web" {
		t.Errorf("override = %q", got)
	}
}

func TestServer(t *testing.T) {
	tb := Default()
	if !tb.Server(ProtoTCP, 50000, 443) || tb.Server(ProtoTCP, 443, 50000) || !tb.Server(ProtoTCP, 50001, 50000) {
		t.Fatal("server heuristic")
	}
	if ProtoName(6) != "tcp" || ProtoName(200) != "200" {
		t.Fatal("ProtoName")
	}
}

func BenchmarkLookup(b *testing.B) {
	tb := Default()
	for b.Loop() {
		tb.Lookup(ProtoTCP, 51515, 443)
	}
}
