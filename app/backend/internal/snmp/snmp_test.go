package snmp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// agent is a tiny SNMPv2c responder for GET-NEXT / GET-BULK over a fixed
// table, enough for gosnmp's BulkWalkAll.
type agent struct {
	conn      *net.UDPConn
	community string
	oids      []string // sorted
	vals      map[string]gosnmp.SnmpPDU
}

func oidLess(a, b string) bool {
	pa, pb := strings.Split(strings.Trim(a, "."), "."), strings.Split(strings.Trim(b, "."), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.ParseUint(pa[i], 10, 64)
		y, _ := strconv.ParseUint(pb[i], 10, 64)
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func newAgent(t *testing.T, community string, pdus []gosnmp.SnmpPDU) *agent {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{conn: c, community: community, vals: map[string]gosnmp.SnmpPDU{}}
	for _, p := range pdus {
		a.oids = append(a.oids, p.Name)
		a.vals[p.Name] = p
	}
	slices.SortFunc(a.oids, func(x, y string) int {
		if oidLess(x, y) {
			return -1
		}
		if x == y {
			return 0
		}
		return 1
	})
	go a.serve()
	t.Cleanup(func() { _ = c.Close() })
	return a
}

func (a *agent) port() uint16 { return uint16(a.conn.LocalAddr().(*net.UDPAddr).Port) }

func (a *agent) next(oid string) (gosnmp.SnmpPDU, bool) {
	for _, o := range a.oids {
		if oidLess(oid, o) {
			return a.vals[o], true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

func (a *agent) serve() {
	buf := make([]byte, 65535)
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: a.community, Logger: gosnmp.NewLogger(nil)}
	for {
		n, from, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, err := dec.SnmpDecodePacket(buf[:n])
		if err != nil || req.Community != a.community {
			continue // wrong community: no answer, like a real agent
		}
		resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: a.community, PDUType: gosnmp.GetResponse,
			RequestID: req.RequestID}
		reps := 1
		if req.PDUType == gosnmp.GetBulkRequest {
			reps = int(req.MaxRepetitions)
		}
		for _, v := range req.Variables {
			cur := v.Name
			for i := 0; i < reps; i++ {
				p, ok := a.next(cur)
				if !ok {
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: cur, Type: gosnmp.EndOfMibView})
					break
				}
				resp.Variables = append(resp.Variables, p)
				cur = p.Name
			}
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteToUDP(out, from)
	}
}

func ifTable() []gosnmp.SnmpPDU {
	s := func(oid string, v string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(v)}
	}
	g := func(oid string, v uint) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Gauge32, Value: v}
	}
	return []gosnmp.SnmpPDU{
		s(oidIfDescr+".1", "GigabitEthernet0/0/0"), s(oidIfDescr+".2", "TenGigE0/1/0"), s(oidIfDescr+".3", "Null0"),
		g(oidIfSpeed+".1", 1_000_000_000), g(oidIfSpeed+".2", 4294967295), g(oidIfSpeed+".3", 0),
		s(oidIfName+".1", "Gi0/0/0"), s(oidIfName+".2", "Te0/1/0"),
		g(oidIfHighSpeed+".1", 1000), g(oidIfHighSpeed+".2", 10000),
		s(oidIfAlias+".1", "uplink to ISP-A"), s(oidIfAlias+".2", ""),
		// a column outside the walked ones, after them in OID order
		s(".1.3.6.1.2.1.31.1.1.1.19.1", "x"),
	}
}

func TestDecodeIfTable(t *testing.T) {
	got := DecodeIfTable(ifTable())
	want := map[uint32]Interface{
		1: {Name: "Gi0/0/0", Descr: "uplink to ISP-A", Speed: 1_000_000_000},
		2: {Name: "Te0/1/0", Speed: 10_000_000_000},
		3: {Name: "Null0"},
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ifIndex %d = %+v, want %+v", k, got[k], v)
		}
	}
}

func settings2c(port uint16, prefixes ...string) Settings {
	return Settings{Enabled: true, PollExporters: true, TimeoutSeconds: 1, Retries: 0,
		Profiles: []Profile{{ID: "lab", Name: "lab", Version: Version2c, Port: port, Prefixes: prefixes, CommunityRef: "openbao://flow/snmp/lab/community#value"}}}
}

func resolver(m map[string]string) Resolver {
	return func(ref string) (string, error) {
		if v, ok := m[ref]; ok {
			return v, nil
		}
		return "", errors.New("not found")
	}
}

func TestPollerWithFakeAgent(t *testing.T) {
	ag := newAgent(t, "s3cret", ifTable())
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := resolver(map[string]string{"openbao://flow/snmp/lab/community#value": "s3cret"})
	if err := p.Apply(settings2c(ag.port(), "127.0.0.0/8"), res); err != nil {
		t.Fatal(err)
	}
	lo := netip.MustParseAddr("127.0.0.1")

	// Direct poll.
	ifs, prof, err := p.Poll(context.Background(), lo)
	if err != nil {
		t.Fatal(err)
	}
	if prof != "lab" || ifs[2].Speed != 10_000_000_000 || ifs[1].Descr != "uplink to ISP-A" {
		t.Fatalf("poll = %q %+v", prof, ifs)
	}

	// The enricher's first lookup misses and schedules a poll.
	if _, _, _, ok := p.Lookup(netip.MustParseAddr("::ffff:127.0.0.1"), 1); ok {
		t.Fatal("hit before poll")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		name, descr, speed, ok := p.Lookup(lo, 1)
		if ok {
			if name != "Gi0/0/0" || descr != "uplink to ISP-A" || speed != 1e9 {
				t.Fatalf("lookup = %q %q %d", name, descr, speed)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no data after poll: %+v", p.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := p.Status()
	if len(st) != 1 || st[0].Interfaces != 3 || st[0].Polled == nil || st[0].Error != "" {
		t.Fatalf("status %+v", st)
	}

	// Addresses outside every profile are not polled.
	if _, _, err := p.Poll(context.Background(), netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("poll without profile")
	}

	// Wrong community: timeout error.
	bad := resolver(map[string]string{"openbao://flow/snmp/lab/community#value": "wrong"})
	if err := p.Apply(settings2c(ag.port()), bad); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Poll(context.Background(), lo); err == nil {
		t.Fatal("poll with a wrong community succeeded")
	}

	// Disabled: no answers.
	s := settings2c(ag.port())
	s.Enabled = false
	_ = p.Apply(s, res)
	if _, _, _, ok := p.Lookup(lo, 1); ok {
		t.Fatal("lookup while disabled")
	}
}

func TestNormalize(t *testing.T) {
	cases := []Settings{
		{Profiles: []Profile{{ID: "a", Name: "a", Version: "1"}}},
		{Profiles: []Profile{{ID: "a", Name: "a", Version: Version3}}},
		{Profiles: []Profile{{ID: "a", Name: "a", Version: Version3, Username: "u", AuthProtocol: "SHA", PrivProtocol: "ROT13"}}},
		{Profiles: []Profile{{ID: "a", Name: "a", Version: Version2c}, {ID: "a", Name: "b", Version: Version2c}}},
		{Profiles: []Profile{{ID: "A/B", Name: "a", Version: Version2c}}},
		{Devices: []string{"router1"}},
		{IntervalMinutes: 60, TTLMinutes: 10},
	}
	for i, c := range cases {
		if _, err := c.Normalize(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	s, err := Settings{Devices: []string{"::ffff:10.0.0.1"}, Profiles: []Profile{{ID: "v3", Name: "v3", Version: Version3, Username: "flow",
		AuthProtocol: "SHA256", PrivProtocol: "AES"}}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if s.Devices[0] != "10.0.0.1" || s.Profiles[0].SecurityLevel != AuthPriv || s.Profiles[0].Port != 161 || s.IntervalMinutes != 30 {
		t.Fatalf("normalized %+v", s)
	}
	g, err := client(context.Background(), netip.MustParseAddr("10.0.0.1"), s.Profiles[0], Credentials{Auth: "a", Priv: "p"}, s)
	if err != nil {
		t.Fatal(err)
	}
	usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || usm.AuthenticationProtocol != gosnmp.SHA256 ||
		usm.PrivacyProtocol != gosnmp.AES || usm.UserName != "flow" {
		t.Fatalf("client %+v %+v", g, usm)
	}
}
