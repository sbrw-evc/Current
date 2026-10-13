package gnmi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeTarget is a gNMI server answering Get for the interface leaves the
// poller reads, the way devices do: some leaves as typed values, some as
// JSON_IETF scalars or {"module:leaf": value} objects.
type fakeTarget struct {
	gpb.UnimplementedGNMIServer
	user, password string
	rejectIETF     bool // answer InvalidArgument to JSON_IETF requests

	mu        sync.Mutex
	encodings []gpb.Encoding
}

func pathKey(p *gpb.Path) string {
	var parts []string
	for _, e := range p.GetElem() {
		parts = append(parts, e.GetName())
	}
	return strings.Join(parts, "/")
}

func ifElems(name string, rest ...string) []*gpb.PathElem {
	out := []*gpb.PathElem{elem("interface", "name", name)}
	for _, r := range rest {
		out = append(out, elem(r))
	}
	return out
}

func subElems(name, idx, leaf string) []*gpb.PathElem {
	return append(ifElems(name, "subinterfaces"), elem("subinterface", "index", idx), elem("state"), elem(leaf))
}

func ietf(s string) *gpb.TypedValue {
	return &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(s)}}
}
func uintV(n uint64) *gpb.TypedValue {
	return &gpb.TypedValue{Value: &gpb.TypedValue_UintVal{UintVal: n}}
}
func strV(s string) *gpb.TypedValue {
	return &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: s}}
}

func (f *fakeTarget) Get(ctx context.Context, req *gpb.GetRequest) (*gpb.GetResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if f.user != "" && (strings.Join(md.Get("username"), "") != f.user || strings.Join(md.Get("password"), "") != f.password) {
		return nil, status.Error(codes.Unauthenticated, "bad credentials")
	}
	f.mu.Lock()
	f.encodings = append(f.encodings, req.GetEncoding())
	f.mu.Unlock()
	if f.rejectIETF && req.GetEncoding() == gpb.Encoding_JSON_IETF {
		return nil, status.Error(codes.InvalidArgument, "unsupported encoding")
	}
	if len(req.GetPath()) != 1 || req.GetPath()[0].GetElem()[1].GetKey()["name"] != "*" {
		return nil, status.Error(codes.InvalidArgument, "one wildcard path expected")
	}
	type upd struct {
		elems []*gpb.PathElem
		val   *gpb.TypedValue
	}
	var ups []upd
	switch pathKey(req.GetPath()[0]) {
	case "interfaces/interface/state/ifindex":
		ups = []upd{
			{ifElems("Ethernet1", "state", "ifindex"), ietf("1")},
			{ifElems("Ethernet2", "state", "ifindex"), uintV(2)},
			{ifElems("Port-Channel1", "state", "ifindex"), ietf(`{"openconfig-interfaces:ifindex": 1000001}`)},
			{ifElems("Management1", "state", "ifindex"), strV("999999")},
		}
	case "interfaces/interface/state/description":
		ups = []upd{
			{ifElems("Ethernet1", "state", "description"), ietf(`"uplink to ISP-A"`)},
			{ifElems("Port-Channel1", "state", "description"), ietf(`{"openconfig-interfaces:description": "core LAG"}`)},
		}
	case "interfaces/interface/ethernet/state/port-speed":
		ups = []upd{
			{ifElems("Ethernet1", "ethernet", "state", "port-speed"), ietf(`"openconfig-if-ethernet:SPEED_100GB"`)},
			{ifElems("Ethernet2", "ethernet", "state", "port-speed"), strV("SPEED_10GB")},
			{ifElems("Management1", "ethernet", "state", "port-speed"), strV("SPEED_UNKNOWN")},
		}
	case "interfaces/interface/ethernet/state/negotiated-port-speed":
		return nil, status.Error(codes.NotFound, "no such path")
	case "interfaces/interface/aggregation/state/lag-speed":
		ups = []upd{{ifElems("Port-Channel1", "aggregation", "state", "lag-speed"), uintV(200000)}}
	case "interfaces/interface/subinterfaces/subinterface/state/ifindex":
		ups = []upd{
			{subElems("Ethernet1", "0", "ifindex"), ietf("1")}, // same as its interface
			{subElems("Ethernet1", "100", "ifindex"), ietf("501")},
		}
	case "interfaces/interface/subinterfaces/subinterface/state/description":
		ups = []upd{{subElems("Ethernet1", "100", "description"), strV("customer VLAN 100")}}
	default:
		return nil, status.Error(codes.NotFound, "no such path")
	}
	n := &gpb.Notification{Timestamp: time.Now().UnixNano(), Prefix: &gpb.Path{Elem: []*gpb.PathElem{elem("interfaces")}}}
	for _, u := range ups {
		n.Update = append(n.Update, &gpb.Update{Path: &gpb.Path{Elem: u.elems}, Val: u.val})
	}
	return &gpb.GetResponse{Notification: []*gpb.Notification{n}}, nil
}

// serve starts the fake target on a localhost port (TLS when cert is set).
func serve(t *testing.T, f *fakeTarget, cert *tls.Certificate) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opts []grpc.ServerOption
	if cert != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{*cert}})))
	}
	srv := grpc.NewServer(opts...)
	gpb.RegisterGNMIServer(srv, f)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func wantIfaces(t *testing.T, got map[uint32]Interface) {
	t.Helper()
	want := map[uint32]Interface{
		1:       {Name: "Ethernet1", Descr: "uplink to ISP-A", Speed: 100_000_000_000},
		2:       {Name: "Ethernet2", Speed: 10_000_000_000},
		1000001: {Name: "Port-Channel1", Descr: "core LAG", Speed: 200_000_000_000},
		999999:  {Name: "Management1"},
		501:     {Name: "Ethernet1.100", Descr: "customer VLAN 100", Speed: 100_000_000_000},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d interfaces: %+v", len(got), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ifindex %d = %+v, want %+v", k, got[k], v)
		}
	}
}

func resolver(m map[string]string) Resolver {
	return func(ref string) (string, error) {
		if v, ok := m[ref]; ok {
			return v, nil
		}
		return "", errors.New("not found")
	}
}

const pwRef = "openbao://flow/gnmi/lab/password#value"

func labSettings(port uint16, prefixes ...string) Settings {
	return Settings{Enabled: true, PollExporters: true, TimeoutSeconds: 2,
		Profiles: []Profile{{ID: "lab", Name: "lab", Port: port, Prefixes: prefixes, Username: "flow", PasswordRef: pwRef}}}
}

func TestPollerWithFakeTarget(t *testing.T) {
	f := &fakeTarget{user: "flow", password: "s3cret"}
	port := serve(t, f, nil)
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := resolver(map[string]string{pwRef: "s3cret"})
	if err := p.Apply(labSettings(port, "127.0.0.0/8"), res); err != nil {
		t.Fatal(err)
	}
	lo := netip.MustParseAddr("127.0.0.1")

	// Direct poll: TLS off, credentials in the metadata, JSON_IETF.
	ifs, prof, err := p.Poll(context.Background(), lo)
	if err != nil {
		t.Fatal(err)
	}
	if prof != "lab" {
		t.Fatal(prof)
	}
	wantIfaces(t, ifs)
	if f.encodings[0] != gpb.Encoding_JSON_IETF {
		t.Fatalf("encodings %v", f.encodings)
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
		name, descr, speed, ok := p.Lookup(lo, 501)
		if ok {
			if name != "Ethernet1.100" || descr != "customer VLAN 100" || speed != 100e9 {
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
	if len(st) != 1 || st[0].Interfaces != 5 || st[0].Polled == nil || st[0].Error != "" {
		t.Fatalf("status %+v", st)
	}

	// Addresses outside every profile are not polled.
	if _, _, err := p.Poll(context.Background(), netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("poll without profile")
	}

	// Wrong password: the target refuses.
	bad := resolver(map[string]string{pwRef: "wrong"})
	if err := p.Apply(labSettings(port), bad); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Poll(context.Background(), lo); err == nil || !strings.Contains(err.Error(), "Unauthenticated") {
		t.Fatalf("poll with a wrong password: %v", err)
	}
	// A user without a password is not even tried.
	if err := p.Apply(labSettings(port), resolver(nil)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Poll(context.Background(), lo); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("poll without the password: %v", err)
	}

	// Disabled: no answers.
	s := labSettings(port)
	s.Enabled = false
	_ = p.Apply(s, res)
	if _, _, _, ok := p.Lookup(lo, 1); ok {
		t.Fatal("lookup while disabled")
	}
}

func TestJSONFallback(t *testing.T) {
	f := &fakeTarget{rejectIETF: true}
	port := serve(t, f, nil)
	ifs, err := Get(context.Background(), netip.MustParseAddr("127.0.0.1"), Profile{Name: "x", Port: port}, Credentials{}, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	wantIfaces(t, ifs)
	if f.encodings[0] != gpb.Encoding_JSON_IETF || f.encodings[1] != gpb.Encoding_JSON || f.encodings[len(f.encodings)-1] != gpb.Encoding_JSON {
		t.Fatalf("encodings %v", f.encodings)
	}
}

// selfSigned returns a certificate for 127.0.0.1 and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "router"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"router.lab"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestTLS(t *testing.T) {
	cert, caPEM := selfSigned(t)
	port := serve(t, &fakeTarget{user: "flow", password: "pw"}, &cert)
	lo := netip.MustParseAddr("127.0.0.1")
	ctx := context.Background()
	base := Profile{Name: "tls", Port: port, Username: "flow", TLS: true}

	// Trusted through the CA of the profile, checked against the address or a name.
	if _, err := Get(ctx, lo, base, Credentials{Password: "pw", CA: caPEM}, Settings{}); err != nil {
		t.Fatal(err)
	}
	named := base
	named.ServerName = "router.lab"
	if _, err := Get(ctx, lo, named, Credentials{Password: "pw", CA: caPEM}, Settings{}); err != nil {
		t.Fatal(err)
	}
	// Unknown issuer fails unless verification is skipped.
	if _, err := Get(ctx, lo, base, Credentials{Password: "pw"}, Settings{TimeoutSeconds: 2}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	skip := base
	skip.SkipVerify = true
	if _, err := Get(ctx, lo, skip, Credentials{Password: "pw"}, Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(ctx, lo, base, Credentials{Password: "pw", CA: "not a PEM"}, Settings{}); err == nil {
		t.Fatal("bad CA accepted")
	}
	// TLS off against a TLS target fails.
	plain := base
	plain.TLS = false
	if _, err := Get(ctx, lo, plain, Credentials{Password: "pw"}, Settings{TimeoutSeconds: 1}); err == nil {
		t.Fatal("plaintext against TLS succeeded")
	}
}

func TestDecodeContainerBlob(t *testing.T) {
	// A device answering with one JSON_IETF blob of the whole tree.
	blob := `{"openconfig-interfaces:interface": [
	  {"name": "xe-0/0/1", "config": {"description": "ignored"},
	   "state": {"name": "xe-0/0/1", "ifindex": 517, "description": "to core-2", "counters": {"in-octets": "123"}},
	   "openconfig-if-ethernet:ethernet": {"state": {"port-speed": "openconfig-if-ethernet:SPEED_10GB", "negotiated-port-speed": "SPEED_1GB"}},
	   "subinterfaces": {"subinterface": [{"index": 0, "state": {"index": 0, "ifindex": 518, "description": ""}}]}},
	  {"name": "ae0", "state": {"ifindex": "600"}, "openconfig-if-aggregate:aggregation": {"state": {"lag-speed": 40000}}},
	  {"name": "noindex", "state": {"description": "x"}}
	]}`
	d := newDecoder()
	d.notification(&gpb.Notification{Update: []*gpb.Update{{Path: &gpb.Path{Elem: []*gpb.PathElem{elem("openconfig-interfaces:interfaces")}}, Val: ietf(blob)}}})
	got := d.interfaces()
	want := map[uint32]Interface{
		517: {Name: "xe-0/0/1", Descr: "to core-2", Speed: 1e9},
		518: {Name: "xe-0/0/1.0", Speed: 1e9},
		600: {Name: "ae0", Speed: 40e9},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ifindex %d = %+v, want %+v", k, got[k], v)
		}
	}
}

func TestSpeedBits(t *testing.T) {
	cases := map[string]uint64{
		"SPEED_10MB": 10e6, "SPEED_100MB": 100e6, "SPEED_1GB": 1e9, "SPEED_2500MB": 2_500_000_000, "SPEED_5GB": 5e9,
		"SPEED_10GB": 10e9, "SPEED_25GB": 25e9, "SPEED_40GB": 40e9, "SPEED_50GB": 50e9, "SPEED_100GB": 100e9,
		"SPEED_200GB": 200e9, "SPEED_400GB": 400e9, "SPEED_800GB": 800e9, "SPEED_1.6TB": 1_600_000_000_000,
		"openconfig-if-ethernet:SPEED_100GB": 100e9, "oc-eth:SPEED_1GB": 1e9,
		"SPEED_UNKNOWN": 0, "": 0, "100G": 0, "SPEED_10XB": 0,
	}
	for in, want := range cases {
		if got := SpeedBits(in); got != want {
			t.Errorf("SpeedBits(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestTTL(t *testing.T) {
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	fail := false
	p.SetGetter(func(context.Context, netip.Addr, Profile, Credentials, Settings) (map[uint32]Interface, error) {
		if fail {
			return nil, errors.New("unreachable")
		}
		return map[uint32]Interface{7: {Name: "et-0/0/7", Speed: 1e11}}, nil
	})
	s := Settings{Enabled: true, Devices: []string{"192.0.2.7"}, IntervalMinutes: 10, TTLMinutes: 60,
		Profiles: []Profile{{ID: "all", Name: "all"}}}
	if err := p.Apply(s, nil); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("192.0.2.7")
	d := p.devs[a]
	p.pollDevice(context.Background(), d, p.Settings())
	if n, _, sp, ok := p.Lookup(a, 7); !ok || n != "et-0/0/7" || sp != 1e11 {
		t.Fatalf("lookup %q %d %v", n, sp, ok)
	}
	if !d.next.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("next poll %v", d.next)
	}
	// The device stops answering: its data stays until the TTL ends.
	fail = true
	now = now.Add(50 * time.Minute)
	p.pollDevice(context.Background(), d, p.Settings())
	if _, _, _, ok := p.Lookup(a, 7); !ok || d.err == "" {
		t.Fatalf("data dropped before the TTL (err %q)", d.err)
	}
	now = now.Add(11 * time.Minute)
	if _, _, _, ok := p.Lookup(a, 7); ok {
		t.Fatal("data kept after the TTL")
	}
	if st := p.Status(); len(st) != 1 || st[0].Error != "unreachable" || !st[0].Configured {
		t.Fatalf("status %+v", st)
	}
}

func TestNormalize(t *testing.T) {
	cases := []Settings{
		{Profiles: []Profile{{ID: "a", Name: "a", Encoding: "proto"}}},
		{Profiles: []Profile{{ID: "a", Name: "a"}, {ID: "a", Name: "b"}}},
		{Profiles: []Profile{{ID: "A/B", Name: "a"}}},
		{Profiles: []Profile{{ID: "a", Name: " "}}},
		{Profiles: []Profile{{ID: "a", Name: "a", Prefixes: []string{"core"}}}},
		{Devices: []string{"router1"}},
		{IntervalMinutes: 60, TTLMinutes: 10},
		{TimeoutSeconds: 61},
		{Concurrency: 65},
	}
	for i, c := range cases {
		if _, err := c.Normalize(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	s, err := Settings{Devices: []string{"::ffff:10.0.0.1"}, Profiles: []Profile{{ID: "p", Name: " core ", SkipVerify: true, ServerName: "x"}}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	p := s.Profiles[0]
	if s.Devices[0] != "10.0.0.1" || p.Port != DefaultPort || p.Encoding != EncodingJSONIETF || p.Name != "core" ||
		p.SkipVerify || p.ServerName != "" || s.IntervalMinutes != 30 || s.TimeoutSeconds != 10 {
		t.Fatalf("normalized %+v", s)
	}
}
