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
	noSubscribe    bool // answer Unimplemented to Subscribe
	// live carries notifications sent on open Subscribe streams after the
	// initial state.
	live chan *gpb.Notification

	mu        sync.Mutex
	encodings []gpb.Encoding
	streams   int
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

func (f *fakeTarget) auth(ctx context.Context, enc gpb.Encoding) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if f.user != "" && (strings.Join(md.Get("username"), "") != f.user || strings.Join(md.Get("password"), "") != f.password) {
		return status.Error(codes.Unauthenticated, "bad credentials")
	}
	f.mu.Lock()
	f.encodings = append(f.encodings, enc)
	f.mu.Unlock()
	if f.rejectIETF && enc == gpb.Encoding_JSON_IETF {
		return status.Error(codes.InvalidArgument, "unsupported encoding")
	}
	return nil
}

func (f *fakeTarget) Get(ctx context.Context, req *gpb.GetRequest) (*gpb.GetResponse, error) {
	if err := f.auth(ctx, req.GetEncoding()); err != nil {
		return nil, err
	}
	if len(req.GetPath()) != 1 || req.GetPath()[0].GetElem()[1].GetKey()["name"] != "*" {
		return nil, status.Error(codes.InvalidArgument, "one wildcard path expected")
	}
	n, err := state(req.GetPath()[0])
	if err != nil {
		return nil, err
	}
	return &gpb.GetResponse{Notification: []*gpb.Notification{n}}, nil
}

func (f *fakeTarget) Subscribe(st gpb.GNMI_SubscribeServer) error {
	if f.noSubscribe {
		return status.Error(codes.Unimplemented, "Subscribe is not supported")
	}
	req, err := st.Recv()
	if err != nil {
		return err
	}
	list := req.GetSubscribe()
	if list.GetMode() != gpb.SubscriptionList_STREAM {
		return status.Error(codes.InvalidArgument, "STREAM expected")
	}
	if err := f.auth(st.Context(), list.GetEncoding()); err != nil {
		return err
	}
	f.mu.Lock()
	f.streams++
	f.mu.Unlock()
	for _, sub := range list.GetSubscription() {
		if sub.GetMode() != gpb.SubscriptionMode_TARGET_DEFINED {
			return status.Error(codes.InvalidArgument, "TARGET_DEFINED expected")
		}
		n, err := state(sub.GetPath())
		if status.Code(err) == codes.NotFound {
			continue
		}
		if err != nil {
			return err
		}
		if err := st.Send(&gpb.SubscribeResponse{Response: &gpb.SubscribeResponse_Update{Update: n}}); err != nil {
			return err
		}
	}
	if err := st.Send(&gpb.SubscribeResponse{Response: &gpb.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
		return err
	}
	for {
		select {
		case <-st.Context().Done():
			return nil
		case n := <-f.live:
			if err := st.Send(&gpb.SubscribeResponse{Response: &gpb.SubscribeResponse_Update{Update: n}}); err != nil {
				return err
			}
		}
	}
}

// state is the notification of the fake device for one wildcard path.
func state(path *gpb.Path) (*gpb.Notification, error) {
	type upd struct {
		elems []*gpb.PathElem
		val   *gpb.TypedValue
	}
	var ups []upd
	switch pathKey(path) {
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
	return n, nil
}

// serve starts the fake target on a localhost port (TLS when cfg is set).
func serve(t *testing.T, f *fakeTarget, cfg *tls.Config) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opts []grpc.ServerOption
	if cfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(cfg)))
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

// selfSigned returns a server certificate for 127.0.0.1 and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	cert, certPEM, _ := selfSignedFor(t, x509.ExtKeyUsageServerAuth)
	return cert, certPEM
}

// selfSignedFor returns a self-signed certificate for 127.0.0.1, its PEM
// and the PEM of its key.
func selfSignedFor(t *testing.T, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "router"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"router.lab"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

func TestTLS(t *testing.T) {
	cert, caPEM := selfSigned(t)
	port := serve(t, &fakeTarget{user: "flow", password: "pw"}, &tls.Config{Certificates: []tls.Certificate{cert}})
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

func TestMutualTLS(t *testing.T) {
	srvCert, caPEM := selfSigned(t)
	_, cliPEM, cliKey := selfSignedFor(t, x509.ExtKeyUsageClientAuth)
	clients := x509.NewCertPool()
	clients.AppendCertsFromPEM([]byte(cliPEM))
	port := serve(t, &fakeTarget{}, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients})
	lo := netip.MustParseAddr("127.0.0.1")
	ctx := context.Background()
	prof := Profile{Name: "mtls", Port: port, TLS: true}

	ifs, err := Get(ctx, lo, prof, Credentials{CA: caPEM, Cert: cliPEM, Key: cliKey}, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	wantIfaces(t, ifs)
	// Without a client certificate the device refuses the handshake.
	if _, err := Get(ctx, lo, prof, Credentials{CA: caPEM}, Settings{TimeoutSeconds: 2}); err == nil {
		t.Fatal("accepted without a client certificate")
	}
	// A key that does not match the certificate is reported as such.
	_, _, otherKey := selfSignedFor(t, x509.ExtKeyUsageClientAuth)
	if _, err := Get(ctx, lo, prof, Credentials{CA: caPEM, Cert: cliPEM, Key: otherKey}, Settings{}); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("mismatched key: %v", err)
	}

	// The poller resolves the certificate and key from OpenBao references.
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const caRef, certRef, keyRef = "openbao://flow/gnmi/m/ca#value", "openbao://flow/gnmi/m/cert#value", "openbao://flow/gnmi/m/key#value"
	s := Settings{Enabled: true, TimeoutSeconds: 2, Profiles: []Profile{{ID: "m", Name: "m", Port: port, TLS: true,
		CARef: caRef, CertRef: certRef, KeyRef: keyRef}}}
	if err := p.Apply(s, resolver(map[string]string{caRef: caPEM, certRef: cliPEM, keyRef: cliKey})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Poll(ctx, lo); err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].KeyRef = ""
	if err := p.Apply(s, nil); err == nil {
		t.Fatal("certificate without its key accepted")
	}
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, what string, cond func() bool, info ...func() any) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			for _, i := range info {
				t.Logf("%+v", i())
			}
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSubscribe(t *testing.T) {
	f := &fakeTarget{user: "flow", password: "s3cret", live: make(chan *gpb.Notification)}
	port := serve(t, f, nil)
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := resolver(map[string]string{pwRef: "s3cret"})
	s := labSettings(port)
	s.PollExporters, s.Devices = false, []string{"127.0.0.1"}
	s.Profiles[0].Mode = ModeSubscribe
	if err := p.Apply(s, res); err != nil {
		t.Fatal(err)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	// The initial state arrives on the stream.
	waitFor(t, "the initial state", func() bool { _, _, _, ok := p.Lookup(lo, 501); return ok })
	if st := p.Status(); len(st) != 1 || st[0].Mode != ModeSubscribe || !st[0].Streaming || st[0].Interfaces != 5 {
		t.Fatalf("status %+v", st)
	}

	// Changes: a new description, then Ethernet1 (and its subinterfaces) removed.
	f.live <- &gpb.Notification{Prefix: &gpb.Path{Elem: []*gpb.PathElem{elem("interfaces")}},
		Update: []*gpb.Update{{Path: &gpb.Path{Elem: ifElems("Ethernet2", "state", "description")}, Val: strV("to core-3")}}}
	waitFor(t, "the new description", func() bool { _, d, _, _ := p.Lookup(lo, 2); return d == "to core-3" })
	f.live <- &gpb.Notification{Delete: []*gpb.Path{{Elem: []*gpb.PathElem{elem("interfaces"), elem("interface", "name", "Ethernet1")}}}}
	waitFor(t, "the deletion", func() bool {
		_, _, _, ok1 := p.Lookup(lo, 1)
		_, _, _, ok501 := p.Lookup(lo, 501)
		return !ok1 && !ok501
	})
	// A leaf delete clears it.
	f.live <- &gpb.Notification{Delete: []*gpb.Path{{Elem: append([]*gpb.PathElem{elem("interfaces")}, ifElems("Ethernet2", "state", "description")...)}}}
	waitFor(t, "the cleared description", func() bool { _, d, _, ok := p.Lookup(lo, 2); return ok && d == "" })

	// Back to Get: the stream closes and a poll reads the whole state again.
	s.Profiles[0].Mode = ModeGet
	if err := p.Apply(s, res); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a Get poll", func() bool {
		st := p.Status()
		return len(st) == 1 && st[0].Mode == ModeGet && !st[0].Streaming && st[0].Interfaces == 5
	}, func() any { return p.Status() })
}

func TestSubscribeFallback(t *testing.T) {
	f := &fakeTarget{noSubscribe: true}
	port := serve(t, f, nil)
	p, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{Enabled: true, Devices: []string{"127.0.0.1"}, TimeoutSeconds: 2,
		Profiles: []Profile{{ID: "x", Name: "x", Port: port, Mode: ModeSubscribe}}}
	if err := p.Apply(s, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitFor(t, "a Get poll", func() bool {
		st := p.Status()
		return len(st) == 1 && st[0].Mode == ModeGet && st[0].Interfaces == 5 && st[0].Error == ""
	})
	// The refusal itself.
	err = subscribeGNMI(ctx, netip.MustParseAddr("127.0.0.1"), Profile{Name: "x", Port: port}, Credentials{}, Settings{TimeoutSeconds: 1}, func(map[uint32]Interface) {})
	if !errors.Is(err, ErrSubscribeUnsupported) {
		t.Fatalf("subscribe: %v", err)
	}
}

func TestSubscribeJSONFallback(t *testing.T) {
	f := &fakeTarget{rejectIETF: true, live: make(chan *gpb.Notification)}
	port := serve(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan map[uint32]Interface, 1)
	go func() {
		_ = subscribeGNMI(ctx, netip.MustParseAddr("127.0.0.1"), Profile{Name: "x", Port: port}, Credentials{}, Settings{TimeoutSeconds: 2},
			func(ifs map[uint32]Interface) {
				select {
				case got <- ifs:
				default:
				}
			})
	}()
	select {
	case ifs := <-got:
		wantIfaces(t, ifs)
	case <-time.After(5 * time.Second):
		t.Fatal("no state")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.encodings) != 2 || f.encodings[1] != gpb.Encoding_JSON {
		t.Fatalf("encodings %v", f.encodings)
	}
}
