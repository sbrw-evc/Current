package devices

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/detector"
	"github.com/sbrw-evc/current/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
	"github.com/sbrw-evc/current/app/backend/internal/inventory"
	"github.com/sbrw-evc/current/app/backend/internal/secrets"
	"github.com/sbrw-evc/current/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/current/app/backend/internal/setup"
	"github.com/sbrw-evc/current/app/backend/internal/snmp"
	"github.com/sbrw-evc/current/app/backend/internal/store"
	"github.com/sbrw-evc/current/app/backend/internal/store/storetest"
)

// fakeDevices answers polls and actions per host.
type fakeDevices struct {
	mu      sync.Mutex
	snaps   map[string]*drivers.Snapshot
	fail    map[string]error
	applied []drivers.Params
	actions []string
	creds   map[string]drivers.Credentials
}

func newFakeDevices() *fakeDevices {
	return &fakeDevices{snaps: map[string]*drivers.Snapshot{}, fail: map[string]error{}, creds: map[string]drivers.Credentials{}}
}

func (f *fakeDevices) set(host string, s *drivers.Snapshot, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps[host], f.fail[host] = s, err
}

type fakeDriver struct {
	f    *fakeDevices
	host string
}

func (d *fakeDriver) Collect(context.Context) (*drivers.Snapshot, error) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	if err := d.f.fail[d.host]; err != nil {
		return nil, err
	}
	s := d.f.snaps[d.host]
	if s == nil {
		return &drivers.Snapshot{}, nil
	}
	b, _ := json.Marshal(s)
	var c drivers.Snapshot
	_ = json.Unmarshal(b, &c)
	return &c, nil
}

func (d *fakeDriver) Apply(_ context.Context, action string, p drivers.Params) (string, error) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	d.f.actions = append(d.f.actions, action)
	d.f.applied = append(d.f.applied, p)
	return "done " + action, nil
}

func (d *fakeDriver) Backup(context.Context) (string, error) {
	return "/system identity\nset name=r1\n", nil
}
func (d *fakeDriver) HostKey() string { return "" }
func (d *fakeDriver) Close()          {}

// fakeSink records the events like a configured detector.Sender.
type fakeSink struct {
	mu     sync.Mutex
	events []detector.Event
	off    bool
}

func (s *fakeSink) Deliver(_ context.Context, ev []detector.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev...)
	return nil
}

func (s *fakeSink) Status() detector.SenderStatus { return detector.SenderStatus{Configured: !s.off} }

func (s *fakeSink) all() []detector.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]detector.Event(nil), s.events...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	svc   *Service
	st    *store.Store
	vault *secrets.Client
	devs  *fakeDevices
	sink  *fakeSink
	clock *clock
	snap  *inventory.Snapshot
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	_, vault := secretstest.New(t)
	e := &env{st: st, vault: vault, devs: newFakeDevices(), sink: &fakeSink{}, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.svc = New(Config{Store: st, Vault: vault, Events: e.sink, Now: e.clock.now,
		Inventory: func() *inventory.Snapshot { return e.snap },
		Driver: func(p *drivers.Platform, tg drivers.Target, c drivers.Credentials) (drivers.Driver, error) {
			e.devs.mu.Lock()
			e.devs.creds[tg.Host] = c
			e.devs.mu.Unlock()
			return &fakeDriver{f: e.devs, host: tg.Host}, nil
		},
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "flow.example.com" {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			}
			return nil, errors.New("no such host")
		},
	})
	t.Cleanup(e.svc.Close)
	return e
}

func sp(s string) *string { return &s }
func ip(n int) *int       { return &n }

func httpStatus(err error) int {
	var he *httpx.HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

func u64(v uint64) *uint64 { return &v }

func TestCreatePollAndCredentials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.devs.set("10.0.0.1", &drivers.Snapshot{
		Facts: drivers.Facts{Hostname: "core-r1", Vendor: "MikroTik", Model: "CCR2004", MAC: "aa:bb:cc:00:00:01"},
		Interfaces: []drivers.Interface{{Name: "ether1", OperUp: drivers.P(true), SpeedMbps: drivers.P(int64(1000)),
			RxBytes: u64(1000), TxBytes: u64(5000), Addresses: []string{"10.0.0.1/24", "fe80::1/64"}}},
		Endpoints: []drivers.Endpoint{{MAC: "11:22:33:44:55:66", IP: "10.0.0.50", Source: "arp", Interface: "bridge"},
			{MAC: "01:00:5e:00:00:01", Source: "arp"}, {MAC: "AA-BB-CC-00-00-02", Hostname: "laptop", Source: "dhcp", IP: "10.0.0.51"}},
	}, nil)
	v, err := e.svc.Create(ctx, "alice", Input{Platform: sp("mikrotik"), Host: sp("10.0.0.1"),
		Credentials: map[string]*string{"username": sp("admin"), "password": sp("s3cret")}})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Credentials.Set["password"] || v.Credentials.Set["api_key"] || v.Credentials.Username != "admin" || v.Transport != "api" {
		t.Fatalf("view %+v", v.Credentials)
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), "s3cret") {
		t.Fatal("the secret is in the view")
	}
	if got, err := secrets.Value(e.vault, e.vault.Ref(SecretPath(v.ID), "password")); err != nil || got != "s3cret" {
		t.Fatalf("OpenBao password = %q, %v", got, err)
	}
	e.svc.Wait() // the first poll
	if c := e.devs.creds["10.0.0.1"]; c.Password != "s3cret" || c.Username != "admin" {
		t.Fatalf("driver credentials %+v", c)
	}
	d, err := e.svc.Get(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "up" || d.Name != "core-r1" || d.Facts.Model != "CCR2004" || len(d.Interfaces) != 1 {
		t.Fatalf("after poll: %+v", d.View)
	}
	if d.Interfaces[0].RxBps != nil {
		t.Fatal("a rate without a previous poll")
	}
	if len(d.Endpoints) != 2 {
		t.Fatalf("endpoints %+v", d.Endpoints)
	}
	if !slicesEqual(d.ExporterIPs, []string{"10.0.0.1"}) {
		t.Fatalf("exporter ips %v", d.ExporterIPs)
	}

	// The second poll 10 s later gives rates from the counters.
	e.clock.add(10 * time.Second)
	e.devs.mu.Lock()
	e.devs.snaps["10.0.0.1"].Interfaces[0].RxBytes = u64(1000 + 12_500_000) // 10 Mbit/s over 10 s
	e.devs.snaps["10.0.0.1"].Interfaces[0].TxBytes = u64(5000)
	e.devs.mu.Unlock()
	if r, err := e.svc.Poll(ctx, v.ID); err != nil || !r.OK {
		t.Fatalf("poll %+v %v", r, err)
	}
	d, _ = e.svc.Get(ctx, v.ID)
	it := d.Interfaces[0]
	if it.RxBps == nil || *it.RxBps != 10_000_000 || it.TxBps == nil || *it.TxBps != 0 || it.Utilization == nil || *it.Utilization != 1 {
		t.Fatalf("rates %+v %+v %+v", it.RxBps, it.TxBps, it.Utilization)
	}

	// Secrets: "" keeps, clear removes, a new value replaces.
	_, changed, err := e.svc.Update(ctx, v.ID, Input{Credentials: map[string]*string{"password": sp("")}, ClearCredentials: []string{"api_key"}})
	if err != nil || len(changed) != 1 {
		t.Fatalf("update %v %v", changed, err)
	}
	if got, _ := secrets.Value(e.vault, e.vault.Ref(SecretPath(v.ID), "password")); got != "s3cret" {
		t.Fatal("an empty password replaced the stored one")
	}
	nv, _, err := e.svc.Update(ctx, v.ID, Input{ClearCredentials: []string{"password"}})
	if err != nil || nv.Credentials.Set["password"] {
		t.Fatalf("clear: %+v %v", nv.Credentials, err)
	}

	// Validation.
	for name, in := range map[string]Input{
		"platform":  {Platform: sp("nope"), Host: sp("10.0.0.9")},
		"host":      {Platform: sp("mikrotik"), Host: sp("bad host;rm")},
		"transport": {Platform: sp("mikrotik"), Host: sp("10.0.0.9"), Transport: sp("telnet")},
		"poll":      {Platform: sp("mikrotik"), Host: sp("10.0.0.9"), PollSeconds: ip(30)},
		"field":     {Platform: sp("mikrotik"), Host: sp("10.0.0.9"), Credentials: map[string]*string{"token": sp("x")}},
		"role":      {Platform: sp("mikrotik"), Host: sp("10.0.0.9"), Role: sp("toaster")},
		"exporter":  {Platform: sp("mikrotik"), Host: sp("10.0.0.9"), FlowExporterIP: sp("nope")},
	} {
		if _, err := e.svc.Create(ctx, "alice", in); httpStatus(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No duplicates: the same address again.
	if _, err := e.svc.Create(ctx, "alice", Input{Platform: sp("mikrotik"), Host: sp("10.0.0.1")}); httpStatus(err) != 409 {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := e.svc.Delete(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Value(e.vault, e.vault.Ref(SecretPath(v.ID), "username")); err == nil {
		t.Log("OpenBao path kept after delete")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDownAfterTwoFailuresAndUmbrellaEvents(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_ = e.st.PutSetting(ctx, setup.SettingGeneral, setup.General{Language: "en", PublicURL: "https://flow.example.com/"})
	e.devs.set("10.0.0.2", nil, &drivers.Error{Msg: "connection refused"})
	v, err := e.svc.Create(ctx, "alice", Input{Platform: sp("mikrotik"), Host: sp("10.0.0.2"), Name: sp("edge")})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	d, _ := e.svc.Get(ctx, v.ID)
	if d.Status != "error" || d.Failures != 1 || d.LastError != "connection refused" {
		t.Fatalf("after one failure: %s %d %q", d.Status, d.Failures, d.LastError)
	}
	e.svc.Tick(ctx)
	if n := len(e.sink.all()); n != 0 {
		t.Fatalf("%d events after one failure", n)
	}
	e.clock.add(time.Minute)
	if r, _ := e.svc.Poll(ctx, v.ID); r.Status != "down" || r.Failures != 2 {
		t.Fatalf("second failure: %+v", r)
	}
	e.svc.Tick(ctx)
	ev := e.sink.all()
	if len(ev) != 1 {
		t.Fatalf("events %+v", ev)
	}
	f := ev[0]
	if f.Status != detector.StatusFiring || f.Signal != SignalDeviceDown || f.Method != "USE" || f.Severity != "critical" ||
		f.CI != "edge" || f.IP != "10.0.0.2" || f.Title != "Device is unreachable: edge" || !strings.HasPrefix(f.ID, "flow-") ||
		f.Links == nil || f.Links.Flow != "https://flow.example.com/devices/"+itoa(v.ID) || f.Labels["error"] != "connection refused" {
		t.Fatalf("firing event %+v", f)
	}
	e.svc.Tick(ctx) // no repeat
	if len(e.sink.all()) != 1 {
		t.Fatal("the firing event was repeated")
	}
	e.clock.add(time.Minute)
	_, _ = e.svc.Poll(ctx, v.ID) // still down: the same episode
	e.svc.Tick(ctx)
	if len(e.sink.all()) != 1 {
		t.Fatal("a third failure sent an event")
	}
	e.devs.set("10.0.0.2", &drivers.Snapshot{}, nil)
	e.clock.add(time.Minute)
	if r, _ := e.svc.Poll(ctx, v.ID); !r.OK || r.Status != "up" {
		t.Fatalf("recovery %+v", r)
	}
	e.svc.Tick(ctx)
	ev = e.sink.all()
	if len(ev) != 2 || ev[1].Status != detector.StatusResolved || ev[1].ID != f.ID || ev[1].EndsAt == "" {
		t.Fatalf("resolved event %+v", ev)
	}

	// Without a configured sink nothing is queued nor marked.
	e.sink.off = true
	e.devs.set("10.0.0.2", nil, errors.New("timeout"))
	for range 2 {
		e.clock.add(time.Minute)
		_, _ = e.svc.Poll(ctx, v.ID)
	}
	e.svc.Tick(ctx)
	if len(e.sink.all()) != 2 {
		t.Fatal("an event went to an unconfigured sink")
	}
	nd, _ := e.st.NetworkDevice(ctx, v.ID)
	if nd.Alerted != nil {
		t.Fatal("marked alerted without a sink")
	}
	// Deleting an alerted device resolves its event.
	e.sink.off = false
	e.svc.Tick(ctx)
	if ev = e.sink.all(); len(ev) != 3 || ev[2].Status != detector.StatusFiring || ev[2].ID == f.ID {
		t.Fatalf("new episode %+v", ev)
	}
	if _, err := e.svc.Delete(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if ev = e.sink.all(); len(ev) != 4 || ev[3].Status != detector.StatusResolved || ev[3].ID != ev[2].ID {
		t.Fatalf("delete %+v", ev)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestEndpointMerge(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const client = "de:ad:be:ef:00:01"
	e.devs.set("10.0.1.1", &drivers.Snapshot{Facts: drivers.Facts{MAC: "aa:00:00:00:00:01"},
		Endpoints: []drivers.Endpoint{{MAC: client, IP: "10.0.1.20", Source: "arp", Interface: "vlan10"},
			{MAC: "aa:00:00:00:00:02", IP: "10.0.1.2", Source: "arp"}}}, nil)
	e.devs.set("10.0.1.2", &drivers.Snapshot{Facts: drivers.Facts{MAC: "aa:00:00:00:00:02"},
		Endpoints: []drivers.Endpoint{{MAC: client, Source: "wifi", SSID: "office", Signal: drivers.P(int64(-55)), Hostname: "phone"}}}, nil)
	r, err := e.svc.Create(ctx, "a", Input{Platform: sp("mikrotik"), Host: sp("10.0.1.1"), Name: sp("router"), Role: sp("router")})
	if err != nil {
		t.Fatal(err)
	}
	ap, err := e.svc.Create(ctx, "a", Input{Platform: sp("openwrt"), Host: sp("10.0.1.2"), Name: sp("ap"), Role: sp("ap")})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	eps, err := e.svc.Endpoints(ctx, EndpointQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("clients (the AP is infrastructure): %+v", eps)
	}
	c := eps[0]
	if c.MAC != client || c.Source != "wifi" || c.DeviceID == nil || *c.DeviceID != ap.ID || c.DeviceName != "ap" || c.IP != "10.0.1.20" ||
		c.Hostname != "phone" || c.Name != "phone" || c.SSID != "office" || c.Signal == nil || *c.Signal != -55 || !c.Online {
		t.Fatalf("merged client %+v", c)
	}
	if all, _ := e.svc.Endpoints(ctx, EndpointQuery{IncludeInfra: true}); len(all) != 2 {
		t.Fatalf("with infrastructure: %d", len(all))
	}
	if q, _ := e.svc.Endpoints(ctx, EndpointQuery{Q: "OFFICE"}); len(q) != 1 {
		t.Fatal("search by SSID")
	}
	off := false
	if q, _ := e.svc.Endpoints(ctx, EndpointQuery{Online: &off}); len(q) != 0 {
		t.Fatal("online filter")
	}
	// Names survive polls; the alias wins.
	if _, err := e.svc.UpdateEndpoint(ctx, strings.ToUpper(client), sp(" Boss phone "), sp("desk 4")); err != nil {
		t.Fatal(err)
	}
	_, _ = e.svc.Poll(ctx, ap.ID)
	got, err := e.svc.Endpoint(ctx, client)
	if err != nil || got.Name != "Boss phone" || got.Note != "desk 4" || len(got.Sightings) != 2 {
		t.Fatalf("detail %+v %v", got, err)
	}
	// The client leaves Wi-Fi: the router's ARP entry is what is left.
	e.devs.set("10.0.1.2", &drivers.Snapshot{Facts: drivers.Facts{MAC: "aa:00:00:00:00:02"}}, nil)
	_, _ = e.svc.Poll(ctx, ap.ID)
	_, _ = e.svc.Poll(ctx, r.ID)
	got, _ = e.svc.Endpoint(ctx, client)
	if got.Source != "arp" || *got.DeviceID != r.ID || got.Interface != "vlan10" {
		t.Fatalf("after leaving Wi-Fi %+v", got.NetworkEndpoint)
	}
	// Offline after the configured minutes.
	e.clock.add(20 * time.Minute)
	if q, _ := e.svc.Endpoints(ctx, EndpointQuery{Online: &off}); len(q) != 1 {
		t.Fatal("not offline after 20 minutes")
	}
	// Blocking needs a device that can block.
	if _, _, err := e.svc.BlockEndpoint(ctx, client, true); httpStatus(err) != 400 {
		t.Fatalf("MikroTik and OpenWrt cannot block: %v", err)
	}
	k, err := e.svc.Create(ctx, "a", Input{Platform: sp("keenetic"), Host: sp("10.0.1.3"), Name: sp("keenetic"), Role: sp("router")})
	if err != nil {
		t.Fatal(err)
	}
	e.devs.set("10.0.1.3", &drivers.Snapshot{Endpoints: []drivers.Endpoint{{MAC: client, Source: "dhcp", IP: "10.0.1.20"}}}, nil)
	e.svc.Wait()
	_, _ = e.svc.Poll(ctx, k.ID)
	if dv, _, err := e.svc.BlockEndpoint(ctx, client, true); err != nil || dv.ID != k.ID {
		t.Fatalf("Keenetic blocks: %v", err)
	}
	if e.devs.actions[len(e.devs.actions)-1] != drivers.ActionEndpointBlock || e.devs.applied[len(e.devs.applied)-1].MAC != client {
		t.Fatalf("block %v %+v", e.devs.actions, e.devs.applied)
	}
	if err := e.svc.ForgetEndpoint(ctx, client); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Endpoint(ctx, client); httpStatus(err) != 404 {
		t.Fatalf("forgotten: %v", err)
	}
	if _, err := e.svc.UpdateEndpoint(ctx, "zz", nil, nil); httpStatus(err) != 400 {
		t.Fatal("invalid MAC accepted")
	}
}

func TestInventoryBinding(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	snap, err := inventory.LoadDir("../inventory/testdata")
	if err != nil {
		t.Fatal(err)
	}
	inv, ok := snap.Device(2)
	if !ok {
		t.Fatal("testdata device 2")
	}
	// Standalone records without Ledger.
	if _, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.1"), InventoryID: ip(2)}); httpStatus(err) != 400 {
		t.Fatalf("binding without Ledger: %v", err)
	}
	if err := e.st.SetInventoryDB(ctx, store.InventoryDB{Enabled: true, URL: "https://inventory.example", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.1"), InventoryID: ip(2)}); httpStatus(err) != 400 {
		t.Fatalf("not loaded yet: %v", err)
	}
	e.snap = snap
	if _, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.1"), Name: sp("x")}); httpStatus(err) != 400 {
		t.Fatalf("standalone with Ledger: %v", err)
	}
	if _, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.1"), InventoryID: ip(999999)}); httpStatus(err) != 400 {
		t.Fatalf("unknown Ledger device: %v", err)
	}
	c, _ := e.svc.InventoryCandidates(ctx, "")
	if !c.Connected || !c.Loaded || !hasCandidate(c, 2) {
		t.Fatalf("candidates %+v", c)
	}
	v, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.1"), InventoryID: ip(2)})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Bound || v.SourceRef != "inventory-db:dcim.device:2" || v.Name != inv.Name || v.Site != inv.Site || v.Role != inv.Role {
		t.Fatalf("bound view %+v", v)
	}
	if c, _ := e.svc.InventoryCandidates(ctx, ""); hasCandidate(c, 2) {
		t.Fatal("a managed device is still a candidate")
	}
	// One managed record per Ledger device.
	if _, err := e.svc.Create(ctx, "a", Input{Platform: sp("juniper"), Host: sp("10.9.0.2"), InventoryID: ip(2)}); httpStatus(err) != 409 {
		t.Fatalf("duplicate binding: %v", err)
	}
	// Name, site and role are read-only; unbinding is refused.
	if _, _, err := e.svc.Update(ctx, v.ID, Input{Name: sp("renamed")}); httpStatus(err) != 400 {
		t.Fatalf("rename bound: %v", err)
	}
	if _, _, err := e.svc.Update(ctx, v.ID, Input{Name: sp(inv.Name), Note: sp("rack 4")}); err != nil {
		t.Fatalf("unchanged name: %v", err)
	}
	if _, _, err := e.svc.Update(ctx, v.ID, Input{InventoryID: ip(0)}); httpStatus(err) != 400 {
		t.Fatalf("unbind: %v", err)
	}
	// The hostname a poll reports does not rename a bound device.
	e.devs.set("10.9.0.1", &drivers.Snapshot{Facts: drivers.Facts{Hostname: "other-name"}}, nil)
	e.svc.Wait()
	_, _ = e.svc.Poll(ctx, v.ID)
	d, _ := e.svc.Get(ctx, v.ID)
	if d.Name != inv.Name || d.Inventory == nil || d.Inventory.ID != 2 {
		t.Fatalf("bound detail %+v", d.View)
	}
	// The device disappears from Ledger: still listed, marked.
	e.snap = inventory.Empty()
	d, _ = e.svc.Get(ctx, v.ID)
	if !d.InventoryGone {
		t.Fatal("missing Ledger device not marked")
	}
}

func hasCandidate(c Candidates, id int) bool {
	for _, d := range c.Devices {
		if d.ID == id {
			return true
		}
	}
	return false
}

func TestApplyActions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, err := e.svc.Create(ctx, "a", Input{Platform: sp("mikrotik"), Host: sp("10.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	// No collector known yet.
	if _, err := e.svc.Apply(ctx, v.ID, drivers.ActionFlowExport, drivers.Params{Protocol: "ipfix"}); httpStatus(err) != 400 {
		t.Fatalf("no collector: %v", err)
	}
	_ = e.st.PutSetting(ctx, setup.SettingGeneral, setup.General{PublicURL: "https://flow.example.com"})
	_ = e.st.PutSetting(ctx, setup.SettingCollector, setup.Collector{NetFlowAddr: ":9995", SFlowAddr: ":6343"})
	if col := e.svc.Collector(ctx); col.IP != "192.0.2.10" || col.NetFlowPort != 9995 || col.Source != "public_url" {
		t.Fatalf("collector %+v", col)
	}
	if _, err := e.svc.Apply(ctx, v.ID, drivers.ActionFlowExport, drivers.Params{Protocol: "ipfix"}); err != nil {
		t.Fatal(err)
	}
	if p := e.devs.applied[len(e.devs.applied)-1]; p.Collector != "192.0.2.10" || p.Port != 9995 {
		t.Fatalf("flow export params %+v", p)
	}
	if _, err := e.svc.Apply(ctx, v.ID, drivers.ActionFlowExport, drivers.Params{Protocol: "sflow"}); err == nil {
		if p := e.devs.applied[len(e.devs.applied)-1]; p.Port != 6343 {
			t.Fatalf("sflow port %+v", p)
		}
	}
	if _, err := e.svc.Apply(ctx, v.ID, drivers.ActionHostname, drivers.Params{Name: "bad name;"}); httpStatus(err) != 400 {
		t.Fatalf("strict validation: %v", err)
	}
	if _, err := e.svc.Apply(ctx, v.ID, "format_disk", drivers.Params{}); httpStatus(err) != 400 {
		t.Fatalf("unknown action: %v", err)
	}
	out, err := e.svc.Backup(ctx, v.ID)
	if err != nil || !strings.Contains(out, "set name=r1") {
		t.Fatalf("backup %q %v", out, err)
	}
	// SNMP-only platforms cannot configure flow export.
	s, err := e.svc.Create(ctx, "a", Input{Platform: sp("tplink"), Host: sp("10.0.2.2")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, s.ID, drivers.ActionFlowExport, drivers.Params{Protocol: "ipfix"}); httpStatus(err) != 400 {
		t.Fatalf("unsupported: %v", err)
	}
	e.svc.Wait()
}

func TestSNMPProfileSourceAndExporterLink(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// A Current SNMP profile covering 10.0.3.0/24 with the community in OpenBao.
	if err := e.vault.Put(ctx, "snmp/lan", map[string]string{"community": "lan-ro"}); err != nil {
		t.Fatal(err)
	}
	_ = e.st.PutSetting(ctx, settingSNMP, snmp.Settings{Enabled: true, Profiles: []snmp.Profile{{ID: "lan", Name: "LAN",
		Prefixes: []string{"10.0.3.0/24"}, Version: "2c", CommunityRef: e.vault.Ref("snmp/lan", "community")}}})
	v, err := e.svc.Create(ctx, "a", Input{Platform: sp("tplink"), Host: sp("10.0.3.1"), SNMPSource: sp(SNMPProfile),
		FlowExporterIP: sp("10.0.3.254")})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	if c := e.devs.creds["10.0.3.1"]; c.SNMPCommunity != "lan-ro" || c.SNMPVersion != "2c" {
		t.Fatalf("profile credentials %+v", c)
	}
	d, _ := e.svc.Get(ctx, v.ID)
	if d.SNMP == nil || d.SNMP.ID != "lan" {
		t.Fatalf("profile summary %+v", d.SNMP)
	}
	// Outside every profile: a clear error.
	o, _ := e.svc.Create(ctx, "a", Input{Platform: sp("tplink"), Host: sp("10.0.4.1"), SNMPSource: sp(SNMPProfile)})
	e.svc.Wait()
	if od, _ := e.svc.Get(ctx, o.ID); !strings.Contains(od.LastError, "No SNMP profile") {
		t.Fatalf("no profile: %q", od.LastError)
	}

	// Own SNMP credentials feed the interface-name poller.
	own, err := e.svc.Create(ctx, "a", Input{Platform: sp("cisco_ios"), Host: sp("10.0.5.1"), FlowExporterIP: sp("10.0.5.9"),
		Credentials: map[string]*string{"snmp_version": sp("3"), "snmp_user": sp("flow"), "snmp_auth_protocol": sp("sha256"),
			"snmp_auth_password": sp("authpass"), "snmp_priv_protocol": sp("aes"), "snmp_priv_password": sp("privpass")}})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := SNMPProfiles(ctx, e.st, e.vault)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles %+v", profiles)
	}
	p := profiles[0]
	if p.ID != "dev-"+itoa(own.ID) || p.Version != "3" || p.Username != "flow" || p.SecurityLevel != snmp.AuthPriv ||
		p.AuthProtocol != "SHA256" || p.PrivProtocol != "AES" || !slicesEqual(p.Prefixes, []string{"10.0.5.9/32", "10.0.5.1/32"}) {
		t.Fatalf("device profile %+v", p)
	}
	if got, err := snmp.ResolveCredentials(p, func(ref string) (string, error) { return secrets.Value(e.vault, ref) }); err != nil ||
		got.Auth != "authpass" || got.Priv != "privpass" {
		t.Fatalf("resolved %+v %v", got, err)
	}
	merged := MergeSNMP(snmp.Settings{}, profiles)
	if !merged.Enabled || !merged.PollExporters || len(merged.Profiles) != 1 {
		t.Fatalf("merged into disabled %+v", merged)
	}
	if _, err := merged.Normalize(); err != nil {
		t.Fatalf("merged settings invalid: %v", err)
	}
	merged = MergeSNMP(snmp.Settings{Enabled: true, Profiles: []snmp.Profile{{ID: "lan"}}}, profiles)
	if len(merged.Profiles) != 2 || merged.Profiles[0].ID != p.ID {
		t.Fatalf("device profiles go first: %+v", merged.Profiles)
	}

	links, err := e.svc.ExporterDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l, ok := links[netip.MustParseAddr("10.0.3.254")]; !ok || l.ID != v.ID {
		t.Fatalf("exporter link %+v", links)
	}
	if l := links[netip.MustParseAddr("10.0.5.1")]; l.ID != own.ID {
		t.Fatalf("host link %+v", l)
	}
}

func TestTopology(t *testing.T) {
	now := time.Now()
	mk := func(id int64, name, role string, facts drivers.Facts, nb []drivers.Neighbor, ch []drivers.Child) store.NetworkDevice {
		return store.NetworkDevice{ID: id, Name: name, Role: role, Platform: "mikrotik", Host: "10.0.0." + itoa(id), Status: "up",
			Facts: mustJSON(facts), Interfaces: mustJSON([]IfaceState{{Interface: drivers.Interface{Name: "GigabitEthernet1/0/1",
				SpeedMbps: drivers.P(int64(1000))}, RxBps: ptrF(5e8), Utilization: ptrF(50)}}),
			Neighbors: mustJSON(nb), Children: mustJSON(ch)}
	}
	devs := []store.NetworkDevice{
		mk(1, "router", "router", drivers.Facts{MAC: "aa:00:00:00:00:01"},
			[]drivers.Neighbor{{LocalInterface: "Gi1/0/1", RemoteName: "switch.lan", RemoteInterface: "ge-0/0/1", Protocol: "lldp"},
				{LocalInterface: "ether5", RemoteName: "printer-x", RemoteMAC: "cc:00:00:00:00:09", RemotePlatform: "Cisco IOS"}}, nil),
		mk(2, "switch", "switch", drivers.Facts{MAC: "aa:00:00:00:00:02"}, nil, nil),
		mk(3, "controller", "controller", drivers.Facts{}, nil,
			[]drivers.Child{{MAC: "bb:00:00:00:00:01", Name: "ap-1", Kind: "ap", Online: true, UplinkMAC: "aa:00:00:00:00:02", UplinkPort: "5"}}),
	}
	devs[2].Status = "down"
	views := make([]View, len(devs))
	s := &Service{}
	for i, d := range devs {
		views[i] = s.view(d, nil)
	}
	dev3 := int64(3)
	dev1 := int64(1)
	eps := []store.NetworkEndpoint{
		{MAC: "de:00:00:00:00:01", Hostname: "phone", SSID: "office", Source: "wifi", AttachedTo: "bb:00:00:00:00:01", DeviceID: &dev3, LastSeen: now},
		{MAC: "de:00:00:00:00:02", IP: "10.0.0.77", Source: "arp", DeviceID: &dev1, LastSeen: now.Add(-time.Hour)},
		{MAC: "aa:00:00:00:00:02", Source: "arp", DeviceID: &dev1, LastSeen: now}, // the switch in the router's ARP
	}
	top := buildTopology(devs, views, eps, 15*time.Minute, false, now)
	nodes := map[string]*Node{}
	for _, n := range top.Nodes {
		nodes[n.ID] = n
	}
	edge := func(a, b, kind string) *Edge {
		for _, e := range top.Edges {
			if e.Kind == kind && ((e.Source == a && e.Target == b) || (e.Source == b && e.Target == a)) {
				return e
			}
		}
		return nil
	}
	if l := edge("dev:1", "dev:2", "link"); l == nil || l.SourcePort != "Gi1/0/1" || l.Bps == nil || *l.Bps != 5e8 {
		t.Fatalf("LLDP link by name %+v", l)
	}
	if nodes["mac:bb:00:00:00:00:01"] == nil || edge("dev:2", "mac:bb:00:00:00:00:01", "link") == nil {
		t.Fatal("AP behind its uplink switch")
	}
	if n := nodes["nb:cc:00:00:00:00:09"]; n == nil || n.PlatformGuess != "cisco_ios" {
		t.Fatalf("unmanaged neighbour %+v", n)
	}
	if edge("mac:bb:00:00:00:00:01", "ep:de:00:00:00:00:01", "wifi") == nil || nodes["mac:bb:00:00:00:00:01"].Clients != 1 {
		t.Fatal("Wi-Fi client on its AP")
	}
	if nodes["ep:de:00:00:00:00:02"] != nil {
		t.Fatal("offline client shown")
	}
	if nodes["ep:aa:00:00:00:00:02"] != nil {
		t.Fatal("infrastructure shown as a client")
	}
	if edge("internet", "dev:1", "wan") == nil {
		t.Fatal("internet behind the router")
	}
	if top.Stats.Devices != 3 || top.Stats.Down != 1 || top.Stats.Children != 1 || top.Stats.Neighbors != 1 || top.Stats.Endpoints != 1 {
		t.Fatalf("stats %+v", top.Stats)
	}
	if all := buildTopology(devs, views, eps, 15*time.Minute, true, now); all.Stats.Endpoints != 2 {
		t.Fatalf("with offline: %+v", all.Stats)
	}
}

func ptrF(v float64) *float64 { return &v }

func TestSettingsAndPositions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.PutSettings(ctx, Settings{Concurrency: 99}); httpStatus(err) != 400 {
		t.Fatal("concurrency range")
	}
	if _, err := e.svc.PutSettings(ctx, Settings{CollectorAddress: "bad address!"}); httpStatus(err) != 400 {
		t.Fatal("collector address")
	}
	set, err := e.svc.PutSettings(ctx, Settings{CollectorAddress: "198.51.100.5", NetFlowPort: 2056})
	if err != nil || set.EndpointOfflineMinutes != 15 || set.Concurrency != 6 {
		t.Fatalf("defaults %+v %v", set, err)
	}
	if c := e.svc.Collector(ctx); c.IP != "198.51.100.5" || c.NetFlowPort != 2056 || c.SFlowPort != 6343 || c.Source != "settings" {
		t.Fatalf("collector %+v", c)
	}
	v, _ := e.svc.Create(ctx, "a", Input{Platform: sp("mikrotik"), Host: sp("10.0.6.1")})
	if err := e.svc.SetPositions(ctx, map[string]*[2]float64{"dev:" + itoa(v.ID): {10, 20}, "ep:x": {1, 1}}); err != nil {
		t.Fatal(err)
	}
	top, _ := e.svc.Topology(ctx, false, true)
	for _, n := range top.Nodes {
		if n.ID == "dev:"+itoa(v.ID) && (n.X == nil || *n.X != 10 || *n.Y != 20) {
			t.Fatalf("position %+v", n)
		}
	}
	e.svc.Wait()
}

func TestOUI(t *testing.T) {
	o := NewOUI("", nil)
	if v := o.Vendor("02:00:00:00:00:01"); v != "Random MAC" {
		t.Fatalf("locally administered: %q", v)
	}
}
