package drivers

import (
	"context"
	"crypto/md5" //nolint:gosec // the Keenetic protocol
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

const iosVersion = `Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)
core-sw uptime is 1 year, 2 weeks, 3 days, 4 hours, 5 minutes
System returned to ROM by power-on
cisco WS-C2960X-48TS-L (APM86XXX) processor (revision B0) with 524288K bytes of memory.
Base ethernet MAC Address       : 70:10:5C:11:22:33
Model number                    : WS-C2960X-48TS-L
System serial number            : FOC1234X0AB
`

const iosInterfaces = `GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 7010.5c11.2201 (bia 7010.5c11.2201)
  Description: uplink to gw
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     1234 packets input, 567890 bytes, 0 no buffer
     4321 packets output, 987654 bytes, 0 underruns
GigabitEthernet1/0/2 is administratively down, line protocol is down (disabled)
  Hardware is Gigabit Ethernet, address is 7010.5c11.2202 (bia 7010.5c11.2202)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec,
Vlan1 is up, line protocol is up
  Hardware is EtherSVI, address is 7010.5c11.2240 (bia 7010.5c11.2240)
  Internet address is 192.168.0.2/24
`

const cdpDetail = `-------------------------
Device ID: ap-hall.local
Entry address(es):
  IP address: 192.168.0.40
Platform: cisco AIR-AP2802I-E-K9,  Capabilities: Router Trans-Bridge
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): GigabitEthernet0
`

const lldpDetail = `------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: 000c.4200.0001
Port id: ether2
Port Description: ether2
System Name: gw

System Description:
MikroTik RouterOS 7.14

Management Addresses:
    IP: 192.168.0.1
`

const comwareLLDP = `System Name        Local Interface  Chassis ID      Port ID
core-sw            GE1/0/24         7010-5c11-2233  GigabitEthernet1/0/48
`

const arpIOS = `Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.0.1             5   000c.4200.0001  ARPA   Vlan1
Internet  192.168.0.50            0   1122.3344.5566  ARPA   Vlan1
`

const arpComware = `IP address      MAC address    VLAN/VSI name Interface                Aging Type
192.168.0.60    aabb-ccdd-eeff 1             GE1/0/3                  20    D
`

const macIOS = `          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    1122.3344.5566    DYNAMIC     Gi1/0/5
   1    000c.4200.0001    DYNAMIC     Gi1/0/1
 All    0100.0ccc.cccc    STATIC      CPU
`

const statusTable = `Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   uplink             connected    trunk      a-full a-1000 10/100/1000BaseTX
Gi1/0/2                      disabled     1            auto   auto 10/100/1000BaseTX
Gi1/0/3                      notconnect   1            auto   auto 10/100/1000BaseTX
`

const comwareBrief = `Brief information on interfaces in bridge mode:
Link: ADM - administratively down; Stby - standby
Interface            Link   Speed   Duplex Type PVID Description
GE1/0/1              UP     1G(a)   F(a)   A    1
GE1/0/2              DOWN   auto    A      A    1
GE1/0/3              ADM    auto    A      A    1
`

const linuxOutput = `#HOST
openwrt
#OS
NAME="OpenWrt"
VERSION_ID="23.05.3"
#UPTIME
3600.50 1000.00
#MODEL
GL.iNet GL-MT6000
#MEM
MemTotal:        1000000 kB
MemFree:          400000 kB
MemAvailable:     500000 kB
#LOAD
0.50 0.40 0.30 1/100 1234
4
#LINK
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\    link/ether 94:83:c4:00:00:01 brd ff:ff:ff:ff:ff:ff
3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 94:83:c4:00:00:02 brd ff:ff:ff:ff:ff:ff
#ADDR
3: br-lan    inet 192.168.8.1/24 brd 192.168.8.255 scope global br-lan\       valid_lft forever preferred_lft forever
#DEV
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0
  eth0: 5000000   4000    0    0    0     0          0         0  6000000    5000    0    0    0     0       0          0
br-lan: 3000000   2000    0    0    0     0          0         0  2000000    1000    0    0    0     0       0          0
#SPEED
/sys/class/net/eth0/speed 1000
/sys/class/net/br-lan/speed -1
#ARP
IP address       HW type     Flags       HW address            Mask     Device
192.168.8.120    0x1         0x2         3c:22:fb:00:00:01     *        br-lan
192.168.8.121    0x1         0x0         00:00:00:00:00:00     *        br-lan
#LEASES
1700000000 3c:22:fb:00:00:01 192.168.8.120 MacBook 01:3c:22:fb:00:00:01
1700000000 e4:5f:01:00:00:02 192.168.8.130 * *
#LLDP
`

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestCiscoParsers(t *testing.T) {
	v := ParseVersion(iosVersion)
	if v.Hostname != "core-sw" || v.Version != "15.2(7)E4" || v.Model != "WS-C2960X-48TS-L" || v.Serial != "FOC1234X0AB" ||
		v.MAC != "70:10:5c:11:22:33" {
		t.Fatalf("version: %+v", v)
	}
	if want := int64(31536000 + 2*604800 + 3*86400 + 4*3600 + 5*60); v.Uptime == nil || *v.Uptime != want {
		t.Fatalf("uptime %v, want %d", deref(v.Uptime), want)
	}
	ifs := ParseShowInterfaces(iosInterfaces)
	var names []string
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	if !reflect.DeepEqual(names, []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "Vlan1"}) {
		t.Fatalf("names %v", names)
	}
	g := ifs[0]
	if !*g.OperUp || !*g.AdminUp || *g.SpeedMbps != 1000 || *g.RxBytes != 567890 || *g.TxBytes != 987654 ||
		g.Description != "uplink to gw" || g.MAC != "70:10:5c:11:22:01" {
		t.Fatalf("gi1: %+v", g)
	}
	if *ifs[1].AdminUp || !reflect.DeepEqual(ifs[2].Addresses, []string{"192.168.0.2/24"}) {
		t.Fatalf("gi2 / vlan1: %+v %+v", ifs[1], ifs[2])
	}
	cdp := ParseCDPDetail(cdpDetail)
	if len(cdp) != 1 || cdp[0].RemoteName != "ap-hall.local" || cdp[0].RemoteIP != "192.168.0.40" || cdp[0].LocalInterface != "GigabitEthernet1/0/5" {
		t.Fatalf("cdp %+v", cdp)
	}
	lldp := ParseLLDPDetail(lldpDetail)
	if len(lldp) != 1 || lldp[0].LocalInterface != "Gi1/0/1" || lldp[0].RemoteMAC != "00:0c:42:00:00:01" || lldp[0].RemoteName != "gw" ||
		lldp[0].RemoteIP != "192.168.0.1" {
		t.Fatalf("lldp %+v", lldp)
	}
	arp := ParseARP(arpIOS)
	var got [][3]string
	for _, e := range arp {
		got = append(got, [3]string{e.IP, e.MAC, e.Interface})
	}
	if !reflect.DeepEqual(got, [][3]string{{"192.168.0.1", "00:0c:42:00:00:01", "Vlan1"}, {"192.168.0.50", "11:22:33:44:55:66", "Vlan1"}}) {
		t.Fatalf("arp %v", got)
	}
	macs := ParseMACTable(macIOS, map[string]bool{"Gi1/0/1": true})
	if len(macs) != 1 || macs[0].MAC != "11:22:33:44:55:66" || *macs[0].VLAN != 10 || macs[0].Interface != "Gi1/0/5" {
		t.Fatalf("mac %+v", macs)
	}
	st := ParseStatusTable(statusTable)
	type row struct {
		name     string
		oper, ad bool
		speed    any
	}
	var rows []row
	for _, i := range st {
		rows = append(rows, row{i.Name, *i.OperUp, *i.AdminUp, deref(i.SpeedMbps)})
	}
	if !reflect.DeepEqual(rows, []row{{"Gi1/0/1", true, true, int64(1000)}, {"Gi1/0/2", false, false, nil}, {"Gi1/0/3", false, true, nil}}) {
		t.Fatalf("status %+v", rows)
	}
}

func TestComwareParsers(t *testing.T) {
	st := ParseStatusTable(comwareBrief)
	if len(st) != 3 || !*st[0].OperUp || !*st[0].AdminUp || *st[1].OperUp || !*st[1].AdminUp || *st[2].OperUp || *st[2].AdminUp {
		t.Fatalf("brief %+v", st)
	}
	if st[0].SpeedMbps == nil || *st[0].SpeedMbps != 1000 {
		t.Fatalf("speed %v", deref(st[0].SpeedMbps))
	}
	nb := ParseLLDPTable(comwareLLDP)
	if len(nb) != 1 || nb[0].RemoteName != "core-sw" || nb[0].LocalInterface != "GE1/0/24" || nb[0].RemoteMAC != "70:10:5c:11:22:33" {
		t.Fatalf("lldp %+v", nb)
	}
	arp := ParseARP(arpComware)
	if len(arp) != 1 || arp[0].IP != "192.168.0.60" || arp[0].Interface != "GE1/0/3" || arp[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("arp %+v", arp)
	}
}

func TestHelpersAndValidation(t *testing.T) {
	if u := ParseUptime("10 days, 03:04:05"); u == nil || *u != 10*86400+3*3600+4*60+5 {
		t.Fatalf("uptime %v", deref(u))
	}
	if d := ParseDuration("1w2d03:04:05"); d == nil || *d != 9*86400+3*3600+4*60+5 {
		t.Fatalf("duration %v", deref(d))
	}
	if NormMAC("AABB.CCDD.EEFF") != "aa:bb:cc:dd:ee:ff" || NormMAC("x") != "" {
		t.Fatal("NormMAC")
	}
	if _, err := ValidateAction(ActionHostname, Params{Name: "bad name; reload"}); err == nil {
		t.Fatal("hostname with spaces accepted")
	}
	if _, err := ValidateAction(ActionInterface, Params{Name: "ether1", Description: P(`a"; /system reset`)}); err == nil {
		t.Fatal("description with quotes accepted")
	}
	if _, err := ValidateAction(ActionInterface, Params{Name: "ether1"}); err == nil {
		t.Fatal("interface without changes accepted")
	}
	p, err := ValidateAction(ActionDNS, Params{Servers: []string{"1.1.1.1", " dns.google "}})
	if err != nil || !reflect.DeepEqual(p.Servers, []string{"1.1.1.1", "dns.google"}) {
		t.Fatalf("dns %v %v", p.Servers, err)
	}
	if _, err := ValidateAction(ActionDNS, Params{Servers: []string{"1.1.1.1; reboot"}}); err == nil {
		t.Fatal("dns injection accepted")
	}
	p, err = ValidateAction(ActionFlowExport, Params{Collector: "192.168.0.210"})
	if err != nil || p.Port != 2055 || p.Protocol != "netflow9" || !p.IsEnabled(false) {
		t.Fatalf("flow %+v %v", p, err)
	}
	if _, err := ValidateAction(ActionFlowExport, Params{Collector: "collector.local"}); err == nil {
		t.Fatal("collector host name accepted")
	}
	p, err = ValidateAction(ActionEndpointBlock, Params{MAC: "3C-22-FB-00-00-01"})
	if err != nil || p.MAC != "3c:22:fb:00:00:01" || !p.IsBlocked() {
		t.Fatalf("block %+v %v", p, err)
	}
	if _, err := ValidateAction("format", Params{}); err == nil {
		t.Fatal("unknown action accepted")
	}
	if MaskBits("255.255.255.0") != 24 || MaskBits("16") != 16 {
		t.Fatal("MaskBits")
	}
	if VendorFromOID(".1.3.6.1.4.1.14988.1") != "MikroTik" || VendorFromOID("1.3.6.1.4.1.99999.1") != "enterprise 99999" {
		t.Fatal("VendorFromOID")
	}
}

func TestLinuxParser(t *testing.T) {
	s := ParseLinux(linuxOutput)
	f := s.Facts
	if f.Hostname != "openwrt" || f.Version != "23.05.3" || f.Model != "GL.iNet GL-MT6000" || *f.UptimeSeconds != 3600 ||
		*f.MemoryPercent != 50 || *f.CPUPercent != 12.5 {
		t.Fatalf("facts %+v", f)
	}
	var eth0, br *Interface
	for i := range s.Interfaces {
		switch s.Interfaces[i].Name {
		case "eth0":
			eth0 = &s.Interfaces[i]
		case "br-lan":
			br = &s.Interfaces[i]
		case "lo":
			t.Fatal("lo is listed")
		}
	}
	if eth0 == nil || *eth0.SpeedMbps != 1000 || *eth0.RxBytes != 5000000 || *eth0.TxBytes != 6000000 || !*eth0.OperUp ||
		eth0.MAC != "94:83:c4:00:00:01" {
		t.Fatalf("eth0 %+v", eth0)
	}
	if br == nil || !reflect.DeepEqual(br.Addresses, []string{"192.168.8.1/24"}) || br.SpeedMbps != nil {
		t.Fatalf("br-lan %+v", br)
	}
	got := map[string]bool{}
	for _, e := range s.Endpoints {
		got[e.MAC+" "+e.Source] = true
	}
	want := map[string]bool{"3c:22:fb:00:00:01 arp": true, "3c:22:fb:00:00:01 dhcp": true, "e4:5f:01:00:00:02 dhcp": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints %v", got)
	}
	if s.Facts.MAC != "94:83:c4:00:00:01" {
		t.Fatalf("mac %s", s.Facts.MAC)
	}
}

func TestLLDPCliAndHostapd(t *testing.T) {
	nb := parseLLDPCli(`{"lldp":{"interface":[{"eth0":{"chassis":{"sw1":{"id":{"type":"mac","value":"aa:00:00:00:00:01"},
		"descr":"RouterOS","mgmt-ip":["192.168.8.2"]}},"port":{"id":{"type":"ifname","value":"ether3"}}}}]}}`)
	if len(nb) != 1 || nb[0].RemoteName != "sw1" || nb[0].RemoteIP != "192.168.8.2" || nb[0].RemoteInterface != "ether3" ||
		nb[0].RemoteMAC != "aa:00:00:00:00:01" {
		t.Fatalf("lldpcli %+v", nb)
	}
	eps := ParseHostapd("#hostapd.wlan0\n{\"freq\": 5180, \"clients\": {\"3c:22:fb:00:00:01\": {\"signal\": -51}}}\n\t\"ssid\": \"Home\",\n")
	if len(eps) != 1 || eps[0].Interface != "wlan0" || eps[0].SSID != "Home" || *eps[0].Signal != -51 {
		t.Fatalf("hostapd %+v", eps)
	}
}

func targetOf(t *testing.T, srv *httptest.Server, transport string) Target {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return Target{Host: u.Hostname(), Port: port, Transport: transport, Timeout: 5 * time.Second}
}

func TestMikrotikREST(t *testing.T) {
	data := map[string]any{
		"system/resource": map[string]any{"uptime": "1w2d03:04:05", "cpu-load": "7", "total-memory": "1000", "free-memory": "250",
			"version": "7.14.2 (stable)", "board-name": "RB5009"},
		"system/identity":    map[string]any{"name": "gw"},
		"system/routerboard": map[string]any{"model": "RB5009UG+S+", "serial-number": "HE1234"},
		"ip/address":         []any{map[string]any{"address": "192.168.0.1/24", "interface": "bridge", "disabled": "false"}},
		"interface": []any{
			map[string]any{"name": "ether1", "type": "ether", "mac-address": "00:0C:42:00:00:01", "running": "true", "disabled": "false",
				"rx-byte": "100", "tx-byte": "200"},
			map[string]any{"name": "bridge", "type": "bridge", "mac-address": "00:0C:42:00:00:09", "running": "true", "disabled": "false"}},
		"ip/neighbor": []any{map[string]any{"interface": "ether2", "identity": "sw1", "mac-address": "AA:00:00:00:00:01",
			"address": "192.168.0.2", "discovered-by": "lldp,mndp"}},
		"ip/arp":               []any{map[string]any{"address": "192.168.0.50", "mac-address": "11:22:33:44:55:66", "interface": "bridge"}},
		"ip/dhcp-server/lease": []any{map[string]any{"address": "192.168.0.50", "mac-address": "11:22:33:44:55:66", "host-name": "tv"}},
		"interface/bridge/host": []any{map[string]any{"mac-address": "11:22:33:44:55:66", "on-interface": "ether3", "local": "false"},
			map[string]any{"mac-address": "AA:00:00:00:00:01", "on-interface": "ether2", "local": "false"}},
	}
	var mu sync.Mutex
	var scripts []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
			w.WriteHeader(401)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/rest/")
		if r.Method == http.MethodPost && path == "execute" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			scripts = append(scripts, Str(body["script"]))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ret": ""})
			return
		}
		if v, ok := data[path]; ok {
			_ = json.NewEncoder(w).Encode(v)
			return
		}
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":404}`)
	}))
	defer srv.Close()
	ctx := context.Background()
	p, _ := Lookup("mikrotik")
	d, err := p.Driver(targetOf(t, srv, "api"), Credentials{Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	snap, err := d.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := snap.Facts
	if f.Hostname != "gw" || f.Model != "RB5009UG+S+" || f.Version != "7.14.2" || *f.UptimeSeconds != 9*86400+3*3600+4*60+5 ||
		*f.MemoryPercent != 75 || *f.CPUPercent != 7 || f.MAC != "00:0c:42:00:00:01" {
		t.Fatalf("facts %+v", f)
	}
	if !reflect.DeepEqual(snap.Interfaces[1].Addresses, []string{"192.168.0.1/24"}) || *snap.Interfaces[0].RxBytes != 100 {
		t.Fatalf("interfaces %+v", snap.Interfaces)
	}
	if snap.Neighbors[0].Protocol != "lldp" || snap.Neighbors[0].RemoteMAC != "aa:00:00:00:00:01" {
		t.Fatalf("neighbors %+v", snap.Neighbors)
	}
	var bridge []string
	for _, e := range snap.Endpoints {
		if e.Source == SourceBridge {
			bridge = append(bridge, e.MAC+"@"+e.Interface)
		}
	}
	if !reflect.DeepEqual(bridge, []string{"11:22:33:44:55:66@ether3"}) {
		t.Fatalf("bridge %v", bridge)
	}
	fp, _ := ValidateAction(ActionFlowExport, Params{Collector: "192.168.0.210"})
	if _, err := d.Apply(ctx, ActionFlowExport, fp); err != nil {
		t.Fatal(err)
	}
	if s := scripts[len(scripts)-1]; !strings.Contains(s, "traffic-flow target add dst-address=192.168.0.210 port=2055 version=9") {
		t.Fatalf("flow script %q", s)
	}
	ip, _ := ValidateAction(ActionInterface, Params{Name: "ether5", Enabled: P(false), Description: P("tv")})
	if _, err := d.Apply(ctx, ActionInterface, ip); err != nil {
		t.Fatal(err)
	}
	if s := scripts[len(scripts)-1]; s != `/interface set [find name="ether5"] disabled=yes comment="tv"` {
		t.Fatalf("interface script %q", s)
	}
	if _, err := d.Apply(ctx, ActionEndpointBlock, Params{MAC: "11:22:33:44:55:66"}); err == nil {
		t.Fatal("RouterOS has no client blocking")
	}
	bad, _ := p.Driver(targetOf(t, srv, "api"), Credentials{Username: "u", Password: "wrong"})
	defer bad.Close()
	if _, err := bad.Collect(ctx); err == nil || !strings.Contains(err.Error(), "denied access") {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestKeeneticAuthAndParse(t *testing.T) {
	var mu sync.Mutex
	authed := false
	var posted [][]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			if c, err := r.Cookie("session"); err == nil && c.Value == "1" {
				return
			}
			w.Header().Set("X-NDM-Realm", "Keenetic")
			w.Header().Set("X-NDM-Challenge", "CH")
			w.WriteHeader(401)
			return
		case r.URL.Path == "/auth" && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			m := md5.Sum([]byte("admin:Keenetic:pw")) //nolint:gosec // protocol
			s := sha256.Sum256([]byte("CH" + hex.EncodeToString(m[:])))
			if body["password"] != hex.EncodeToString(s[:]) {
				w.WriteHeader(401)
				return
			}
			authed = true
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "1", Path: "/"})
			return
		}
		if c, err := r.Cookie("session"); !authed || err != nil || c.Value != "1" {
			w.WriteHeader(401)
			return
		}
		var v any
		switch r.URL.Path {
		case "/rci/show/version":
			v = map[string]any{"model": "Keenetic Giga", "release": "4.1.1"}
		case "/rci/show/system":
			v = map[string]any{"hostname": "home", "uptime": "100", "cpuload": 5, "memory": "50/200"}
		case "/rci/show/interface":
			v = map[string]any{"GigabitEthernet1": map[string]any{"id": "GigabitEthernet1", "type": "GigabitEthernet", "link": "up",
				"state": "up", "mac": "50:ff:20:00:00:01"}}
		case "/rci/show/ip/hotspot":
			v = map[string]any{"host": []any{map[string]any{"mac": "3c:22:fb:00:00:01", "ip": "192.168.1.33", "name": "Mac",
				"ssid": "Home", "rssi": -48, "access": "permit"}}}
		case "/rci/":
			var body []map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			posted = append(posted, body)
			v = []any{map[string]any{"parse": map[string]any{"status": []any{map[string]any{"status": "message"}}}}}
		default:
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	defer srv.Close()
	ctx := context.Background()
	p, _ := Lookup("keenetic")
	d, _ := p.Driver(targetOf(t, srv, "http"), Credentials{Username: "admin", Password: "pw"})
	defer d.Close()
	snap, err := d.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Facts.Model != "Keenetic Giga" || *snap.Facts.MemoryPercent != 25 || snap.Facts.Hostname != "home" {
		t.Fatalf("facts %+v", snap.Facts)
	}
	if len(snap.Endpoints) != 1 || snap.Endpoints[0].Source != SourceWiFi || *snap.Endpoints[0].Signal != -48 {
		t.Fatalf("endpoints %+v", snap.Endpoints)
	}
	bp, _ := ValidateAction(ActionEndpointBlock, Params{MAC: "3C:22:FB:00:00:01"})
	if _, err := d.Apply(ctx, ActionEndpointBlock, bp); err != nil {
		t.Fatal(err)
	}
	last := posted[len(posted)-1]
	if Str(last[0]["parse"]) != "ip hotspot host 3c:22:fb:00:00:01 deny" || Str(last[1]["parse"]) != "system configuration save" {
		t.Fatalf("posted %v", last)
	}
	bad, _ := p.Driver(targetOf(t, srv, "http"), Credentials{Username: "admin", Password: "nope"})
	defer bad.Close()
	if _, err := bad.Collect(ctx); err == nil || !strings.Contains(err.Error(), "wrong login") {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestOmadaController(t *testing.T) {
	var blocked []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v any
		switch {
		case r.URL.Path == "/api/info":
			v = map[string]any{"errorCode": 0, "result": map[string]any{"omadacId": "cid1", "controllerVer": "5.13", "name": "oc200"}}
		case r.URL.Path == "/openapi/authorize/token":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["client_id"] != "id" || body["client_secret"] != "sec" || r.URL.Query().Get("grant_type") != "client_credentials" {
				v = map[string]any{"errorCode": -44112, "msg": "Invalid client credentials"}
			} else {
				v = map[string]any{"errorCode": 0, "result": map[string]any{"accessToken": "TOK"}}
			}
		case r.Header.Get("Authorization") != "AccessToken=TOK":
			w.WriteHeader(401)
			return
		case r.URL.Path == "/openapi/v1/cid1/sites":
			v = map[string]any{"errorCode": 0, "result": map[string]any{"data": []any{
				map[string]any{"siteId": "s0", "name": "Default"}, map[string]any{"siteId": "s1", "name": "Office"}}}}
		case r.URL.Path == "/openapi/v1/cid1/sites/s1/devices":
			v = map[string]any{"errorCode": 0, "result": map[string]any{"data": []any{
				map[string]any{"mac": "AA-BB-CC-00-00-01", "name": "ap-1", "model": "EAP650", "type": "ap", "ip": "10.0.0.5", "status": 1,
					"uplinkDeviceMac": "AA-BB-CC-00-00-02", "clientNum": 3}}}}
		case r.URL.Path == "/openapi/v1/cid1/sites/s1/clients":
			v = map[string]any{"errorCode": 0, "result": map[string]any{"data": []any{
				map[string]any{"mac": "11-22-33-44-55-66", "ip": "10.0.0.50", "name": "phone", "wireless": true, "ssid": "Office",
					"rssi": -60, "apMac": "AA-BB-CC-00-00-01"}}}}
		case strings.HasPrefix(r.URL.Path, "/openapi/v1/cid1/sites/s1/clients/"):
			blocked = append(blocked, r.URL.Path)
			v = map[string]any{"errorCode": 0}
		default:
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	defer srv.Close()
	p, _ := Lookup("omada")
	tg := targetOf(t, srv, "https")
	tg.Site = "office"
	d, _ := p.Driver(tg, Credentials{APIKey: "id", APISecret: "sec"})
	defer d.Close()
	ctx := context.Background()
	snap, err := d.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Children) != 1 || snap.Children[0].MAC != "aa:bb:cc:00:00:01" || !snap.Children[0].Online || snap.Children[0].Kind != "ap" {
		t.Fatalf("children %+v", snap.Children)
	}
	e := snap.Endpoints[0]
	if e.Source != SourceController || e.AttachedTo != "aa:bb:cc:00:00:01" || e.SSID != "Office" || snap.Facts.Version != "5.13" {
		t.Fatalf("endpoint %+v facts %+v", e, snap.Facts)
	}
	if _, err := d.Apply(ctx, ActionEndpointBlock, Params{MAC: "11:22:33:44:55:66", Blocked: P(true)}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(blocked, []string{"/openapi/v1/cid1/sites/s1/clients/11-22-33-44-55-66/block"}) {
		t.Fatalf("block %v", blocked)
	}
	bad, _ := p.Driver(tg, Credentials{APIKey: "id", APISecret: "x"})
	defer bad.Close()
	if _, err := bad.Collect(ctx); err == nil || !strings.Contains(err.Error(), "Invalid client credentials") {
		t.Fatalf("bad secret: %v", err)
	}
}

// fakeSNMP serves fixed variables.
type fakeSNMP struct {
	vars map[string]Var
	sets []Var
}

func (f *fakeSNMP) Get(_ context.Context, oids ...string) (map[string]Var, error) {
	out := map[string]Var{}
	for _, o := range oids {
		if v, ok := f.vars[o]; ok {
			out[o] = v
		}
	}
	return out, nil
}

func (f *fakeSNMP) Walk(_ context.Context, oid string) (map[string]Var, error) {
	out := map[string]Var{}
	for k, v := range f.vars {
		if strings.HasPrefix(k, oid+".") {
			out[k[len(oid)+1:]] = v
		}
	}
	return out, nil
}

func (f *fakeSNMP) Set(_ context.Context, v Var) error { f.sets = append(f.sets, v); return nil }
func (f *fakeSNMP) Close()                             {}

func TestSNMPDriver(t *testing.T) {
	str := func(s string) Var { return Var{Type: gosnmp.OctetString, Value: []byte(s)} }
	num := func(n int) Var { return Var{Type: gosnmp.Integer, Value: n} }
	f := &fakeSNMP{vars: map[string]Var{
		oidSysDescr: str("TL-SG2008 8-Port Gigabit Smart Switch"), oidSysObjectID: {Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.11863.5.1"},
		oidSysUpTime: {Type: gosnmp.TimeTicks, Value: uint32(360000)}, oidSysName: str("sw-office"),
		ifCols["descr"] + ".1": str("port 1"), ifCols["descr"] + ".2": str("port 2"),
		ifCols["name"] + ".1": str("gi1"), ifCols["name"] + ".2": str("gi2"),
		ifCols["type"] + ".1": num(6), ifCols["type"] + ".2": num(6),
		ifCols["mac"] + ".1":   {Type: gosnmp.OctetString, Value: []byte{0x50, 0xd4, 0xf7, 0, 0, 1}},
		ifCols["admin"] + ".1": num(1), ifCols["admin"] + ".2": num(2), ifCols["oper"] + ".1": num(1), ifCols["oper"] + ".2": num(2),
		ifCols["highspeed"] + ".1": {Type: gosnmp.Gauge32, Value: uint(1000)},
		ifCols["hcin"] + ".1":      {Type: gosnmp.Counter64, Value: uint64(1 << 40)}, ifCols["in"] + ".1": {Type: gosnmp.Counter32, Value: uint(5)},
		ifCols["alias"] + ".1":       str("uplink"),
		oidIPAddrIf + ".192.168.0.3": num(1), oidIPAddrMask + ".192.168.0.3": {Type: gosnmp.IPAddress, Value: "255.255.255.0"},
		oidARP + ".1.192.168.0.50": {Type: gosnmp.OctetString, Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
		oidBridgeIf + ".2":         num(2), oidBridgeIf + ".1": num(1),
		oidQFDBPort + ".10.17.34.51.68.85.102": num(2), oidQFDBPort + ".1.170.0.0.0.0.1": num(1),
		oidLLDPLocPort + ".1":      str("gi1"),
		lldpRem["name"] + ".0.1.1": str("gw"), lldpRem["chassis"] + ".0.1.1": {Type: gosnmp.OctetString, Value: []byte{0xaa, 0, 0, 0, 0, 1}},
		lldpRem["port"] + ".0.1.1": str("ether2"),
	}}
	old := NewSNMPClient
	NewSNMPClient = func(Target, Credentials) (SNMPClient, error) { return f, nil }
	defer func() { NewSNMPClient = old }()
	p, _ := Lookup("tplink")
	d, _ := p.Driver(Target{Host: "192.168.0.3"}, Credentials{SNMPCommunity: "public"})
	snap, err := d.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Facts.Hostname != "sw-office" || snap.Facts.Vendor != "TP-Link" || *snap.Facts.UptimeSeconds != 3600 || snap.Facts.MAC != "50:d4:f7:00:00:01" {
		t.Fatalf("facts %+v", snap.Facts)
	}
	g1 := snap.Interfaces[0]
	if g1.Name != "gi1" || *g1.Index != 1 || *g1.SpeedMbps != 1000 || *g1.RxBytes != 1<<40 || g1.Description != "uplink" ||
		!reflect.DeepEqual(g1.Addresses, []string{"192.168.0.3/24"}) || *snap.Interfaces[1].AdminUp {
		t.Fatalf("interfaces %+v", snap.Interfaces)
	}
	if len(snap.Neighbors) != 1 || snap.Neighbors[0].LocalInterface != "gi1" || snap.Neighbors[0].RemoteMAC != "aa:00:00:00:00:01" {
		t.Fatalf("neighbors %+v", snap.Neighbors)
	}
	var eps []string
	for _, e := range snap.Endpoints {
		eps = append(eps, e.Source+" "+e.MAC+" "+e.Interface)
	}
	// The MAC learned on the LLDP uplink gi1 is not a client of the switch.
	if !reflect.DeepEqual(eps, []string{"arp 11:22:33:44:55:66 gi1", "bridge 11:22:33:44:55:66 gi2"}) {
		t.Fatalf("endpoints %v", eps)
	}
	if _, err := d.Apply(context.Background(), ActionInterface, Params{Name: "gi2", Enabled: P(true)}); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 1 || f.sets[0].OID != ifCols["admin"]+".2" || f.sets[0].Value != 1 {
		t.Fatalf("sets %+v", f.sets)
	}
	if _, err := d.Apply(context.Background(), ActionReboot, Params{}); err == nil {
		t.Fatal("SNMP reboot accepted")
	}
}

func TestRegistry(t *testing.T) {
	var all []string
	for _, p := range Platforms {
		all = append(all, strings.ToLower(p.Vendor+" "+p.Title))
	}
	text := strings.Join(all, " ")
	for _, brand := range []string{"tp-link", "omada", "mikrotik", "opnsense", "routeros", "pfsense", "openwrt", "keenetic", "cisco",
		"unifi", "zyxel", "hp", "dell", "juniper", "huawei", "fortinet", "eltex", "netgear", "d-link", "meraki", "gnmi"} {
		if !strings.Contains(text, brand) {
			t.Errorf("no platform for %s", brand)
		}
	}
	if len(Platforms) != 29 {
		t.Errorf("%d platforms, want the 28 of Network Control and gNMI", len(Platforms))
	}
	seen := map[string]bool{}
	for _, p := range Platforms {
		if seen[p.Key] {
			t.Errorf("duplicate %s", p.Key)
		}
		seen[p.Key] = true
		for _, tr := range p.Transports {
			d, err := p.Driver(Target{Host: "192.0.2.1", Transport: tr.Name}, Credentials{})
			if err != nil || d == nil {
				t.Errorf("%s/%s: %v", p.Key, tr.Name, err)
				continue
			}
			d.Close()
		}
		if _, err := p.Driver(Target{Host: "192.0.2.1", Transport: "telnet"}, Credentials{}); err == nil {
			t.Errorf("%s accepts telnet", p.Key)
		}
		for _, f := range p.Credentials {
			if _, ok := (&Credentials{}).Fields()[f]; !ok {
				t.Errorf("%s: unknown credential field %s", p.Key, f)
			}
		}
	}
	c, _ := Lookup("cisco_ios")
	if caps := c.Capabilities("ssh"); !slices.Equal(caps[:2], []string{ActionHostname, ActionInterface}) || !slices.Contains(caps, ActionFlowExport) {
		t.Fatalf("cisco caps %v", caps)
	}
	if caps := c.Capabilities("snmp"); !slices.Equal(caps, []string{ActionHostname, ActionInterface}) {
		t.Fatalf("cisco snmp caps %v", caps)
	}
	m, _ := Lookup("mikrotik")
	if m.DefaultTransport() != "api" || m.Port("api") != 443 {
		t.Fatal("mikrotik default transport")
	}
	if _, err := Lookup("nope"); err == nil {
		t.Fatal("unknown platform found")
	}
}

func TestHosts(t *testing.T) {
	h, err := Hosts("192.168.1.0/30", 1024)
	if err != nil || len(h) != 2 || h[0].String() != "192.168.1.1" {
		t.Fatalf("%v %v", h, err)
	}
	if h, _ := Hosts("192.168.1.7", 1024); len(h) != 1 {
		t.Fatal("single host")
	}
	if _, err := Hosts("10.0.0.0/21", 1024); err == nil {
		t.Fatal("/21 accepted")
	}
	if h, err := Hosts("10.0.0.0/22", 1024); err != nil || len(h) != 1022 {
		t.Fatalf("/22: %d %v", len(h), err)
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "SSH-2.0-ROSSSH\r\n")
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	p := &Prober{Ports: []int{22}, Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
		if strings.HasSuffix(a, ":22") {
			return net.Dial("tcp", addr)
		}
		return nil, io.EOF
	}, SNMP: func(Target, Credentials) (SNMPClient, error) {
		return &fakeSNMP{vars: map[string]Var{oidSysObjectID: {Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.14988.1"},
			oidSysName: {Type: gosnmp.OctetString, Value: []byte("gw")}, oidSysDescr: {Type: gosnmp.OctetString, Value: []byte("RouterOS RB5009")}}}, nil
	}}
	f := p.Probe(context.Background(), "192.0.2.10", "public")
	if !f.Reachable || !slices.Equal(f.Ports, []int{22}) || len(f.Platforms) == 0 || f.Platforms[0] != "mikrotik" || f.Name != "gw" {
		t.Fatalf("%+v", f)
	}
}
