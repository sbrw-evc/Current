package drivers

// Controllers that manage many devices: TP-Link Omada, Ubiquiti UniFi,
// Cisco Meraki, and servers through their BMC (Redfish). The controller
// itself is the managed device; its access points, switches and gateways
// become children and their clients endpoints attached to them.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func dashMAC(mac string) string { return strings.ToUpper(strings.ReplaceAll(mac, ":", "-")) }

// ---------------- Omada ----------------

// ControllerCaps are the actions of Omada and UniFi.
var ControllerCaps = []string{ActionReboot, ActionEndpointBlock}

// OmadaDriver is the TP-Link Omada SDN controller (software, OC200 / OC300)
// via the Open API: an application with client credentials under Settings →
// Platform Integration → Open API.
type OmadaDriver struct {
	httpDriver
	cid, site string
}

// NewOmada returns the driver (port 8043 by default).
func NewOmada(t Target, c Credentials, vendor string) *OmadaDriver {
	return &OmadaDriver{httpDriver: httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 8043)}}
}

func (d *OmadaDriver) auth(ctx context.Context) error {
	if d.cid != "" {
		return nil
	}
	info, err := d.http.GetObj(ctx, "/api/info", false, nil)
	if err != nil {
		return err
	}
	cid := Str(O(info, "result")["omadacId"])
	if cid == "" {
		return Errorf("%s: this is not an Omada controller (no omadacId)", d.t.Host)
	}
	raw, err := d.http.Send(ctx, http.MethodPost, "/openapi/authorize/token?grant_type=client_credentials",
		Obj{"omadacId": cid, "client_id": d.c.APIKey, "client_secret": d.c.APISecret}, 0)
	if err != nil {
		return err
	}
	data := asObj(raw)
	token := Str(O(data, "result")["accessToken"])
	if token == "" {
		return Errorf("Omada: %s", or(Str(data["msg"]), "no token issued, check the Client ID / Secret"))
	}
	d.http.Header.Set("Authorization", "AccessToken="+token)
	d.cid = cid
	sites, err := d.open(ctx, "/openapi/v1/"+cid+"/sites", "page", "1", "pageSize", "100")
	if err != nil {
		d.cid = ""
		return err
	}
	rows := L(asObj(sites)["data"])
	wanted := strings.ToLower(strings.TrimSpace(d.t.Site))
	var site Obj
	for _, s := range rows {
		if wanted != "" && (strings.ToLower(Str(s["name"])) == wanted || strings.ToLower(Str(s["siteId"])) == wanted) {
			site = s
			break
		}
	}
	if site == nil && len(rows) > 0 {
		site = rows[0]
	}
	if site == nil {
		d.cid = ""
		return Errorf("Omada: the controller has no sites")
	}
	d.site = Str(site["siteId"])
	return nil
}

func (d *OmadaDriver) open(ctx context.Context, path string, kv ...string) (any, error) {
	r, err := d.http.GetObj(ctx, path, false, q(kv...))
	if err != nil {
		return nil, err
	}
	if code, _ := ToInt(r["errorCode"]); code != 0 {
		return nil, Errorf("Omada: %s", or(Str(r["msg"]), "API error"))
	}
	return r["result"], nil
}

// Collect implements Driver.
func (d *OmadaDriver) Collect(ctx context.Context) (*Snapshot, error) {
	if err := d.auth(ctx); err != nil {
		return nil, err
	}
	info, _ := d.http.GetObj(ctx, "/api/info", true, nil)
	res := O(info, "result")
	prefix := fmt.Sprintf("/openapi/v1/%s/sites/%s", d.cid, d.site)
	devs, err := d.open(ctx, prefix+"/devices", "page", "1", "pageSize", "1000")
	if err != nil {
		return nil, err
	}
	clients, _ := d.open(ctx, prefix+"/clients", "page", "1", "pageSize", "1000")
	snap := &Snapshot{}
	for _, x := range L(asObj(devs)["data"]) {
		mac := NormMAC(Str(x["mac"]))
		if mac == "" {
			continue
		}
		st, _ := ToInt(x["status"])
		snap.Children = append(snap.Children, Child{MAC: mac, Name: Str(x["name"]), Model: S(x, "model", "showModel"),
			Kind: strings.ToLower(or(Str(x["type"]), "other")), IP: NormIP(Str(x["ip"])),
			Online: st == 1 || st == 2 || st == 14 || Str(x["statusCategory"]) == "1", Version: Str(x["firmwareVersion"]),
			UplinkMAC: NormMAC(Str(x["uplinkDeviceMac"])), UplinkPort: Str(x["uplinkDevicePort"]), Clients: IntP(x["clientNum"])})
	}
	for _, c := range L(asObj(clients)["data"]) {
		mac := NormMAC(Str(c["mac"]))
		if mac == "" {
			continue
		}
		e := Endpoint{MAC: mac, IP: NormIP(Str(c["ip"])), Hostname: S(c, "name", "hostName"), Source: SourceController,
			Port: Str(c["port"]), VLAN: IntP(c["vid"]), Blocked: ToBool(c["block"])}
		if ToBool(c["wireless"]) {
			e.SSID, e.Signal, e.AttachedTo = Str(c["ssid"]), IntP(c["rssi"]), NormMAC(Str(c["apMac"]))
		} else {
			e.AttachedTo = NormMAC(S(c, "switchMac", "gatewayMac"))
		}
		snap.Endpoints = append(snap.Endpoints, e)
	}
	snap.Facts = Facts{Hostname: or(Str(res["name"]), "Omada Controller"), Vendor: "TP-Link", Model: "Omada Controller",
		OS: "Omada SDN", Version: Str(res["controllerVer"]),
		Extra: map[string]any{"site": d.site, "devices": len(snap.Children), "clients": len(snap.Endpoints)}}
	return snap, nil
}

// Apply implements Driver.
func (d *OmadaDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	if action != ActionReboot && action != ActionEndpointBlock {
		return "", Unsupported("Omada", action)
	}
	if err := d.auth(ctx); err != nil {
		return "", err
	}
	prefix := fmt.Sprintf("/openapi/v1/%s/sites/%s", d.cid, d.site)
	if action == ActionReboot {
		mac := NormMAC(p.MAC)
		if mac == "" {
			return "", Errorf("Specify the MAC of the Omada device to reboot")
		}
		if _, err := d.http.Send(ctx, http.MethodPost, prefix+"/devices/"+dashMAC(mac)+"/reboot", Obj{}, 0); err != nil {
			return "", err
		}
		return "Reboot started", nil
	}
	verb := map[bool]string{true: "block", false: "unblock"}[p.IsBlocked()]
	if _, err := d.http.Send(ctx, http.MethodPost, prefix+"/clients/"+dashMAC(p.MAC)+"/"+verb, Obj{}, 0); err != nil {
		return "", err
	}
	return map[bool]string{true: "Client blocked", false: "Client unblocked"}[p.IsBlocked()], nil
}

// ---------------- UniFi ----------------

var unifiKind = map[string]string{"uap": "ap", "usw": "switch", "ugw": "gateway", "udm": "gateway", "uxg": "gateway", "ucg": "gateway"}

// UnifiDriver is Ubiquiti UniFi Network: UniFi OS consoles (UDM, UCG, Cloud
// Key Gen2+) and the self-hosted controller. It logs in with a local user
// (or an API key); the site is "default" unless set.
type UnifiDriver struct {
	httpDriver
	prefix *string
	site   string
}

// NewUnifi returns the driver.
func NewUnifi(t Target, c Credentials, vendor string) *UnifiDriver {
	return &UnifiDriver{httpDriver: httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)},
		site: or(strings.TrimSpace(t.Site), "default")}
}

func (d *UnifiDriver) login(ctx context.Context) error {
	if d.prefix != nil {
		return nil
	}
	if d.c.APIKey != "" {
		d.http.Header.Set("X-API-KEY", d.c.APIKey)
		d.prefix = P("/proxy/network")
		return nil
	}
	_, hdr, err := d.http.Do(ctx, http.MethodPost, "/api/auth/login", nil,
		Obj{"username": d.c.Username, "password": d.c.Password, "remember": false}, 0)
	if err == nil {
		if csrf := or(hdr.Get("X-Csrf-Token"), hdr.Get("X-Updated-Csrf-Token")); csrf != "" {
			d.http.Header.Set("X-CSRF-Token", csrf)
		}
		d.prefix = P("/proxy/network")
		return nil
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return d.http.Error(err)
	}
	if se.Code != 404 && se.Code != 405 {
		return Errorf("UniFi: login failed (%d)", se.Code)
	}
	if _, _, err := d.http.Do(ctx, http.MethodPost, "/api/login", nil, Obj{"username": d.c.Username, "password": d.c.Password}, 0); err != nil {
		if errors.As(err, &se) {
			return Errorf("UniFi: login failed (%d)", se.Code)
		}
		return d.http.Error(err)
	}
	d.prefix = P("")
	return nil
}

func (d *UnifiDriver) api(ctx context.Context, path string, optional bool) ([]Obj, error) {
	if err := d.login(ctx); err != nil {
		return nil, err
	}
	r, err := d.http.GetObj(ctx, fmt.Sprintf("%s/api/s/%s/%s", *d.prefix, d.site, path), optional, nil)
	if err != nil {
		return nil, err
	}
	return L(r["data"]), nil
}

// Collect implements Driver.
func (d *UnifiDriver) Collect(ctx context.Context) (*Snapshot, error) {
	devices, err := d.api(ctx, "stat/device", false)
	if err != nil {
		return nil, err
	}
	sysinfo := Obj{}
	if rows, _ := d.api(ctx, "stat/sysinfo", true); len(rows) > 0 {
		sysinfo = rows[0]
	}
	clients, _ := d.api(ctx, "stat/sta", true)
	snap := &Snapshot{}
	for _, x := range devices {
		mac := NormMAC(Str(x["mac"]))
		if mac == "" {
			continue
		}
		up := O(x, "uplink")
		kind := unifiKind[Str(x["type"])]
		if kind == "" {
			kind = "other"
		}
		state, _ := ToInt(x["state"])
		snap.Children = append(snap.Children, Child{MAC: mac, Name: S(x, "name", "model"), Model: Str(x["model"]), Kind: kind,
			IP: NormIP(Str(x["ip"])), Online: state == 1, Version: Str(x["version"]), UplinkMAC: NormMAC(Str(up["uplink_mac"])),
			UplinkPort: Str(up["uplink_remote_port"]), Clients: IntP(x["num_sta"])})
		for _, port := range L(x["port_table"]) {
			enabled := true
			if v, ok := port["enable"]; ok {
				enabled = ToBool(v)
			}
			snap.Interfaces = append(snap.Interfaces, Interface{Name: or(Str(x["name"]), mac) + "/" + Str(port["port_idx"]),
				Description: Str(port["name"]), OperUp: P(ToBool(port["up"])), AdminUp: P(enabled), SpeedMbps: IntP(port["speed"]),
				RxBytes: UintP(port["rx_bytes"]), TxBytes: UintP(port["tx_bytes"])})
		}
	}
	for _, c := range clients {
		mac := NormMAC(Str(c["mac"]))
		if mac == "" {
			continue
		}
		e := Endpoint{MAC: mac, IP: NormIP(S(c, "ip", "last_ip")), Hostname: S(c, "name", "hostname"), Source: SourceController,
			Port: Str(c["sw_port"]), VLAN: IntP(c["vlan"]), Blocked: ToBool(c["blocked"])}
		if rx, ok := c["rx_bytes-r"].(float64); ok {
			e.RxRate = &rx
		}
		if tx, ok := c["tx_bytes-r"].(float64); ok {
			e.TxRate = &tx
		}
		if ToBool(c["is_wired"]) {
			e.AttachedTo = NormMAC(Str(c["sw_mac"]))
		} else {
			e.SSID, e.AttachedTo = Str(c["essid"]), NormMAC(Str(c["ap_mac"]))
			e.Signal = IntP(c["signal"])
			if e.Signal == nil {
				e.Signal = IntP(c["rssi"])
			}
		}
		snap.Endpoints = append(snap.Endpoints, e)
	}
	snap.Facts = Facts{Hostname: or(S(sysinfo, "hostname", "name"), "UniFi Network"), Vendor: "Ubiquiti", Model: "UniFi Network",
		OS: "UniFi Network", Version: Str(sysinfo["version"]), UptimeSeconds: IntP(sysinfo["uptime"]),
		Extra: map[string]any{"site": d.site, "devices": len(snap.Children), "clients": len(snap.Endpoints)}}
	return snap, nil
}

// Apply implements Driver.
func (d *UnifiDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	if action != ActionReboot && action != ActionEndpointBlock {
		return "", Unsupported("UniFi", action)
	}
	if err := d.login(ctx); err != nil {
		return "", err
	}
	prefix := fmt.Sprintf("%s/api/s/%s/cmd", *d.prefix, d.site)
	if action == ActionReboot {
		mac := NormMAC(p.MAC)
		if mac == "" {
			return "", Errorf("Specify the MAC of the UniFi device to reboot")
		}
		if _, err := d.http.Send(ctx, http.MethodPost, prefix+"/devmgr", Obj{"cmd": "restart", "mac": mac}, 0); err != nil {
			return "", err
		}
		return "Reboot started", nil
	}
	cmd := map[bool]string{true: "block-sta", false: "unblock-sta"}[p.IsBlocked()]
	if _, err := d.http.Send(ctx, http.MethodPost, prefix+"/stamgr", Obj{"cmd": cmd, "mac": p.MAC}, 0); err != nil {
		return "", err
	}
	return map[bool]string{true: "Client blocked", false: "Client unblocked"}[p.IsBlocked()], nil
}

// ---------------- Meraki ----------------

// MerakiCaps are the actions of the Meraki Dashboard.
var MerakiCaps = []string{ActionReboot}

// MerakiDriver is the Cisco Meraki Dashboard API v1. The host is
// api.meraki.com (or a regional endpoint); the site is the organisation ID
// or name (the first organisation by default).
type MerakiDriver struct{ httpDriver }

// NewMeraki returns the driver.
func NewMeraki(t Target, c Credentials, vendor string) *MerakiDriver {
	if t.Timeout == 0 {
		t.Timeout = 40 * time.Second
	}
	d := &MerakiDriver{httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)}}
	d.http.Header.Set("Authorization", "Bearer "+c.APIKey)
	return d
}

func (d *MerakiDriver) org(ctx context.Context) (Obj, error) {
	v, err := d.http.Get(ctx, "/api/v1/organizations", false, nil)
	if err != nil {
		return nil, err
	}
	orgs := L(v)
	wanted := strings.ToLower(strings.TrimSpace(d.t.Site))
	for _, o := range orgs {
		if wanted != "" && (strings.ToLower(Str(o["id"])) == wanted || strings.ToLower(Str(o["name"])) == wanted) {
			return o, nil
		}
	}
	if len(orgs) == 0 {
		return nil, Errorf("Meraki: the key sees no organizations")
	}
	return orgs[0], nil
}

func (d *MerakiDriver) devices(ctx context.Context, org Obj) ([]Obj, error) {
	v, err := d.http.Get(ctx, "/api/v1/organizations/"+Str(org["id"])+"/devices", false, q("perPage", "1000"))
	return L(v), err
}

// Collect implements Driver.
func (d *MerakiDriver) Collect(ctx context.Context) (*Snapshot, error) {
	org, err := d.org(ctx)
	if err != nil {
		return nil, err
	}
	devices, err := d.devices(ctx, org)
	if err != nil {
		return nil, err
	}
	sv, _ := d.http.Get(ctx, "/api/v1/organizations/"+Str(org["id"])+"/devices/statuses", true, q("perPage", "1000"))
	statuses := map[string]Obj{}
	for _, s := range L(sv) {
		statuses[Str(s["serial"])] = s
	}
	kind := map[string]string{"wireless": "ap", "switch": "switch", "appliance": "gateway", "cellularGateway": "gateway"}
	snap := &Snapshot{}
	nets := map[string]bool{}
	for _, x := range devices {
		if n := Str(x["networkId"]); n != "" {
			nets[n] = true
		}
		mac := NormMAC(Str(x["mac"]))
		if mac == "" {
			continue
		}
		k := kind[Str(x["productType"])]
		if k == "" {
			k = "other"
		}
		status := "online"
		if s, ok := statuses[Str(x["serial"])]; ok {
			status = or(Str(s["status"]), "online")
		}
		snap.Children = append(snap.Children, Child{MAC: mac, Name: S(x, "name", "serial"), Model: Str(x["model"]), Kind: k,
			IP: NormIP(Str(x["lanIp"])), Online: status == "online", Version: Str(x["firmware"])})
	}
	ids := make([]string, 0, len(nets))
	for n := range nets {
		ids = append(ids, n)
	}
	sort.Strings(ids)
	for _, n := range ids {
		cv, _ := d.http.Get(ctx, "/api/v1/networks/"+n+"/clients", true, q("timespan", "900", "perPage", "1000"))
		for _, c := range L(cv) {
			if mac := NormMAC(Str(c["mac"])); mac != "" {
				snap.Endpoints = append(snap.Endpoints, Endpoint{MAC: mac, IP: NormIP(Str(c["ip"])), Hostname: S(c, "description", "dhcpHostname"),
					Source: SourceController, SSID: Str(c["ssid"]), AttachedTo: NormMAC(Str(c["recentDeviceMac"])),
					Port: Str(c["switchport"]), VLAN: IntP(c["vlan"])})
			}
		}
	}
	snap.Facts = Facts{Hostname: or(Str(org["name"]), "Meraki"), Vendor: "Cisco Meraki", Model: "Meraki Dashboard", OS: "Meraki",
		Extra: map[string]any{"organization": org["id"], "devices": len(snap.Children)}}
	return snap, nil
}

// Apply implements Driver.
func (d *MerakiDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	if action != ActionReboot {
		return "", Unsupported("Meraki", action)
	}
	mac := NormMAC(p.MAC)
	org, err := d.org(ctx)
	if err != nil {
		return "", err
	}
	devices, err := d.devices(ctx, org)
	if err != nil {
		return "", err
	}
	for _, x := range devices {
		if mac != "" && NormMAC(Str(x["mac"])) == mac {
			if _, err := d.http.Send(ctx, http.MethodPost, "/api/v1/devices/"+Str(x["serial"])+"/reboot", Obj{}, 0); err != nil {
				return "", err
			}
			return "Reboot started", nil
		}
	}
	return "", Errorf("Meraki: no device with this MAC")
}

// ---------------- Redfish ----------------

// RedfishCaps are the actions of a BMC.
var RedfishCaps = []string{ActionHostname, ActionReboot}

// RedfishDriver manages servers through their BMC: Dell iDRAC, HPE iLO,
// Lenovo XClarity, Supermicro, Fujitsu iRMC (DMTF Redfish).
type RedfishDriver struct{ httpDriver }

// NewRedfish returns the driver.
func NewRedfish(t Target, c Credentials, vendor string) *RedfishDriver {
	d := &RedfishDriver{httpDriver{base: base{t, c, vendor}, http: NewHTTP(t, "https", 0)}}
	d.http.User, d.http.Pass = c.Username, c.Password
	return d
}

func (d *RedfishDriver) system(ctx context.Context) (string, Obj, error) {
	r, err := d.http.GetObj(ctx, "/redfish/v1/Systems", false, nil)
	if err != nil {
		return "", nil, err
	}
	members := L(r["Members"])
	if len(members) == 0 {
		return "", nil, Errorf("Redfish: no systems found")
	}
	path := Str(members[0]["@odata.id"])
	s, err := d.http.GetObj(ctx, path, false, nil)
	return path, s, err
}

// Collect implements Driver.
func (d *RedfishDriver) Collect(ctx context.Context) (*Snapshot, error) {
	path, s, err := d.system(ctx)
	if err != nil {
		return nil, err
	}
	mgrs, _ := d.http.GetObj(ctx, "/redfish/v1/Managers", true, nil)
	mgr := Obj{}
	if m := L(mgrs["Members"]); len(m) > 0 {
		mgr, _ = d.http.GetObj(ctx, Str(m[0]["@odata.id"]), true, nil)
	}
	mem, cpu := O(s, "MemorySummary"), O(s, "ProcessorSummary")
	snap := &Snapshot{Facts: Facts{Hostname: S(s, "HostName", "Name"), Vendor: Str(s["Manufacturer"]), Model: Str(s["Model"]),
		OS: "Redfish", Version: Str(s["BiosVersion"]), Serial: Str(s["SerialNumber"]),
		Extra: map[string]any{"power": s["PowerState"], "health": O(s, "Status")["Health"], "bmc_firmware": mgr["FirmwareVersion"],
			"cpus": cpu["Count"], "cpu_model": cpu["Model"], "memory_gib": mem["TotalSystemMemoryGiB"]}}}
	nics, _ := d.http.GetObj(ctx, path+"/EthernetInterfaces", true, nil)
	members := L(nics["Members"])
	if len(members) > 32 {
		members = members[:32]
	}
	for _, m := range members {
		n, _ := d.http.GetObj(ctx, Str(m["@odata.id"]), true, nil)
		var addrs []string
		for _, a := range L(n["IPv4Addresses"]) {
			if ip := Str(a["Address"]); ip != "" {
				addrs = append(addrs, addr(ip, MaskBits(Str(a["SubnetMask"]))))
			}
		}
		enabled := true
		if v, ok := n["InterfaceEnabled"].(bool); ok {
			enabled = v
		}
		snap.Interfaces = append(snap.Interfaces, Interface{Name: S(n, "Id", "Name"), Description: Str(n["Description"]),
			MAC: NormMAC(S(n, "MACAddress", "PermanentMACAddress")), OperUp: P(strings.EqualFold(Str(n["LinkStatus"]), "linkup")),
			AdminUp: P(enabled), SpeedMbps: IntP(n["SpeedMbps"]), Addresses: addrs})
	}
	for _, i := range snap.Interfaces {
		if i.MAC != "" {
			snap.Facts.MAC = i.MAC
			break
		}
	}
	return snap, nil
}

// Apply implements Driver.
func (d *RedfishDriver) Apply(ctx context.Context, action string, p Params) (string, error) {
	if action != ActionReboot && action != ActionHostname {
		return "", Unsupported("Redfish", action)
	}
	path, _, err := d.system(ctx)
	if err != nil {
		return "", err
	}
	if action == ActionReboot {
		if _, err := d.http.Send(ctx, http.MethodPost, path+"/Actions/ComputerSystem.Reset", Obj{"ResetType": "GracefulRestart"}, 0); err != nil {
			return "", err
		}
		return "Reboot started", nil
	}
	if _, err := d.http.Send(ctx, http.MethodPatch, path, Obj{"HostName": p.Name}, 0); err != nil {
		return "", err
	}
	return "Done", nil
}
