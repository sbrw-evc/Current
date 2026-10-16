package devices

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// The network map, built from what the devices report: LLDP / CDP / MNDP
// neighbours, controller uplinks and clients on ports and Wi-Fi.

// Node is a node of the map.
type Node struct {
	ID            string     `json:"id"`
	Type          string     `json:"type"` // device | child | neighbor | endpoint | internet
	Label         string     `json:"label"`
	Role          string     `json:"role,omitempty"`
	Status        string     `json:"status"`
	Vendor        string     `json:"vendor,omitempty"`
	Model         string     `json:"model,omitempty"`
	IP            string     `json:"ip,omitempty"`
	MAC           string     `json:"mac,omitempty"`
	DeviceID      int64      `json:"device_id,omitempty"`
	Platform      string     `json:"platform,omitempty"`
	Site          string     `json:"site,omitempty"`
	X             *float64   `json:"x,omitempty"`
	Y             *float64   `json:"y,omitempty"`
	Clients       int        `json:"clients"`
	Interfaces    int        `json:"interfaces,omitempty"`
	Error         string     `json:"error,omitempty"`
	Controller    string     `json:"controller,omitempty"` // child: the controller node
	Version       string     `json:"version,omitempty"`
	PlatformGuess string     `json:"platform_guess,omitempty"` // neighbour: a Flow platform key
	Hostname      string     `json:"hostname,omitempty"`
	Alias         string     `json:"alias,omitempty"`
	SSID          string     `json:"ssid,omitempty"`
	Signal        *int       `json:"signal,omitempty"`
	Blocked       bool       `json:"blocked,omitempty"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	Parent        string     `json:"parent,omitempty"` // endpoint: the node it is attached to
}

// Edge links two nodes.
type Edge struct {
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Kind        string   `json:"kind"` // link | managed | wired | wifi | wan
	SourcePort  string   `json:"source_port,omitempty"`
	TargetPort  string   `json:"target_port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Label       string   `json:"label,omitempty"`
	Bps         *float64 `json:"bps,omitempty"`
	Utilization *float64 `json:"utilization,omitempty"`
	SpeedMbps   *int64   `json:"speed_mbps,omitempty"`
}

// TopologyStats summarise the map.
type TopologyStats struct {
	Devices   int `json:"devices"`
	Children  int `json:"children"`
	Neighbors int `json:"neighbors"`
	Endpoints int `json:"endpoints"`
	Online    int `json:"online"`
	Down      int `json:"down"`
}

// Topology is the network map.
type Topology struct {
	Nodes       []*Node       `json:"nodes"`
	Edges       []*Edge       `json:"edges"`
	Stats       TopologyStats `json:"stats"`
	GeneratedAt time.Time     `json:"generated_at"`
}

var neighborHints = []struct {
	re  *regexp.Regexp
	key string
}{}

func init() {
	for _, h := range [][2]string{{`RouterOS|mikrotik`, "mikrotik"}, {`OPNsense`, "opnsense"}, {`pfSense`, "pfsense"},
		{`LuCI|OpenWrt`, "openwrt"}, {`Keenetic`, "keenetic"}, {`Omada`, "omada"}, {`UniFi|ubnt`, "unifi"},
		{`FortiGate|Fortinet`, "fortigate"}, {`Zyxel|ZyXEL`, "zyxel"}, {`TP-?Link|Archer|Deco`, "tplink"},
		{`iDRAC|Integrated Lights-Out|iLO|XClarity|Redfish`, "redfish"}, {`Aruba|ArubaOS`, "aruba_cx"}, {`ProCurve`, "aruba_os"},
		{`Netgear`, "netgear"}, {`D-Link`, "dlink"}, {`EdgeOS|EdgeRouter`, "edgeos"}, {`NX-OS|Nexus`, "cisco_nxos"},
		{`Cisco`, "cisco_ios"}, {`Huawei`, "huawei"}, {`JUNOS|Juniper`, "juniper"}, {`Eltex`, "eltex"}, {`Dell`, "dell_os10"},
		{`Linux`, "linux"}} {
		neighborHints = append(neighborHints, struct {
			re  *regexp.Regexp
			key string
		}{regexp.MustCompile(`(?i)` + h[0]), h[1]})
	}
}

func ifaceKey(name string) string {
	return strings.ReplaceAll(strings.ToLower(drivers.ShortenIface(name)), " ", "")
}

func shortName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n, _, _ = strings.Cut(n, ".")
	return n
}

// Topology builds the map; offline includes clients not seen recently and
// endpoints = false leaves the clients out.
func (s *Service) Topology(ctx context.Context, offline, endpoints bool) (Topology, error) {
	devs, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return Topology{}, err
	}
	var eps []store.NetworkEndpoint
	if endpoints {
		if eps, err = s.st.NetworkEndpoints(ctx, 0, 3000); err != nil {
			return Topology{}, err
		}
	}
	snap := s.snapshot()
	views := make([]View, len(devs))
	for i, d := range devs {
		views[i] = s.view(d, snap)
	}
	return buildTopology(devs, views, eps, s.offlineAfter(ctx), offline, s.cfg.Now()), nil
}

func buildTopology(devs []store.NetworkDevice, views []View, eps []store.NetworkEndpoint, offlineAfter time.Duration,
	includeOffline bool, now time.Time) Topology {
	nodes := map[string]*Node{}
	var order []string
	addNode := func(n *Node) {
		nodes[n.ID] = n
		order = append(order, n.ID)
	}
	edges := map[string]*Edge{}
	var edgeOrder []string
	addEdge := func(a, b, kind string, e Edge) {
		if a == b || nodes[a] == nil || nodes[b] == nil {
			return
		}
		x, y := a, b
		if y < x {
			x, y = y, x
		}
		key := x + "\x00" + y + "\x00" + kind
		if cur := edges[key]; cur != nil {
			if cur.SourcePort == "" {
				cur.SourcePort = e.SourcePort
			}
			if cur.TargetPort == "" {
				cur.TargetPort = e.TargetPort
			}
			if cur.Protocol == "" {
				cur.Protocol = e.Protocol
			}
			if cur.Label == "" {
				cur.Label = e.Label
			}
			if cur.Bps == nil {
				cur.Bps, cur.Utilization, cur.SpeedMbps = e.Bps, e.Utilization, e.SpeedMbps
			}
			return
		}
		e.Source, e.Target, e.Kind = a, b, kind
		edges[key] = &e
		edgeOrder = append(edgeOrder, key)
	}
	byMAC, byIP, byName := map[string]string{}, map[string]string{}, map[string]string{}
	setDefault := func(m map[string]string, k, v string) {
		if k == "" {
			return
		}
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}

	// managed devices
	ifaces := map[string]map[string]IfaceState{}
	for i, d := range devs {
		v := views[i]
		nid := fmt.Sprintf("dev:%d", d.ID)
		facts := v.Facts
		n := &Node{ID: nid, Type: "device", Label: v.Name, Role: v.Role, Status: v.Status, Vendor: v.Vendor, Model: facts.Model,
			IP: d.Host, MAC: drivers.NormMAC(facts.MAC), DeviceID: d.ID, Platform: d.Platform, Site: v.Site, X: d.MapX, Y: d.MapY,
			Interfaces: v.Counts.Interfaces}
		if d.Status != "up" {
			n.Error = d.LastError
		}
		addNode(n)
		ifs := decode(d.Interfaces, []IfaceState{})
		ifaces[nid] = map[string]IfaceState{}
		setDefault(byMAC, n.MAC, nid)
		for _, it := range ifs {
			ifaces[nid][ifaceKey(it.Name)] = it
			setDefault(byMAC, drivers.NormMAC(it.MAC), nid)
		}
		for _, ip := range v.ExporterIPs {
			setDefault(byIP, ip, nid)
		}
		setDefault(byIP, d.Host, nid)
		setDefault(byName, shortName(v.Name), nid)
		setDefault(byName, shortName(facts.Hostname), nid)
	}

	// A neighbour seen by MAC that is a known device by name or address
	// lends that MAC to it, so controller uplinks find the right node.
	neighbors := make([][]drivers.Neighbor, len(devs))
	children := make([][]drivers.Child, len(devs))
	for i, d := range devs {
		neighbors[i] = decode(d.Neighbors, []drivers.Neighbor{})
		children[i] = decode(d.Children, []drivers.Child{})
		for _, n := range neighbors[i] {
			mac := drivers.NormMAC(n.RemoteMAC)
			hit := byIP[drivers.NormIP(n.RemoteIP)]
			if hit == "" {
				hit = byName[shortName(n.RemoteName)]
			}
			if mac != "" && hit != "" {
				setDefault(byMAC, mac, hit)
			}
		}
	}

	// devices behind controllers
	for i, d := range devs {
		parent := fmt.Sprintf("dev:%d", d.ID)
		for _, c := range children[i] {
			mac := drivers.NormMAC(c.MAC)
			if mac == "" {
				continue
			}
			nid := byMAC[mac]
			if nid == "" {
				nid = "mac:" + mac
			}
			if nodes[nid] == nil {
				status := "down"
				if c.Online {
					status = "up"
				}
				addNode(&Node{ID: nid, Type: "child", Label: or(c.Name, mac), Role: or(c.Kind, "other"), Status: status,
					Vendor: nodes[parent].Vendor, Model: c.Model, IP: c.IP, MAC: mac, Controller: parent, Version: c.Version,
					Site: nodes[parent].Site})
				byMAC[mac] = nid
				setDefault(byIP, drivers.NormIP(c.IP), nid)
				setDefault(byName, strings.ToLower(c.Name), nid)
			} else if nodes[nid].Type == "device" {
				nodes[nid].Controller = parent
			}
		}
	}
	for i, d := range devs {
		parent := fmt.Sprintf("dev:%d", d.ID)
		for _, c := range children[i] {
			nid := byMAC[drivers.NormMAC(c.MAC)]
			up := byMAC[drivers.NormMAC(c.UplinkMAC)]
			switch {
			case nid != "" && up != "":
				addEdge(up, nid, "link", Edge{TargetPort: c.UplinkPort})
			case nid != "":
				addEdge(parent, nid, "managed", Edge{})
			}
		}
	}

	// LLDP / CDP / MNDP neighbours
	for i, d := range devs {
		nid := fmt.Sprintf("dev:%d", d.ID)
		for _, n := range neighbors[i] {
			mac := drivers.NormMAC(n.RemoteMAC)
			remote := byMAC[mac]
			if remote == "" {
				remote = byIP[drivers.NormIP(n.RemoteIP)]
			}
			if remote == "" {
				remote = byName[shortName(n.RemoteName)]
			}
			if remote == "" {
				key := strings.ToLower(or(mac, drivers.NormIP(n.RemoteIP), strings.TrimSpace(n.RemoteName)))
				if key == "" {
					continue
				}
				remote = "nb:" + key
				if nodes[remote] == nil {
					guess := ""
					for _, h := range neighborHints {
						if h.re.MatchString(n.RemotePlatform) {
							guess = h.key
							break
						}
					}
					addNode(&Node{ID: remote, Type: "neighbor", Label: or(n.RemoteName, key), Role: "other", Status: "unknown",
						IP: drivers.NormIP(n.RemoteIP), MAC: mac, Model: truncate(n.RemotePlatform, 80), PlatformGuess: guess})
					setDefault(byMAC, mac, remote)
				}
			}
			e := Edge{SourcePort: n.LocalInterface, TargetPort: n.RemoteInterface, Protocol: n.Protocol}
			if it, ok := ifaces[nid][ifaceKey(n.LocalInterface)]; ok {
				hi := 0.0
				for _, r := range []*float64{it.RxBps, it.TxBps} {
					if r != nil && *r > hi {
						hi = *r
					}
				}
				if hi > 0 {
					e.Bps = &hi
				}
				e.Utilization, e.SpeedMbps = it.Utilization, it.SpeedMbps
			}
			addEdge(nid, remote, "link", e)
		}
	}

	// Clients. Network equipment seen as a client somewhere (a controller or
	// an AP in the router's ARP) is attached there when nothing else links it.
	shown := 0
	type seen struct{ parent, port string }
	infraSeen := map[string]seen{}
	var infraOrder []string
	parentOf := func(e store.NetworkEndpoint) string {
		if p := byMAC[drivers.NormMAC(e.AttachedTo)]; p != "" {
			return p
		}
		if e.DeviceID != nil {
			return fmt.Sprintf("dev:%d", *e.DeviceID)
		}
		return ""
	}
	for _, e := range eps {
		infra := byMAC[e.MAC]
		if infra == "" && e.IP != "" {
			infra = byIP[e.IP]
		}
		if infra != "" {
			if p := parentOf(e); p != "" && p != infra && nodes[p] != nil {
				if _, ok := infraSeen[infra]; !ok {
					infraSeen[infra] = seen{p, or(e.Port, e.Interface)}
					infraOrder = append(infraOrder, infra)
				}
			}
			continue
		}
		online := now.Sub(e.LastSeen) <= offlineAfter
		if !online && !includeOffline {
			continue
		}
		parent := parentOf(e)
		if parent == "" || nodes[parent] == nil {
			continue
		}
		status := "offline"
		if online {
			status = "online"
		}
		last := e.LastSeen
		nid := "ep:" + e.MAC
		addNode(&Node{ID: nid, Type: "endpoint", Label: or(e.Alias, e.Hostname, e.IP, e.MAC), Status: status, IP: e.IP, MAC: e.MAC,
			Vendor: e.Vendor, Hostname: e.Hostname, Alias: e.Alias, SSID: e.SSID, Signal: e.Signal, Blocked: e.Blocked,
			LastSeen: &last, Parent: parent})
		kind := "wired"
		if e.SSID != "" || e.Source == drivers.SourceWiFi {
			kind = "wifi"
		}
		addEdge(parent, nid, kind, Edge{SourcePort: or(e.Port, e.Interface), Label: e.SSID})
		nodes[parent].Clients++
		shown++
	}
	linked := map[string]bool{}
	for _, e := range edges {
		if e.Kind == "link" || e.Kind == "wan" {
			linked[e.Source], linked[e.Target] = true, true
		}
	}
	for _, infra := range infraOrder {
		if !linked[infra] {
			addEdge(infraSeen[infra].parent, infra, "wired", Edge{SourcePort: infraSeen[infra].port})
		}
	}

	// the Internet behind the edge routers
	if len(devs) > 0 {
		addNode(&Node{ID: "internet", Type: "internet", Label: "Internet", Status: "up"})
		var edge []string
		for _, id := range order {
			n := nodes[id]
			if (n.Type == "device" || n.Type == "child") && (n.Role == "router" || n.Role == "firewall" || n.Role == "gateway") {
				edge = append(edge, id)
			}
		}
		if len(edge) == 0 {
			edge = []string{fmt.Sprintf("dev:%d", devs[0].ID)}
		}
		for _, id := range edge {
			addEdge("internet", id, "wan", Edge{})
		}
	}

	t := Topology{Nodes: make([]*Node, 0, len(order)), Edges: make([]*Edge, 0, len(edgeOrder)), GeneratedAt: now}
	for _, id := range order {
		n := nodes[id]
		t.Nodes = append(t.Nodes, n)
		switch n.Type {
		case "device":
			t.Stats.Devices++
			if n.Status == "down" || n.Status == "error" {
				t.Stats.Down++
			}
		case "child":
			t.Stats.Children++
		case "neighbor":
			t.Stats.Neighbors++
		}
		if n.Status == "online" {
			t.Stats.Online++
		}
	}
	t.Stats.Endpoints = shown
	for _, k := range edgeOrder {
		t.Edges = append(t.Edges, edges[k])
	}
	sort.SliceStable(t.Edges, func(i, j int) bool { return t.Edges[i].Kind == "wan" && t.Edges[j].Kind != "wan" })
	return t
}
