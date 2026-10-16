package inventory

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Source-ref prefixes, as in Ledger's Beacon CMDB feed
// (server/src/integrations/umbrella/ci.ts: `inventory-db:<object type>:<id>`).
const (
	SourcePrefix = "inventory-db:"
	RefDevice    = "inventory-db:dcim.device:"
	RefVM        = "inventory-db:virtualization.virtualmachine:"
)

// DeviceRef returns the source_ref of a device.
func DeviceRef(id int) string { return RefDevice + strconv.Itoa(id) }

// VMRef returns the source_ref of a virtual machine.
func VMRef(id int) string { return RefVM + strconv.Itoa(id) }

// Object kinds.
const (
	KindDevice = "device"
	KindVM     = "vm"
)

// Device is a DCIM device or a virtual machine.
type Device struct {
	ID           int               `json:"id"`
	Kind         string            `json:"kind"` // KindDevice or KindVM
	Name         string            `json:"name"`
	Ref          string            `json:"ref"` // source_ref
	Status       string            `json:"status"`
	Site         string            `json:"site"`
	SiteSlug     string            `json:"site_slug"`
	Region       string            `json:"region"`
	Role         string            `json:"role"`
	Tenant       string            `json:"tenant"`
	Platform     string            `json:"platform"`
	Manufacturer string            `json:"manufacturer"`
	Model        string            `json:"model"`
	Cluster      string            `json:"cluster"`
	Tags         []string          `json:"tags"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
	PrimaryIP4   netip.Addr        `json:"primary_ip4"`
	PrimaryIP6   netip.Addr        `json:"primary_ip6"`
	// Addresses: primary, OOB and IPAM addresses of the device's interfaces.
	Addresses []netip.Addr `json:"addresses"`
}

// Interface is a device interface with its derived edge classification.
type Interface struct {
	ID          int    `json:"id"`
	DeviceID    int    `json:"device_id"`
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	// Speed in bits per second (Ledger stores Kbps).
	Speed   uint64   `json:"speed"`
	IfIndex uint32   `json:"if_index,omitempty"` // from the snmp_index custom field, 0 = unknown
	LAGID   int      `json:"lag_id,omitempty"`
	Mode    string   `json:"mode"`
	VLAN    uint16   `json:"vlan,omitempty"` // untagged VLAN id
	Tags    []string `json:"tags"`
	// VRF of the interface (its own, else that of its IP addresses) and the
	// route distinguisher of that VRF, used for BMP L3VPN route lookups.
	VRF string `json:"vrf,omitempty"`
	RD  string `json:"rd,omitempty"`

	Boundary     string `json:"boundary"` // flow.Boundary*
	Connectivity string `json:"connectivity"`
	Provider     string `json:"provider"`
	Circuit      string `json:"circuit"`
	// CommitRate of the circuit in bits per second.
	CommitRate uint64 `json:"commit_rate,omitempty"`
	// PeerDevice / PeerInterface for internal links (cable to another device).
	PeerDevice    string `json:"peer_device,omitempty"`
	PeerInterface string `json:"peer_interface,omitempty"`
}

// Prefix is an IPAM prefix.
type Prefix struct {
	ID          int          `json:"id"`
	Prefix      netip.Prefix `json:"prefix"`
	Name        string       `json:"name"` // description, else first tag, else VLAN name
	Description string       `json:"description"`
	Status      string       `json:"status"`
	Role        string       `json:"role"`
	Site        string       `json:"site"`
	Tenant      string       `json:"tenant"`
	VRF         string       `json:"vrf"`
	VLAN        uint16       `json:"vlan,omitempty"`
	VLANName    string       `json:"vlan_name"`
	Tags        []string     `json:"tags"`
}

// Address is an IPAM IP address.
type Address struct {
	ID       int          `json:"id"`
	Addr     netip.Addr   `json:"addr"`
	Prefix   netip.Prefix `json:"prefix"` // address with its mask
	DNSName  string       `json:"dns_name"`
	Host     string       `json:"host"` // DNS name, else the owning device / VM name
	Ref      string       `json:"ref"`  // source_ref of the owning device / VM
	OwnerID  int          `json:"owner_id,omitempty"`
	Kind     string       `json:"kind,omitempty"` // owner kind
	Tenant   string       `json:"tenant"`
	VRF      string       `json:"vrf"`
	Status   string       `json:"status"`
	Role     string       `json:"role"`
	IfaceID  int          `json:"interface_id,omitempty"`
	IfaceTyp string       `json:"interface_type,omitempty"`
}

// Circuit is a provider circuit.
type Circuit struct {
	ID           int    `json:"id"`
	CID          string `json:"cid"`
	Provider     string `json:"provider"`
	Type         string `json:"type"`
	TypeSlug     string `json:"type_slug"`
	Connectivity string `json:"connectivity"`
	Status       string `json:"status"`
	Tenant       string `json:"tenant"`
	CommitRate   uint64 `json:"commit_rate"` // bits per second
}

// Stats of a sync, served as `last_sync` by GET /api/inventory-db.
type Stats struct {
	At         time.Time     `json:"at"`
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
	Devices    int           `json:"devices"`
	VMs        int           `json:"vms"`
	Interfaces int           `json:"interfaces"`
	Addresses  int           `json:"addresses"`
	Prefixes   int           `json:"prefixes"`
	Circuits   int           `json:"circuits"`
}

type ifIndexKey struct {
	dev int
	idx uint32
}

type ifNameKey struct {
	dev  int
	name string
}

// Snapshot is an immutable view of Ledger. All methods are safe for
// concurrent use; returned pointers must be treated as read-only.
type Snapshot struct {
	at         time.Time
	devices    map[int]*Device
	vms        map[int]*Device
	exporters  map[netip.Addr]*Device
	ifaces     map[int]*Interface
	ifByIndex  map[ifIndexKey]*Interface
	ifByName   map[ifNameKey]*Interface
	devIfaces  map[int][]*Interface
	prefixes   trie[*Prefix]
	prefixList []*Prefix
	addrs      map[netip.Addr]*Address
	circuits   map[int]*Circuit
}

// Empty returns a snapshot without data.
func Empty() *Snapshot { return build(&raw{}, "snmp_index", time.Time{}) }

// At is when the data was fetched.
func (s *Snapshot) At() time.Time { return s.at }

// Stats counts the objects of the snapshot.
func (s *Snapshot) Stats() Stats {
	return Stats{At: s.at, OK: true, Devices: len(s.devices), VMs: len(s.vms), Interfaces: len(s.ifaces),
		Addresses: len(s.addrs), Prefixes: len(s.prefixList), Circuits: len(s.circuits)}
}

// Exporter finds the device (or VM) owning addr: primary IPs, OOB IP, then
// any IPAM address of its interfaces.
func (s *Snapshot) Exporter(addr netip.Addr) (*Device, bool) {
	d, ok := s.exporters[addr.Unmap()]
	return d, ok
}

// Device by id.
func (s *Snapshot) Device(id int) (*Device, bool) { d, ok := s.devices[id]; return d, ok }

// VM by id.
func (s *Snapshot) VM(id int) (*Device, bool) { d, ok := s.vms[id]; return d, ok }

// Devices returns all devices sorted by name.
func (s *Snapshot) Devices() []*Device {
	out := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b *Device) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out
}

// Interfaces of a device, sorted by name.
func (s *Snapshot) Interfaces(deviceID int) []*Interface { return s.devIfaces[deviceID] }

// Interface by device and SNMP ifIndex (custom field snmp_index).
func (s *Snapshot) Interface(deviceID int, ifIndex uint32) (*Interface, bool) {
	i, ok := s.ifByIndex[ifIndexKey{deviceID, ifIndex}]
	return i, ok
}

// InterfaceByName by device and interface name (case-insensitive).
func (s *Snapshot) InterfaceByName(deviceID int, name string) (*Interface, bool) {
	if i, ok := s.ifByName[ifNameKey{deviceID, name}]; ok {
		return i, true
	}
	i, ok := s.ifByName[ifNameKey{deviceID, strings.ToLower(name)}]
	return i, ok
}

// InterfaceByID by Ledger id.
func (s *Snapshot) InterfaceByID(id int) (*Interface, bool) { i, ok := s.ifaces[id]; return i, ok }

// Prefix returns the longest IPAM prefix containing addr. When the same
// prefix exists in several VRFs, the global one wins.
func (s *Snapshot) Prefix(addr netip.Addr) (*Prefix, bool) { return s.prefixes.lookup(addr) }

// Prefixes returns all prefixes.
func (s *Snapshot) Prefixes() []*Prefix { return s.prefixList }

// Address returns the IPAM address equal to addr (mask ignored).
func (s *Snapshot) Address(addr netip.Addr) (*Address, bool) {
	a, ok := s.addrs[addr.Unmap()]
	return a, ok
}

// Circuit by id.
func (s *Snapshot) Circuit(id int) (*Circuit, bool) { c, ok := s.circuits[id]; return c, ok }

// ---------------------------------------------------------------------------

// Connectivity maps a circuit type slug / name to a connectivity class:
// transit, peering, ix, pni, customer; anything else gives the slug.
func Connectivity(slug, name string) string {
	s := strings.ToLower(strings.TrimSpace(slug))
	if s == "" {
		s = strings.ToLower(strings.TrimSpace(name))
	}
	if s == "" {
		return ""
	}
	tokens := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == ' ' || r == '/' || r == '.' })
	has := func(ws ...string) bool {
		for _, t := range tokens {
			if slices.Contains(ws, t) {
				return true
			}
		}
		return false
	}
	switch {
	case has("pni") || (has("private") && has("peering", "peer", "interconnect")):
		return "pni"
	case has("ix", "ixp", "exchange", "ix-peering"):
		return "ix"
	case has("transit", "upstream"):
		return "transit"
	case has("peering", "peer"):
		return "peering"
	case has("customer", "customers", "downstream", "client"):
		return "customer"
	}
	return strings.ReplaceAll(s, " ", "-")
}

func kbps(v *int64) uint64 {
	if v == nil || *v <= 0 {
		return 0
	}
	return uint64(*v) * 1000
}

func parseHost(s string) (netip.Addr, netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		a := p.Addr().Unmap()
		return a, netip.PrefixFrom(a, p.Bits()), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return a, netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Addr{}, netip.Prefix{}, false
}

func cfStrings(cf map[string]any) map[string]string {
	if len(cf) == 0 {
		return nil
	}
	var out map[string]string
	for k, v := range cf {
		var s string
		switch x := v.(type) {
		case nil:
			continue
		case string:
			s = x
		case float64:
			s = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			s = strconv.FormatBool(x)
		default:
			continue
		}
		if out == nil {
			out = make(map[string]string, len(cf))
		}
		out[k] = s
	}
	return out
}

// build turns the raw lists into a snapshot.
func build(r *raw, snmpField string, at time.Time) *Snapshot {
	s := &Snapshot{
		at:        at,
		devices:   make(map[int]*Device, len(r.devices)),
		vms:       make(map[int]*Device, len(r.vms)),
		exporters: make(map[netip.Addr]*Device),
		ifaces:    make(map[int]*Interface, len(r.interfaces)),
		ifByIndex: make(map[ifIndexKey]*Interface),
		ifByName:  make(map[ifNameKey]*Interface, len(r.interfaces)),
		devIfaces: make(map[int][]*Interface),
		addrs:     make(map[netip.Addr]*Address, len(r.addresses)),
		circuits:  make(map[int]*Circuit, len(r.circuits)),
	}

	tenants := map[int]string{}
	for _, t := range r.tenants {
		tenants[t.ID] = t.Name
	}
	tenantName := func(x *ref) string {
		if x == nil {
			return ""
		}
		if n, ok := tenants[x.ID]; ok {
			return n
		}
		return x.name()
	}
	regions := map[int]string{}
	for _, rg := range r.regions {
		regions[rg.ID] = rg.Name
	}
	type siteInfo struct{ name, slug, region, tenant string }
	sites := map[int]siteInfo{}
	for _, st := range r.sites {
		reg := ""
		if st.Region != nil {
			reg = regions[st.Region.ID]
			if reg == "" {
				reg = st.Region.name()
			}
		}
		sites[st.ID] = siteInfo{st.Name, st.Slug, reg, tenantName(st.Tenant)}
	}
	siteOf := func(x *ref) siteInfo {
		if x == nil {
			return siteInfo{}
		}
		if si, ok := sites[x.ID]; ok {
			return si
		}
		return siteInfo{name: x.name(), slug: x.Slug}
	}
	vrfs := map[int]string{}
	vrfRD := map[int]string{}
	for _, v := range r.vrfs {
		vrfs[v.ID] = v.Name
		vrfRD[v.ID] = v.RD
	}
	vrfName := func(x *ref) string {
		if x == nil {
			return ""
		}
		if n, ok := vrfs[x.ID]; ok {
			return n
		}
		return x.name()
	}
	setVRF := func(it *Interface, x *ref) {
		if x == nil || x.ID == 0 {
			return
		}
		it.VRF = vrfName(x)
		if rd, ok := vrfRD[x.ID]; ok {
			it.RD = rd
		} else {
			it.RD = x.RD
		}
	}
	vlans := map[int]rawVLAN{}
	for _, v := range r.vlans {
		vlans[v.ID] = v
	}

	// Devices and VMs.
	for _, d := range r.devices {
		si := siteOf(d.Site)
		dev := &Device{
			ID: d.ID, Kind: KindDevice, Name: cmp.Or(d.Name, d.Display), Ref: DeviceRef(d.ID), Status: d.Status.Value,
			Site: si.name, SiteSlug: si.slug, Region: si.region,
			Role: cmp.Or(d.Role, d.DeviceRole).name(), Tenant: cmp.Or(tenantName(d.Tenant), si.tenant),
			Platform: d.Platform.name(), Cluster: d.Cluster.name(),
			Tags: tagNames(d.Tags), CustomFields: cfStrings(d.CustomFields),
		}
		if d.DeviceType != nil {
			dev.Model = d.DeviceType.Model
			dev.Manufacturer = d.DeviceType.Manufacturer.name()
		}
		if d.PrimaryIP4 != nil {
			dev.PrimaryIP4, _, _ = parseHost(d.PrimaryIP4.Address)
		}
		if d.PrimaryIP6 != nil {
			dev.PrimaryIP6, _, _ = parseHost(d.PrimaryIP6.Address)
		}
		s.devices[d.ID] = dev
	}
	for _, v := range r.vms {
		si := siteOf(v.Site)
		vm := &Device{
			ID: v.ID, Kind: KindVM, Name: cmp.Or(v.Name, v.Display), Ref: VMRef(v.ID), Status: v.Status.Value,
			Site: si.name, SiteSlug: si.slug, Region: si.region, Role: v.Role.name(),
			Tenant: cmp.Or(tenantName(v.Tenant), si.tenant), Platform: v.Platform.name(), Cluster: v.Cluster.name(),
			Tags: tagNames(v.Tags), CustomFields: cfStrings(v.CustomFields),
		}
		if v.PrimaryIP4 != nil {
			vm.PrimaryIP4, _, _ = parseHost(v.PrimaryIP4.Address)
		}
		if v.PrimaryIP6 != nil {
			vm.PrimaryIP6, _, _ = parseHost(v.PrimaryIP6.Address)
		}
		s.vms[v.ID] = vm
	}

	// Exporter addresses by priority: primary IPs, OOB, interface addresses;
	// devices before VMs.
	type cand struct {
		dev  *Device
		prio int
	}
	exp := map[netip.Addr]cand{}
	addExp := func(a netip.Addr, d *Device, prio int) {
		if !a.IsValid() || d == nil {
			return
		}
		if d.Kind == KindVM {
			prio += 10
		}
		if c, ok := exp[a]; ok && (c.prio < prio || (c.prio == prio && c.dev.ID <= d.ID && c.dev.Kind == d.Kind)) {
			return
		}
		exp[a] = cand{d, prio}
	}
	for _, d := range r.devices {
		dev := s.devices[d.ID]
		addExp(dev.PrimaryIP4, dev, 0)
		addExp(dev.PrimaryIP6, dev, 0)
		if d.OOBIP != nil {
			a, _, _ := parseHost(d.OOBIP.Address)
			addExp(a, dev, 1)
		}
	}
	for _, vm := range s.vms {
		addExp(vm.PrimaryIP4, vm, 0)
		addExp(vm.PrimaryIP6, vm, 0)
	}

	// IP addresses.
	for _, ip := range r.addresses {
		a, pfx, ok := parseHost(ip.Address)
		if !ok {
			continue
		}
		addr := &Address{
			ID: ip.ID, Addr: a, Prefix: pfx, DNSName: strings.TrimSpace(ip.DNSName), Tenant: tenantName(ip.Tenant),
			VRF: vrfName(ip.VRF), Status: ip.Status.Value, Role: ip.Role.Value, IfaceTyp: ip.AssignedObjectType,
		}
		if ip.AssignedObjectID != nil {
			addr.IfaceID = *ip.AssignedObjectID
		}
		var owner *Device
		if ao := ip.AssignedObject; ao != nil {
			switch {
			case ao.Device != nil:
				owner = s.devices[ao.Device.ID]
				if owner == nil {
					addr.Ref, addr.OwnerID, addr.Kind = DeviceRef(ao.Device.ID), ao.Device.ID, KindDevice
					addr.Host = ao.Device.name()
				}
			case ao.VirtualMachine != nil:
				owner = s.vms[ao.VirtualMachine.ID]
				if owner == nil {
					addr.Ref, addr.OwnerID, addr.Kind = VMRef(ao.VirtualMachine.ID), ao.VirtualMachine.ID, KindVM
					addr.Host = ao.VirtualMachine.name()
				}
			}
		}
		if owner != nil {
			addr.Ref, addr.OwnerID, addr.Kind, addr.Host = owner.Ref, owner.ID, owner.Kind, owner.Name
			addExp(a, owner, 2)
		}
		if addr.DNSName != "" {
			addr.Host = addr.DNSName
		}
		// The same host in several VRFs: prefer an assigned address, then the
		// global table, then the lowest id.
		if old, ok := s.addrs[a]; ok {
			better := func(x *Address) int {
				score := 0
				if x.Ref != "" {
					score += 2
				}
				if x.VRF == "" {
					score++
				}
				return score
			}
			if better(old) > better(addr) || (better(old) == better(addr) && old.ID < addr.ID) {
				continue
			}
		}
		s.addrs[a] = addr
	}
	for a, c := range exp {
		s.exporters[a] = c.dev
		c.dev.Addresses = append(c.dev.Addresses, a)
	}
	for _, m := range []map[int]*Device{s.devices, s.vms} {
		for _, d := range m {
			slices.SortFunc(d.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		}
	}

	// Circuits.
	types := map[int]rawCircuitType{}
	for _, t := range r.circuitTypes {
		types[t.ID] = t
	}
	providers := map[int]string{}
	for _, p := range r.providers {
		providers[p.ID] = p.Name
	}
	for _, c := range r.circuits {
		ci := &Circuit{ID: c.ID, CID: c.CID, Status: c.Status.Value, Tenant: tenantName(c.Tenant), CommitRate: kbps(c.CommitRate)}
		if c.Provider != nil {
			ci.Provider = cmp.Or(providers[c.Provider.ID], c.Provider.name())
		}
		if c.Type != nil {
			t, ok := types[c.Type.ID]
			if !ok {
				t = rawCircuitType{Name: c.Type.name(), Slug: c.Type.Slug}
			}
			ci.Type, ci.TypeSlug = t.Name, t.Slug
			ci.Connectivity = Connectivity(t.Slug, t.Name)
		}
		s.circuits[c.ID] = ci
	}

	// Interfaces.
	for _, ri := range r.interfaces {
		if ri.Device == nil {
			continue
		}
		it := &Interface{
			ID: ri.ID, DeviceID: ri.Device.ID, Name: ri.Name, Label: ri.Label, Description: ri.Description,
			Type: ri.Type.Value, Enabled: ri.Enabled == nil || *ri.Enabled, Speed: kbps(ri.Speed),
			LAGID: ri.LAG.id(), Mode: ri.Mode.Value, Tags: tagNames(ri.Tags),
		}
		if ri.UntaggedVLAN != nil {
			vid := ri.UntaggedVLAN.VID
			if v, ok := vlans[ri.UntaggedVLAN.ID]; ok {
				vid = v.VID
			}
			it.VLAN = uint16(vid)
		}
		if idx, ok := cfUint(ri.CustomFields, snmpField); ok {
			it.IfIndex = idx
		}
		setVRF(it, ri.VRF)
		s.ifaces[ri.ID] = it
	}
	// Interfaces without their own VRF take the VRF of an assigned address
	// (the lowest address id wins, for stable results).
	ipVRF := map[int]*rawIPAddress{}
	for i := range r.addresses {
		ip := &r.addresses[i]
		if ip.AssignedObjectType != "dcim.interface" || ip.AssignedObjectID == nil || ip.VRF == nil {
			continue
		}
		if old, ok := ipVRF[*ip.AssignedObjectID]; !ok || ip.ID < old.ID {
			ipVRF[*ip.AssignedObjectID] = ip
		}
	}
	for id, ip := range ipVRF {
		if it := s.ifaces[id]; it != nil && it.VRF == "" {
			setVRF(it, ip.VRF)
		}
	}

	// Edge classification. Circuit terminations name the interfaces they
	// reach (directly or through patch panels).
	ifCircuit := map[int]int{}
	for _, ct := range r.terminations {
		if ct.Circuit == nil {
			continue
		}
		peers := ct.LinkPeers
		if ct.LinkPeersType != "dcim.interface" {
			peers = nil
			if ct.ConnectedEndpointsType == "dcim.interface" {
				peers = ct.ConnectedEndpoints
			}
		}
		for _, p := range peers {
			if _, ok := ifCircuit[p.ID]; !ok {
				ifCircuit[p.ID] = ct.Circuit.ID
			}
		}
	}
	// Cables as a fallback when interfaces lack link_peers.
	type cableEnd struct {
		typ string
		p   *peer
		id  int
	}
	cablePeer := map[int]cableEnd{}
	for _, c := range r.cables {
		if c.Status.Value != "" && c.Status.Value != "connected" {
			continue
		}
		for _, pair := range [][2][]rawTermination{{c.ATerminations, c.BTerminations}, {c.BTerminations, c.ATerminations}} {
			if len(pair[1]) == 0 {
				continue
			}
			far := pair[1][0]
			for _, near := range pair[0] {
				if near.ObjectType == "dcim.interface" {
					cablePeer[near.ObjectID] = cableEnd{far.ObjectType, far.Object, far.ObjectID}
				}
			}
		}
	}
	for _, ri := range r.interfaces {
		it := s.ifaces[ri.ID]
		if it == nil {
			continue
		}
		circuitID, internalPeer := 0, (*peer)(nil)
		switch ri.LinkPeersType {
		case "circuits.circuittermination":
			for _, p := range ri.LinkPeers {
				if p.Circuit != nil {
					circuitID = p.Circuit.ID
					break
				}
			}
		case "dcim.interface":
			if len(ri.LinkPeers) > 0 {
				internalPeer = &ri.LinkPeers[0]
			}
		case "":
			if ce, ok := cablePeer[ri.ID]; ok {
				switch ce.typ {
				case "circuits.circuittermination":
					if ce.p != nil && ce.p.Circuit != nil {
						circuitID = ce.p.Circuit.ID
					}
				case "dcim.interface":
					internalPeer = ce.p
					if internalPeer == nil {
						internalPeer = &peer{ID: ce.id}
					}
				}
			}
		}
		if circuitID == 0 {
			circuitID = ifCircuit[ri.ID]
		}
		if circuitID == 0 && internalPeer == nil && ri.ConnectedEndpointsType == "dcim.interface" && len(ri.ConnectedEndpoints) > 0 {
			internalPeer = &ri.ConnectedEndpoints[0]
		}
		switch {
		case circuitID != 0:
			it.Boundary = "external"
			if c, ok := s.circuits[circuitID]; ok {
				it.Provider, it.Circuit, it.Connectivity, it.CommitRate = c.Provider, c.CID, c.Connectivity, c.CommitRate
			}
		case internalPeer != nil:
			it.Boundary = "internal"
			if pi, ok := s.ifaces[internalPeer.ID]; ok {
				it.PeerInterface = pi.Name
				if d, ok := s.devices[pi.DeviceID]; ok {
					it.PeerDevice = d.Name
				}
			} else {
				it.PeerInterface = internalPeer.Name
				it.PeerDevice = internalPeer.Device.name()
			}
		}
	}
	// LAGs inherit from their members when not classified themselves; their
	// speed defaults to the sum of the members.
	members := map[int][]*Interface{}
	for _, it := range s.ifaces {
		if it.LAGID != 0 {
			members[it.LAGID] = append(members[it.LAGID], it)
		}
	}
	for lagID, ms := range members {
		lag := s.ifaces[lagID]
		if lag == nil {
			continue
		}
		slices.SortFunc(ms, func(a, b *Interface) int { return cmp.Compare(a.ID, b.ID) })
		var speed uint64
		for _, m := range ms {
			speed += m.Speed
		}
		if lag.Speed == 0 {
			lag.Speed = speed
		}
		if lag.Boundary != "" {
			continue
		}
		var ext, inr *Interface
		for _, m := range ms {
			switch m.Boundary {
			case "external":
				if ext == nil {
					ext = m
				}
			case "internal":
				if inr == nil {
					inr = m
				}
			}
		}
		switch {
		case ext != nil:
			lag.Boundary, lag.Provider, lag.Circuit, lag.Connectivity = ext.Boundary, ext.Provider, ext.Circuit, ext.Connectivity
			for _, m := range ms {
				lag.CommitRate += m.CommitRate
			}
		case inr != nil:
			lag.Boundary, lag.PeerDevice = inr.Boundary, inr.PeerDevice
		}
	}
	// Indexes.
	for _, it := range s.ifaces {
		s.devIfaces[it.DeviceID] = append(s.devIfaces[it.DeviceID], it)
		if it.IfIndex != 0 {
			k := ifIndexKey{it.DeviceID, it.IfIndex}
			if old, ok := s.ifByIndex[k]; !ok || old.ID > it.ID {
				s.ifByIndex[k] = it
			}
		}
		for _, n := range []string{it.Name, strings.ToLower(it.Name)} {
			k := ifNameKey{it.DeviceID, n}
			if old, ok := s.ifByName[k]; !ok || old.ID > it.ID {
				s.ifByName[k] = it
			}
		}
	}
	for _, l := range s.devIfaces {
		slices.SortFunc(l, func(a, b *Interface) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	}

	// Prefixes.
	for _, rp := range r.prefixes {
		p, err := netip.ParsePrefix(strings.TrimSpace(rp.Prefix))
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		px := &Prefix{
			ID: rp.ID, Prefix: p, Description: strings.TrimSpace(rp.Description), Status: rp.Status.Value,
			Role: rp.Role.name(), Tenant: tenantName(rp.Tenant), VRF: vrfName(rp.VRF), Tags: tagNames(rp.Tags),
		}
		if rp.Site != nil {
			px.Site = siteOf(rp.Site).name
		} else if rp.Scope != nil && rp.ScopeType == "dcim.site" {
			px.Site = siteOf(rp.Scope).name
		}
		if rp.VLAN != nil {
			v, ok := vlans[rp.VLAN.ID]
			if !ok {
				v = rawVLAN{VID: rp.VLAN.VID, Name: rp.VLAN.name()}
			}
			px.VLAN, px.VLANName = uint16(v.VID), v.Name
		}
		switch {
		case px.Description != "":
			px.Name = px.Description
		case len(rp.Tags) > 0:
			px.Name = cmp.Or(rp.Tags[0].Name, rp.Tags[0].Slug)
		default:
			px.Name = px.VLANName
		}
		s.prefixList = append(s.prefixList, px)
		s.prefixes.insert(p, px, func(old *Prefix) bool {
			if (old.VRF == "") != (px.VRF == "") {
				return px.VRF == ""
			}
			return px.ID < old.ID
		})
	}
	slices.SortFunc(s.prefixList, func(a, b *Prefix) int {
		return cmp.Or(a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), cmp.Compare(a.ID, b.ID))
	})
	return s
}
