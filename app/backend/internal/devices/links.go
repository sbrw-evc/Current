package devices

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/snmp"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Links of managed devices to the rest of Flow: the flow exporters they
// are, and their SNMP credentials as profiles of the SNMP interface-name
// poller (so one device is configured once).

// ExporterDevice is the managed device behind a flow exporter address.
type ExporterDevice struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Platform string `json:"platform"`
}

// ExporterDevices maps the addresses devices may export flows from (the
// configured exporter address, the host and the interface addresses) to the
// device. The first device wins an address.
func (s *Service) ExporterDevices(ctx context.Context) (map[netip.Addr]ExporterDevice, error) {
	devs, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	names := s.deviceNames(devs)
	out := map[netip.Addr]ExporterDevice{}
	for _, d := range devs {
		ed := ExporterDevice{ID: d.ID, Name: names[d.ID], Status: d.Status, Platform: d.Platform}
		for _, ip := range exporterIPs(d, decode(d.Interfaces, []IfaceState{})) {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if _, ok := out[a.Unmap()]; !ok {
				out[a.Unmap()] = ed
			}
		}
	}
	return out, nil
}

// SNMPProfiles turns the own SNMP credentials of the managed devices into
// profiles of the SNMP interface-name poller (ids "dev-<id>", prefixes the
// device's exporter addresses, references to OpenBao devices/<id>). SNMPv1
// and devices that use a Flow SNMP profile are left out.
func SNMPProfiles(ctx context.Context, st *store.Store, vault *secrets.Client) ([]snmp.Profile, error) {
	if st == nil || vault == nil {
		return nil, nil
	}
	devs, err := st.NetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	var out []snmp.Profile
	for _, d := range devs {
		if p, ok := deviceSNMPProfile(d, vault); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func deviceSNMPProfile(d store.NetworkDevice, vault *secrets.Client) (snmp.Profile, bool) {
	if !d.Enabled || d.Credentials["snmp_source"] == SNMPProfile {
		return snmp.Profile{}, false
	}
	has := func(f string) bool { return slices.Contains(d.Secrets, f) }
	version := d.Credentials[drivers.FieldSNMPVersion]
	user := d.Credentials[drivers.FieldSNMPUser]
	if version == "" {
		switch {
		case user != "":
			version = snmp.Version3
		case has(drivers.FieldSNMPCommunity):
			version = snmp.Version2c
		}
	}
	ref := func(f string) string { return vault.Ref(SecretPath(d.ID), f) }
	p := snmp.Profile{ID: fmt.Sprintf("dev-%d", d.ID), Name: "Device: " + or(d.Name, d.Host), Version: version}
	switch version {
	case snmp.Version2c:
		if !has(drivers.FieldSNMPCommunity) {
			return p, false
		}
		p.CommunityRef = ref(drivers.FieldSNMPCommunity)
	case snmp.Version3:
		if user == "" {
			return p, false
		}
		p.Username = user
		p.SecurityLevel = snmp.NoAuthNoPriv
		if has(drivers.FieldSNMPAuthPassword) {
			p.SecurityLevel = snmp.AuthNoPriv
			p.AuthRef = ref(drivers.FieldSNMPAuthPassword)
			p.AuthProtocol = strings.ToUpper(or(d.Credentials[drivers.FieldSNMPAuthProtocol], "sha"))
			if has(drivers.FieldSNMPPrivPassword) {
				p.SecurityLevel = snmp.AuthPriv
				p.PrivRef = ref(drivers.FieldSNMPPrivPassword)
				p.PrivProtocol = strings.ToUpper(or(d.Credentials[drivers.FieldSNMPPrivProtocol], "aes"))
			}
		}
	default:
		return p, false
	}
	if d.Transport == "snmp" && d.Port != nil {
		p.Port = uint16(*d.Port)
	}
	for _, ip := range exporterIPs(d, decode(d.Interfaces, []IfaceState{})) {
		if a, err := netip.ParseAddr(ip); err == nil {
			p.Prefixes = append(p.Prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String())
		}
	}
	if len(p.Prefixes) == 0 {
		return p, false // a host name only: nothing to match exporters with
	}
	return p, true
}

// MergeSNMP puts the device profiles ahead of the configured ones. With
// SNMP polling off, it is turned on for the managed devices only.
func MergeSNMP(set snmp.Settings, devs []snmp.Profile) snmp.Settings {
	if len(devs) == 0 {
		return set
	}
	if !set.Enabled {
		set.Enabled, set.PollExporters, set.Profiles = true, true, nil
	}
	ids := map[string]bool{}
	for _, p := range set.Profiles {
		ids[p.ID] = true
	}
	merged := make([]snmp.Profile, 0, len(devs)+len(set.Profiles))
	for _, p := range devs {
		if !ids[p.ID] {
			merged = append(merged, p)
		}
	}
	set.Profiles = append(merged, set.Profiles...)
	return set
}
