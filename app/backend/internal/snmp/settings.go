// Package snmp polls interface names, descriptions and speeds over SNMP
// (v2c / v3) for exporters that Inventory DB does not describe, or whose
// interfaces have no name or speed there. It is the last interface source of
// the enricher, after the Inventory DB and the collector's option data.
//
// Devices are the exporters seen by the collector / enricher (when
// PollExporters is set) and the configured Devices; each one is polled with
// the first credential profile whose prefixes contain it. Results are cached
// and refreshed every Interval; they are kept for TTL when a device stops
// answering. Credentials live in OpenBao: the settings hold only openbao://
// references.
package snmp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// SNMP versions.
const (
	Version2c = "2c"
	Version3  = "3"
)

// v3 security levels.
const (
	NoAuthNoPriv = "noAuthNoPriv"
	AuthNoPriv   = "authNoPriv"
	AuthPriv     = "authPriv"
)

// AuthProtocols and PrivProtocols are the accepted v3 protocol names.
var (
	AuthProtocols = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	PrivProtocols = []string{"DES", "AES", "AES192", "AES256", "AES192C", "AES256C"}
)

// Settings are the SNMP poller settings (PostgreSQL settings key "snmp").
type Settings struct {
	Enabled bool `json:"enabled"`
	// PollExporters polls the exporters seen in flows (within the prefixes
	// of a profile).
	PollExporters bool `json:"poll_exporters"`
	// Devices are polled even before they send flows (addresses).
	Devices         []string  `json:"devices"`
	IntervalMinutes int       `json:"interval_minutes"` // refresh period (default 30)
	TTLMinutes      int       `json:"ttl_minutes"`      // keep data of a silent device (default 360)
	TimeoutSeconds  int       `json:"timeout_seconds"`  // per request (default 3)
	Retries         int       `json:"retries"`          // default 1
	Concurrency     int       `json:"concurrency"`      // parallel polls (default 8)
	Profiles        []Profile `json:"profiles"`
}

// Profile is a set of credentials and the devices it applies to.
type Profile struct {
	ID   string `json:"id"` // stable id (OpenBao paths snmp/<id>/…)
	Name string `json:"name"`
	// Prefixes of the devices using this profile; empty = every device.
	Prefixes []string `json:"prefixes"`
	Version  string   `json:"version"` // "2c" or "3"
	Port     uint16   `json:"port"`    // default 161

	CommunityRef string `json:"community_ref,omitempty"` // v2c, openbao:// reference

	Username      string `json:"username,omitempty"` // v3
	SecurityLevel string `json:"security_level,omitempty"`
	AuthProtocol  string `json:"auth_protocol,omitempty"`
	AuthRef       string `json:"auth_ref,omitempty"`
	PrivProtocol  string `json:"priv_protocol,omitempty"`
	PrivRef       string `json:"priv_ref,omitempty"`
	ContextName   string `json:"context_name,omitempty"`
}

// Normalize fills defaults and validates (credentials are not checked).
func (s Settings) Normalize() (Settings, error) {
	if s.IntervalMinutes == 0 {
		s.IntervalMinutes = 30
	}
	if s.TTLMinutes == 0 {
		s.TTLMinutes = 360
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = 3
	}
	if s.Concurrency == 0 {
		s.Concurrency = 8
	}
	switch {
	case s.IntervalMinutes < 1 || s.IntervalMinutes > 1440:
		return s, errors.New("interval_minutes must be between 1 and 1440")
	case s.TTLMinutes < s.IntervalMinutes || s.TTLMinutes > 10080:
		return s, errors.New("ttl_minutes must be between interval_minutes and 10080")
	case s.TimeoutSeconds < 1 || s.TimeoutSeconds > 60:
		return s, errors.New("timeout_seconds must be between 1 and 60")
	case s.Retries < 0 || s.Retries > 5:
		return s, errors.New("retries must be between 0 and 5")
	case s.Concurrency < 1 || s.Concurrency > 64:
		return s, errors.New("concurrency must be between 1 and 64")
	}
	if s.Devices == nil {
		s.Devices = []string{}
	}
	for i, d := range s.Devices {
		a, err := netip.ParseAddr(strings.TrimSpace(d))
		if err != nil {
			return s, fmt.Errorf("device %q is not an IP address", d)
		}
		s.Devices[i] = a.Unmap().String()
	}
	if s.Profiles == nil {
		s.Profiles = []Profile{}
	}
	ids := map[string]bool{}
	for i := range s.Profiles {
		p := &s.Profiles[i]
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			return s, fmt.Errorf("profile %d: the name is required", i+1)
		}
		if p.ID == "" || ids[p.ID] || !validID(p.ID) {
			return s, fmt.Errorf("profile %q: invalid or duplicate id", p.Name)
		}
		ids[p.ID] = true
		if p.Port == 0 {
			p.Port = 161
		}
		if p.Prefixes == nil {
			p.Prefixes = []string{}
		}
		if _, err := parsePrefixes(p.Prefixes); err != nil {
			return s, fmt.Errorf("profile %q: %w", p.Name, err)
		}
		switch p.Version {
		case Version2c:
		case Version3:
			if strings.TrimSpace(p.Username) == "" {
				return s, fmt.Errorf("profile %q: SNMPv3 needs a user name", p.Name)
			}
			switch p.SecurityLevel {
			case "":
				p.SecurityLevel = AuthPriv
			case NoAuthNoPriv, AuthNoPriv, AuthPriv:
			default:
				return s, fmt.Errorf("profile %q: security_level must be %s, %s or %s", p.Name, NoAuthNoPriv, AuthNoPriv, AuthPriv)
			}
			if p.SecurityLevel != NoAuthNoPriv && !contains(AuthProtocols, p.AuthProtocol) {
				return s, fmt.Errorf("profile %q: auth_protocol must be one of %s", p.Name, strings.Join(AuthProtocols, ", "))
			}
			if p.SecurityLevel == AuthPriv && !contains(PrivProtocols, p.PrivProtocol) {
				return s, fmt.Errorf("profile %q: priv_protocol must be one of %s", p.Name, strings.Join(PrivProtocols, ", "))
			}
		default:
			return s, fmt.Errorf("profile %q: version must be 2c or 3", p.Name)
		}
	}
	return s, nil
}

func validID(id string) bool {
	if len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or prefix", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (s Settings) interval() time.Duration { return time.Duration(s.IntervalMinutes) * time.Minute }
func (s Settings) ttl() time.Duration      { return time.Duration(s.TTLMinutes) * time.Minute }
func (s Settings) timeout() time.Duration  { return time.Duration(s.TimeoutSeconds) * time.Second }

// SecretPath is the OpenBao path of a profile secret (community, auth, priv).
func SecretPath(profileID, what string) string { return "snmp/" + profileID + "/" + what }
