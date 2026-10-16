// Package gnmi polls interface names, descriptions and speeds over gNMI
// (OpenConfig models) for exporters that Inventory DB does not describe, or
// whose interfaces have no name or speed there. It is an interface source of
// the enricher after the Inventory DB and the collector's option data, and
// before SNMP (when both answer for a device, gNMI wins).
//
// Each device is read with gNMI Get requests of the OpenConfig
// /interfaces/interface/state and subinterface leaves (ifindex, description)
// and of the Ethernet / aggregate speeds, or (profile mode "subscribe") with
// one long-lived Subscribe stream of the same leaves that delivers changes as
// they happen. Devices are the exporters seen by the collector / enricher
// (when PollExporters is set) and the configured Devices; each one is polled
// with the first credential profile whose prefixes contain it. Get results
// are refreshed every Interval; data is kept for TTL when a device stops
// answering. Credentials (password, CA certificate, client certificate and
// key for mutual TLS) live in OpenBao: the settings hold only openbao://
// references.
package gnmi

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Encodings of the Get requests.
const (
	EncodingJSONIETF = "json_ietf"
	EncodingJSON     = "json"
)

// Encodings are the accepted encoding names.
var Encodings = []string{EncodingJSONIETF, EncodingJSON}

// Modes of reading a device.
const (
	// ModeGet polls with Get requests every refresh period.
	ModeGet = "get"
	// ModeSubscribe keeps a Subscribe stream (STREAM, TARGET_DEFINED) open;
	// a device refusing it is polled with Get.
	ModeSubscribe = "subscribe"
)

// Modes are the accepted mode names.
var Modes = []string{ModeGet, ModeSubscribe}

// DefaultPort is the usual gNMI port (Nokia SR OS / SR Linux, Arista, gnmic).
const DefaultPort = 57400

// Settings are the gNMI poller settings (PostgreSQL settings key "gnmi").
type Settings struct {
	Enabled bool `json:"enabled"`
	// PollExporters polls the exporters seen in flows (within the prefixes
	// of a profile).
	PollExporters bool `json:"poll_exporters"`
	// Devices are polled even before they send flows (addresses).
	Devices         []string  `json:"devices"`
	IntervalMinutes int       `json:"interval_minutes"` // refresh period (default 30)
	TTLMinutes      int       `json:"ttl_minutes"`      // keep data of a silent device (default 360)
	TimeoutSeconds  int       `json:"timeout_seconds"`  // per request (default 10)
	Concurrency     int       `json:"concurrency"`      // parallel polls (default 8)
	Profiles        []Profile `json:"profiles"`
}

// Profile is a set of credentials and the devices it applies to.
type Profile struct {
	ID   string `json:"id"` // stable id (OpenBao paths gnmi/<id>/…)
	Name string `json:"name"`
	// Prefixes of the devices using this profile; empty = every device.
	Prefixes []string `json:"prefixes"`
	Port     uint16   `json:"port"` // default 57400

	// Username and password go in the "username" / "password" metadata of
	// every RPC (the gNMI convention); no username = no metadata.
	Username    string `json:"username,omitempty"`
	PasswordRef string `json:"password_ref,omitempty"` // openbao:// reference

	TLS        bool   `json:"tls"`
	SkipVerify bool   `json:"skip_verify,omitempty"` // do not check the device certificate
	CARef      string `json:"ca_ref,omitempty"`      // PEM CA bundle, openbao:// reference; empty = system roots
	ServerName string `json:"server_name,omitempty"` // expected certificate name; empty = the address
	// Client certificate and private key (PEM, openbao:// references) for
	// mutual TLS; both or neither.
	CertRef string `json:"cert_ref,omitempty"`
	KeyRef  string `json:"key_ref,omitempty"`

	// Encoding of the Get requests: json_ietf (default) or json. A device
	// rejecting json_ietf is asked again with json.
	Encoding string `json:"encoding"`
	// Mode: get (default) or subscribe.
	Mode string `json:"mode"`
}

// Normalize fills defaults and validates (credentials are not checked).
func (s Settings) Normalize() (Settings, error) {
	// Work on copies: the caller keeps its slices.
	s.Devices, s.Profiles = slices.Clone(s.Devices), slices.Clone(s.Profiles)
	for i := range s.Profiles {
		s.Profiles[i].Prefixes = slices.Clone(s.Profiles[i].Prefixes)
	}
	if s.IntervalMinutes == 0 {
		s.IntervalMinutes = 30
	}
	if s.TTLMinutes == 0 {
		s.TTLMinutes = 360
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = 10
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
			p.Port = DefaultPort
		}
		if p.Prefixes == nil {
			p.Prefixes = []string{}
		}
		if _, err := parsePrefixes(p.Prefixes); err != nil {
			return s, fmt.Errorf("profile %q: %w", p.Name, err)
		}
		p.Username = strings.TrimSpace(p.Username)
		p.ServerName = strings.TrimSpace(p.ServerName)
		switch p.Encoding {
		case "":
			p.Encoding = EncodingJSONIETF
		case EncodingJSONIETF, EncodingJSON:
		default:
			return s, fmt.Errorf("profile %q: encoding must be %s or %s", p.Name, EncodingJSONIETF, EncodingJSON)
		}
		switch p.Mode {
		case "":
			p.Mode = ModeGet
		case ModeGet, ModeSubscribe:
		default:
			return s, fmt.Errorf("profile %q: mode must be %s or %s", p.Name, ModeGet, ModeSubscribe)
		}
		if !p.TLS {
			p.SkipVerify, p.ServerName = false, ""
		}
		if (p.CertRef == "") != (p.KeyRef == "") {
			return s, fmt.Errorf("profile %q: the client certificate and its key go together", p.Name)
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

// SecretPath is the OpenBao path of a profile secret (password, ca, cert,
// key).
func SecretPath(profileID, what string) string { return "gnmi/" + profileID + "/" + what }

// ProfileFor returns the first profile whose prefixes contain a (a profile
// without prefixes covers every device). Managed network devices of the
// gnmi platform use it (internal/devices).
func (s Settings) ProfileFor(a netip.Addr) (Profile, bool) {
	a = a.Unmap()
	for _, pr := range s.Profiles {
		nets, err := parsePrefixes(pr.Prefixes)
		if err != nil {
			continue
		}
		if len(nets) == 0 {
			return pr, true
		}
		for _, n := range nets {
			if n.Contains(a) {
				return pr, true
			}
		}
	}
	return Profile{}, false
}

// ResolveCredentials resolves the secrets of a profile.
func ResolveCredentials(p Profile, resolve Resolver) (Credentials, error) {
	return resolveCredentials(p, resolve)
}
