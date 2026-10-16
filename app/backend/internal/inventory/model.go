package inventory

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Wire types: the subset of Ledger's NetBox-compatible JSON that the
// snapshot needs. Unknown fields are ignored, missing ones stay zero.

// ref is a nested reference {id, url, display, ...brief fields}.
type ref struct {
	ID      int    `json:"id"`
	Display string `json:"display"`
	Name    string `json:"name"`
	Slug    string `json:"slug"`
	Model   string `json:"model"`
	CID     string `json:"cid"`
	VID     int    `json:"vid"`
	RD      string `json:"rd"`
	Address string `json:"address"`
}

func (r *ref) id() int {
	if r == nil {
		return 0
	}
	return r.ID
}

func (r *ref) name() string {
	if r == nil {
		return ""
	}
	if r.Name != "" {
		return r.Name
	}
	return r.Display
}

// choice is {"value": "...", "label": "..."}; value may be a string or a
// number (family). A plain string is accepted too.
type choice struct {
	Value string
	Label string
}

func (c *choice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		return json.Unmarshal(b, &c.Value)
	}
	var o struct {
		Value json.RawMessage `json:"value"`
		Label string          `json:"label"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	c.Label = o.Label
	v := strings.TrimSpace(string(o.Value))
	if strings.HasPrefix(v, `"`) {
		return json.Unmarshal(o.Value, &c.Value)
	}
	if v != "null" {
		c.Value = v
	}
	return nil
}

type tag struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func tagNames(ts []tag) []string {
	if len(ts) == 0 {
		return nil
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		if t.Slug != "" {
			out = append(out, t.Slug)
		} else if t.Name != "" {
			out = append(out, t.Name)
		}
	}
	return out
}

type page[T any] struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []T     `json:"results"`
}

type rawRegion struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Parent *ref   `json:"parent"`
}

type rawTenant struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type rawSite struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Region *ref   `json:"region"`
	Tenant *ref   `json:"tenant"`
	Tags   []tag  `json:"tags"`
}

type rawDeviceType struct {
	ID           int    `json:"id"`
	Model        string `json:"model"`
	Manufacturer *ref   `json:"manufacturer"`
}

type rawDevice struct {
	ID           int            `json:"id"`
	Name         string         `json:"name"`
	Display      string         `json:"display"`
	DeviceType   *rawDeviceType `json:"device_type"`
	Role         *ref           `json:"role"`
	DeviceRole   *ref           `json:"device_role"` // NetBox < 4
	Tenant       *ref           `json:"tenant"`
	Platform     *ref           `json:"platform"`
	Site         *ref           `json:"site"`
	Cluster      *ref           `json:"cluster"`
	Status       choice         `json:"status"`
	PrimaryIP4   *ref           `json:"primary_ip4"`
	PrimaryIP6   *ref           `json:"primary_ip6"`
	OOBIP        *ref           `json:"oob_ip"` // NetBox 4; not in Ledger yet
	Tags         []tag          `json:"tags"`
	CustomFields map[string]any `json:"custom_fields"`
}

type rawVM struct {
	ID           int            `json:"id"`
	Name         string         `json:"name"`
	Display      string         `json:"display"`
	Role         *ref           `json:"role"`
	Tenant       *ref           `json:"tenant"`
	Platform     *ref           `json:"platform"`
	Site         *ref           `json:"site"`
	Cluster      *ref           `json:"cluster"`
	Status       choice         `json:"status"`
	PrimaryIP4   *ref           `json:"primary_ip4"`
	PrimaryIP6   *ref           `json:"primary_ip6"`
	Tags         []tag          `json:"tags"`
	CustomFields map[string]any `json:"custom_fields"`
}

// peer is an element of link_peers / connected_endpoints / cable terminations.
type peer struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Device  *ref   `json:"device"`
	Circuit *ref   `json:"circuit"`
}

type rawInterface struct {
	ID                     int            `json:"id"`
	Device                 *ref           `json:"device"`
	Name                   string         `json:"name"`
	Label                  string         `json:"label"`
	Type                   choice         `json:"type"`
	Enabled                *bool          `json:"enabled"`
	Parent                 *ref           `json:"parent"`
	LAG                    *ref           `json:"lag"`
	Speed                  *int64         `json:"speed"` // Kbps
	Description            string         `json:"description"`
	Mode                   choice         `json:"mode"`
	UntaggedVLAN           *ref           `json:"untagged_vlan"`
	VRF                    *ref           `json:"vrf"` // NetBox 3.3+; Ledger derives it from addresses
	Cable                  *ref           `json:"cable"`
	LinkPeers              []peer         `json:"link_peers"`
	LinkPeersType          string         `json:"link_peers_type"`
	ConnectedEndpoints     []peer         `json:"connected_endpoints"`
	ConnectedEndpointsType string         `json:"connected_endpoints_type"`
	Tags                   []tag          `json:"tags"`
	CustomFields           map[string]any `json:"custom_fields"`
}

type rawVMInterface struct {
	ID             int    `json:"id"`
	VirtualMachine *ref   `json:"virtual_machine"`
	Name           string `json:"name"`
	Description    string `json:"description"`
}

type rawAssigned struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Device         *ref   `json:"device"`
	VirtualMachine *ref   `json:"virtual_machine"`
}

type rawIPAddress struct {
	ID                 int          `json:"id"`
	Address            string       `json:"address"`
	VRF                *ref         `json:"vrf"`
	Tenant             *ref         `json:"tenant"`
	Status             choice       `json:"status"`
	Role               choice       `json:"role"`
	AssignedObjectType string       `json:"assigned_object_type"`
	AssignedObjectID   *int         `json:"assigned_object_id"`
	AssignedObject     *rawAssigned `json:"assigned_object"`
	DNSName            string       `json:"dns_name"`
	Description        string       `json:"description"`
}

type rawPrefix struct {
	ID           int            `json:"id"`
	Prefix       string         `json:"prefix"`
	VRF          *ref           `json:"vrf"`
	Site         *ref           `json:"site"`
	ScopeType    string         `json:"scope_type"`
	Scope        *ref           `json:"scope"`
	Tenant       *ref           `json:"tenant"`
	VLAN         *ref           `json:"vlan"`
	Status       choice         `json:"status"`
	Role         *ref           `json:"role"`
	Description  string         `json:"description"`
	Tags         []tag          `json:"tags"`
	CustomFields map[string]any `json:"custom_fields"`
}

type rawVLAN struct {
	ID     int    `json:"id"`
	VID    int    `json:"vid"`
	Name   string `json:"name"`
	Site   *ref   `json:"site"`
	Tenant *ref   `json:"tenant"`
	Role   *ref   `json:"role"`
}

type rawVRF struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	RD     string `json:"rd"`
	Tenant *ref   `json:"tenant"`
}

type rawCircuit struct {
	ID          int    `json:"id"`
	CID         string `json:"cid"`
	Provider    *ref   `json:"provider"`
	Type        *ref   `json:"type"`
	Status      choice `json:"status"`
	Tenant      *ref   `json:"tenant"`
	CommitRate  *int64 `json:"commit_rate"` // Kbps
	Description string `json:"description"`
}

type rawCircuitType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type rawProvider struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type rawCircuitTermination struct {
	ID                     int    `json:"id"`
	Circuit                *ref   `json:"circuit"`
	TermSide               choice `json:"term_side"`
	Site                   *ref   `json:"site"`
	PortSpeed              *int64 `json:"port_speed"`
	UpstreamSpeed          *int64 `json:"upstream_speed"`
	LinkPeers              []peer `json:"link_peers"`
	LinkPeersType          string `json:"link_peers_type"`
	ConnectedEndpoints     []peer `json:"connected_endpoints"`
	ConnectedEndpointsType string `json:"connected_endpoints_type"`
}

type rawTermination struct {
	ObjectType string `json:"object_type"`
	ObjectID   int    `json:"object_id"`
	Object     *peer  `json:"object"`
}

type rawCable struct {
	ID            int              `json:"id"`
	Status        choice           `json:"status"`
	ATerminations []rawTermination `json:"a_terminations"`
	BTerminations []rawTermination `json:"b_terminations"`
}

// cfUint reads an unsigned integer custom field stored as a number or a
// numeric string.
func cfUint(cf map[string]any, name string) (uint32, bool) {
	v, ok := cf[name]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		if x > 0 && x <= 1<<32-1 && x == float64(uint32(x)) {
			return uint32(x), true
		}
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(x), 10, 32)
		if err == nil && n > 0 {
			return uint32(n), true
		}
	case json.Number:
		n, err := strconv.ParseUint(x.String(), 10, 32)
		if err == nil && n > 0 {
			return uint32(n), true
		}
	}
	return 0, false
}
