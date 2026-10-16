// Package inventory reads DCIM / IPAM / circuits data from Ledger
// (NetBox-compatible REST API, xc-token auth) and builds an immutable
// Snapshot with fast lookups for flow enrichment.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config of the Ledger connection.
type Config struct {
	// URL is the base URL of Ledger, e.g. "https://inventory.corp"
	// (the "/api/v1" suffix is optional).
	URL string
	// Token is the API token sent as the xc-token header.
	Token string
	// Timeout of one HTTP request (default 30 s).
	Timeout time.Duration
	// PageSize for list requests (default and max 1000).
	PageSize int
	// HTTPClient overrides the HTTP client (tests, custom TLS).
	HTTPClient *http.Client
	// SnmpIndexField is the interface custom field holding the SNMP
	// ifIndex (default "snmp_index").
	SnmpIndexField string
	// SkipVirtualization disables fetching virtual machines and their
	// interfaces.
	SkipVirtualization bool
}

// Client talks to Ledger.
type Client struct {
	base     string // ".../api/v1"
	token    string
	pageSize int
	http     *http.Client
	cfg      Config
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	u := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if u == "" {
		return nil, errors.New("inventory: URL is required")
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return nil, fmt.Errorf("inventory: invalid URL %q", cfg.URL)
	}
	if !strings.HasSuffix(u, "/api/v1") {
		u += "/api/v1"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.PageSize <= 0 || cfg.PageSize > 1000 {
		cfg.PageSize = 1000
	}
	if cfg.SnmpIndexField == "" {
		cfg.SnmpIndexField = "snmp_index"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{base: u, token: cfg.Token, pageSize: cfg.PageSize, http: hc, cfg: cfg}, nil
}

// HTTPError is a non-2xx answer from Ledger.
type HTTPError struct {
	Status  int
	Path    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("inventory: GET %s: HTTP %d: %s", e.Path, e.Status, e.Message)
}

func (c *Client) get(ctx context.Context, path string, q url.Values, v any) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	u := c.base + "/" + strings.TrimLeft(path, "/")
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("xc-token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("inventory: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		return &HTTPError{Status: resp.StatusCode, Path: path, Message: msg}
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("inventory: GET %s: decode: %w", path, err)
	}
	return nil
}

// list fetches every object of a list endpoint using limit/offset paging.
func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	offset := 0
	for {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(c.pageSize))
		q.Set("offset", strconv.Itoa(offset))
		var p page[T]
		if err := c.get(ctx, path, q, &p); err != nil {
			return nil, err
		}
		if out == nil && p.Count > 0 {
			out = make([]T, 0, p.Count)
		}
		out = append(out, p.Results...)
		offset += len(p.Results)
		if p.Next == nil || *p.Next == "" || len(p.Results) == 0 || offset >= p.Count {
			return out, nil
		}
		if offset > 10_000_000 {
			return nil, fmt.Errorf("inventory: GET %s: too many objects", path)
		}
	}
}

// Ping checks the connection and the token (used by POST /api/inventory-db/test).
func (c *Client) Ping(ctx context.Context) error {
	var p page[json.RawMessage]
	q := url.Values{}
	q.Set("limit", "1")
	return c.get(ctx, "dcim/sites/", q, &p)
}

// raw is everything a full sync downloads.
type raw struct {
	regions      []rawRegion
	tenants      []rawTenant
	sites        []rawSite
	devices      []rawDevice
	interfaces   []rawInterface
	vms          []rawVM
	vmInterfaces []rawVMInterface
	addresses    []rawIPAddress
	prefixes     []rawPrefix
	vlans        []rawVLAN
	vrfs         []rawVRF
	circuits     []rawCircuit
	circuitTypes []rawCircuitType
	providers    []rawProvider
	terminations []rawCircuitTermination
	cables       []rawCable
}

// fetch downloads everything, a few lists in parallel.
func (c *Client) fetch(ctx context.Context) (*raw, error) {
	r := &raw{}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job func() error
	jobs := []job{
		func() (err error) { r.regions, err = list[rawRegion](ctx, c, "dcim/regions/"); return },
		func() (err error) { r.tenants, err = list[rawTenant](ctx, c, "tenancy/tenants/"); return },
		func() (err error) { r.sites, err = list[rawSite](ctx, c, "dcim/sites/"); return },
		func() (err error) { r.devices, err = list[rawDevice](ctx, c, "dcim/devices/"); return },
		func() (err error) { r.interfaces, err = list[rawInterface](ctx, c, "dcim/interfaces/"); return },
		func() (err error) { r.addresses, err = list[rawIPAddress](ctx, c, "ipam/ip-addresses/"); return },
		func() (err error) { r.prefixes, err = list[rawPrefix](ctx, c, "ipam/prefixes/"); return },
		func() (err error) { r.vlans, err = list[rawVLAN](ctx, c, "ipam/vlans/"); return },
		func() (err error) { r.vrfs, err = list[rawVRF](ctx, c, "ipam/vrfs/"); return },
		func() (err error) { r.circuits, err = list[rawCircuit](ctx, c, "circuits/circuits/"); return },
		func() (err error) {
			r.circuitTypes, err = list[rawCircuitType](ctx, c, "circuits/circuit-types/")
			return
		},
		func() (err error) { r.providers, err = list[rawProvider](ctx, c, "circuits/providers/"); return },
		func() (err error) {
			r.terminations, err = list[rawCircuitTermination](ctx, c, "circuits/circuit-terminations/")
			return
		},
		func() (err error) { r.cables, err = list[rawCable](ctx, c, "dcim/cables/"); return },
	}
	if !c.cfg.SkipVirtualization {
		jobs = append(jobs,
			func() (err error) { r.vms, err = list[rawVM](ctx, c, "virtualization/virtual-machines/"); return },
			func() (err error) {
				r.vmInterfaces, err = list[rawVMInterface](ctx, c, "virtualization/interfaces/")
				return
			},
		)
	}
	const parallel = 4
	sem := make(chan struct{}, parallel)
	errc := make(chan error, len(jobs))
	for _, j := range jobs {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			errc <- j()
		}()
	}
	var first error
	for range jobs {
		if err := <-errc; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	if first != nil {
		return nil, first
	}
	return r, nil
}

// Fetch downloads everything and builds a snapshot.
func (c *Client) Fetch(ctx context.Context) (*Snapshot, error) {
	r, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return build(r, c.cfg.SnmpIndexField, time.Now()), nil
}

// LoadDir builds a snapshot from JSON list dumps named like the API paths
// ("dcim_devices.json" for /api/v1/dcim/devices/), each either a page
// {count, next, previous, results} or a plain array. Missing files are
// empty lists. Used by tests and for offline use.
func LoadDir(dir string) (*Snapshot, error) {
	r := &raw{}
	load := func(name string, v any) error {
		b, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 && b[0] == '{' {
			var p struct {
				Results json.RawMessage `json:"results"`
			}
			if err := json.Unmarshal(b, &p); err != nil {
				return fmt.Errorf("inventory: %s: %w", name, err)
			}
			b = p.Results
		}
		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("inventory: %s: %w", name, err)
		}
		return nil
	}
	for name, v := range map[string]any{
		"dcim_regions": &r.regions, "tenancy_tenants": &r.tenants, "dcim_sites": &r.sites, "dcim_devices": &r.devices,
		"dcim_interfaces": &r.interfaces, "virtualization_virtual-machines": &r.vms, "virtualization_interfaces": &r.vmInterfaces,
		"ipam_ip-addresses": &r.addresses, "ipam_prefixes": &r.prefixes, "ipam_vlans": &r.vlans, "ipam_vrfs": &r.vrfs,
		"circuits_circuits": &r.circuits, "circuits_circuit-types": &r.circuitTypes, "circuits_providers": &r.providers,
		"circuits_circuit-terminations": &r.terminations, "dcim_cables": &r.cables,
	} {
		if err := load(name, v); err != nil {
			return nil, err
		}
	}
	return build(r, "snmp_index", time.Now()), nil
}
