// Package devices manages network equipment (docs/devices.md): the device
// registry in PostgreSQL bound to Inventory DB, credentials in OpenBao,
// scheduled polling through internal/devices/drivers, clients merged by MAC,
// the network map, settings applied on devices and device down / up events
// for Umbrella.
//
// Inventory DB is the source of truth: when it is connected every managed
// device is bound to an Inventory DB device (inventory_id, source_ref) and
// takes its name, site and role from there; Flow keeps only the management
// data (address, platform, transport, credentials) and the live state.
// Without Inventory DB a device is a standalone local record.
package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/detector"
	"github.com/sbrw-evc/network/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/network/app/backend/internal/gnmi"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/inventory"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/snmp"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Settings keys read by the service.
const (
	SettingDevices = "devices"
	settingSNMP    = "snmp" // app.SettingSNMP
	settingGNMI    = "gnmi" // app.SettingGNMI
)

// Roles of a standalone device (a bound one takes its role from Inventory DB).
var Roles = []string{"router", "switch", "firewall", "ap", "controller", "server", "other"}

// SNMP credential sources.
const (
	SNMPOwn     = "own"     // the device's own SNMP credentials (OpenBao devices/<id>)
	SNMPProfile = "profile" // the SNMP profile of Flow that covers the address
)

// SecretPath is the OpenBao path of a device's credentials.
func SecretPath(id int64) string { return fmt.Sprintf("devices/%d", id) }

// AdminActions need devices:admin; the others devices:operate.
var AdminActions = []string{drivers.ActionReboot, drivers.ActionCommand, drivers.ActionBackup}

// EventSink delivers events to Umbrella (detector.Sender).
type EventSink interface {
	Deliver(ctx context.Context, events []detector.Event) error
}

// Config are the dependencies of the service.
type Config struct {
	Store *store.Store
	Vault *secrets.Client
	// Inventory is the Inventory DB snapshot of this process (nil = none).
	Inventory func() *inventory.Snapshot
	// Events receives device down / up events (nil = none).
	Events EventSink
	OUI    *OUI
	Log    *slog.Logger
	// Driver builds the driver of a device (tests replace it).
	Driver func(p *drivers.Platform, t drivers.Target, c drivers.Credentials) (drivers.Driver, error)
	Prober *drivers.Prober
	// LookupHost resolves a host name (net.DefaultResolver by default).
	LookupHost func(ctx context.Context, host string) ([]netip.Addr, error)
	// GNMIGet reads OpenConfig interfaces (gnmi.Get by default).
	GNMIGet func(ctx context.Context, a netip.Addr, p gnmi.Profile, c gnmi.Credentials, s gnmi.Settings) (map[uint32]gnmi.Interface, error)
	Now     func() time.Time
}

// Service is the device manager.
type Service struct {
	cfg Config
	st  *store.Store
	log *slog.Logger

	mu      sync.Mutex
	running map[int64]bool
	sem     chan struct{}
	repoll  sync.WaitGroup
	// bg is the context of background polls; stop cancels it (Close).
	bg        context.Context
	stop      context.CancelFunc
	lastPurge time.Time
}

// New returns the service.
func New(cfg Config) *Service {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.OUI == nil {
		cfg.OUI = NewOUI("", cfg.Log)
	}
	if cfg.Driver == nil {
		cfg.Driver = func(p *drivers.Platform, t drivers.Target, c drivers.Credentials) (drivers.Driver, error) {
			return p.Driver(t, c)
		}
	}
	if cfg.Prober == nil {
		cfg.Prober = &drivers.Prober{}
	}
	if cfg.LookupHost == nil {
		cfg.LookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.GNMIGet == nil {
		cfg.GNMIGet = gnmi.Get
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	bg, stop := context.WithCancel(context.Background())
	return &Service{cfg: cfg, st: cfg.Store, log: cfg.Log.With("component", "devices"), running: map[int64]bool{},
		sem: make(chan struct{}, 32), bg: bg, stop: stop}
}

// ---------------- errors ----------------

func invalid(format string, a ...any) error {
	return httpx.BadRequest("invalid_device", fmt.Sprintf(format, a...))
}

// deviceErr turns a driver error into a reply: what the device said is
// shown to the user (422), anything else is a 500.
func deviceErr(err error) error {
	if err == nil {
		return nil
	}
	var de *drivers.Error
	if errors.As(err, &de) {
		if errors.Is(err, drivers.ErrUnsupported) {
			return httpx.BadRequest("unsupported_action", de.Msg)
		}
		return &httpx.HTTPError{Status: http.StatusUnprocessableEntity, Code: "device_error", Msg: de.Msg}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &httpx.HTTPError{Status: http.StatusUnprocessableEntity, Code: "device_error", Msg: "the device did not answer in time"}
	}
	return err
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return httpx.NotFound("device not found")
	}
	return err
}

// ---------------- settings ----------------

// Settings of the device manager (settings key "devices").
type Settings struct {
	// CollectorAddress is where devices send flows ("Enable flow export"):
	// an IP address or a host name; "" = the host of the public URL.
	CollectorAddress string `json:"collector_address"`
	// NetFlowPort / SFlowPort: 0 = the ports of the collector settings.
	NetFlowPort            int `json:"netflow_port"`
	SFlowPort              int `json:"sflow_port"`
	EndpointOfflineMinutes int `json:"endpoint_offline_minutes"` // a client is offline after (15)
	EndpointRetentionDays  int `json:"endpoint_retention_days"`  // unnamed clients are forgotten after (90)
	Concurrency            int `json:"concurrency"`              // parallel polls (6)
}

// Normalize fills the defaults and checks the ranges.
func (s Settings) Normalize() (Settings, error) {
	s.CollectorAddress = strings.TrimSpace(s.CollectorAddress)
	if s.CollectorAddress != "" && drivers.NormIP(s.CollectorAddress) == "" && !hostRe.MatchString(s.CollectorAddress) {
		return s, invalid("The collector address must be an IP address or a host name")
	}
	for _, p := range []int{s.NetFlowPort, s.SFlowPort} {
		if p < 0 || p > 65535 {
			return s, invalid("Invalid collector port")
		}
	}
	if s.EndpointOfflineMinutes == 0 {
		s.EndpointOfflineMinutes = 15
	}
	if s.EndpointRetentionDays == 0 {
		s.EndpointRetentionDays = 90
	}
	if s.Concurrency == 0 {
		s.Concurrency = 6
	}
	if s.EndpointOfflineMinutes < 1 || s.EndpointOfflineMinutes > 1440 {
		return s, invalid("A client is offline after 1 to 1440 minutes")
	}
	if s.EndpointRetentionDays < 1 || s.EndpointRetentionDays > 3650 {
		return s, invalid("Clients are kept 1 to 3650 days")
	}
	if s.Concurrency < 1 || s.Concurrency > 32 {
		return s, invalid("Parallel polls: 1 to 32")
	}
	return s, nil
}

// Settings returns the stored settings with the defaults.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	var set Settings
	if _, err := s.st.Setting(ctx, SettingDevices, &set); err != nil {
		return set, err
	}
	n, err := set.Normalize()
	if err != nil {
		return Settings{EndpointOfflineMinutes: 15, EndpointRetentionDays: 90, Concurrency: 6}, nil
	}
	return n, nil
}

// PutSettings validates and stores the settings.
func (s *Service) PutSettings(ctx context.Context, set Settings) (Settings, error) {
	n, err := set.Normalize()
	if err != nil {
		return n, err
	}
	return n, s.st.PutSetting(ctx, SettingDevices, n)
}

// Collector is where "Enable flow export" points a device.
type Collector struct {
	Address     string `json:"address"` // as configured ("" = not known)
	IP          string `json:"ip"`      // resolved
	NetFlowPort int    `json:"netflow_port"`
	SFlowPort   int    `json:"sflow_port"`
	Source      string `json:"source"` // settings | public_url | ""
}

func portOf(addr string, def int) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return def
	}
	var n int
	if _, err := fmt.Sscan(p, &n); err != nil || n <= 0 {
		return def
	}
	return n
}

// Collector returns the flow collector of this installation: the address
// from the device settings, else the host of the public URL; the ports from
// the device settings, else from the collector settings.
func (s *Service) Collector(ctx context.Context) Collector {
	set, _ := s.Settings(ctx)
	var col setup.Collector
	_, _ = s.st.Setting(ctx, setup.SettingCollector, &col)
	c := Collector{Address: set.CollectorAddress, Source: "settings", NetFlowPort: set.NetFlowPort, SFlowPort: set.SFlowPort}
	if c.NetFlowPort == 0 {
		c.NetFlowPort = portOf(col.NetFlowAddr, 2055)
	}
	if c.SFlowPort == 0 {
		c.SFlowPort = portOf(col.SFlowAddr, 6343)
	}
	if c.Address == "" {
		var g setup.General
		_, _ = s.st.Setting(ctx, setup.SettingGeneral, &g)
		c.Address, c.Source = hostOfURL(g.PublicURL), "public_url"
	}
	if c.Address == "" {
		c.Source = ""
		return c
	}
	if ip := drivers.NormIP(c.Address); ip != "" {
		c.IP = ip
		return c
	}
	if addrs, err := s.cfg.LookupHost(ctx, c.Address); err == nil {
		for _, a := range addrs {
			if a.Is4() || a.Is4In6() {
				c.IP = a.Unmap().String()
				break
			}
		}
		if c.IP == "" && len(addrs) > 0 {
			c.IP = addrs[0].String()
		}
	}
	return c
}

func hostOfURL(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	u, _, _ = strings.Cut(u, "/")
	if at := strings.LastIndex(u, "@"); at >= 0 {
		u = u[at+1:]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return strings.Trim(u, "[]")
}

// ---------------- views ----------------

// IfaceState is an interface with rates computed from counter deltas.
type IfaceState struct {
	drivers.Interface
	RxBps       *float64 `json:"rx_bps"`
	TxBps       *float64 `json:"tx_bps"`
	Utilization *float64 `json:"utilization"` // % of the speed, the busier direction
}

// CredentialView is what the API tells about credentials: plain fields and
// which secret fields are set.
type CredentialView struct {
	Username         string          `json:"username"`
	SNMPVersion      string          `json:"snmp_version"`
	SNMPUser         string          `json:"snmp_user"`
	SNMPAuthProtocol string          `json:"snmp_auth_protocol"`
	SNMPPrivProtocol string          `json:"snmp_priv_protocol"`
	SNMPSource       string          `json:"snmp_source"` // own | profile
	Set              map[string]bool `json:"set"`         // secret field → set in OpenBao
}

// Counts summarise a device.
type Counts struct {
	Interfaces   int `json:"interfaces"`
	InterfacesUp int `json:"interfaces_up"`
	Neighbors    int `json:"neighbors"`
	Children     int `json:"children"`
	Endpoints    int `json:"endpoints"`
}

// View is a device in lists.
type View struct {
	ID             int64          `json:"id"`
	Name           string         `json:"name"`
	Platform       string         `json:"platform"`
	PlatformTitle  string         `json:"platform_title"`
	Vendor         string         `json:"vendor"`
	Kind           string         `json:"kind"`
	Host           string         `json:"host"`
	Port           *int           `json:"port"`
	Transport      string         `json:"transport"`
	VerifyTLS      bool           `json:"verify_tls"`
	ControllerSite string         `json:"controller_site"`
	InventoryID    *int           `json:"inventory_id"`
	SourceRef      string         `json:"source_ref"`
	Bound          bool           `json:"bound"`             // bound to Inventory DB
	InventoryGone  bool           `json:"inventory_missing"` // bound, but not in the loaded snapshot
	Site           string         `json:"site"`
	Role           string         `json:"role"`
	Tags           []string       `json:"tags"`
	Note           string         `json:"note"`
	Enabled        bool           `json:"enabled"`
	PollSeconds    int            `json:"poll_seconds"`
	FlowExporterIP string         `json:"flow_exporter_ip"`
	SSHHostKey     string         `json:"ssh_host_key"` // SHA-256 fingerprint of the pinned key ("" = none)
	Status         string         `json:"status"`
	Failures       int            `json:"failures"`
	LastPollAt     *time.Time     `json:"last_poll_at"`
	LastOKAt       *time.Time     `json:"last_ok_at"`
	LastError      string         `json:"last_error"`
	DownSince      *time.Time     `json:"down_since"`
	Alerted        bool           `json:"alerted"`
	Facts          drivers.Facts  `json:"facts"`
	Capabilities   []string       `json:"capabilities"`
	Counts         Counts         `json:"counts"`
	Credentials    CredentialView `json:"credentials"`
	ExporterIPs    []string       `json:"exporter_ips"` // addresses the device may export flows from
	CreatedBy      string         `json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Detail is a device with everything collected.
type Detail struct {
	View
	Interfaces []IfaceState        `json:"interfaces"`
	Neighbors  []drivers.Neighbor  `json:"neighbors"`
	Children   []drivers.Child     `json:"children"`
	Endpoints  []EndpointView      `json:"endpoints"`
	Collector  Collector           `json:"collector"`
	Platforms  *drivers.Describe   `json:"platform_info,omitempty"`
	Inventory  *inventory.Device   `json:"inventory,omitempty"`
	SNMP       *SNMPProfileSummary `json:"snmp_profile,omitempty"`
}

// SNMPProfileSummary names the Flow SNMP profile a device uses.
type SNMPProfileSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func decode[T any](raw json.RawMessage, def T) T {
	if len(raw) == 0 {
		return def
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return def
	}
	return v
}

func (s *Service) view(d store.NetworkDevice, snap *inventory.Snapshot) View {
	p, _ := drivers.Lookup(d.Platform)
	v := View{ID: d.ID, Name: d.Name, Platform: d.Platform, PlatformTitle: d.Platform, Host: d.Host, Port: d.Port,
		Transport: d.Transport, VerifyTLS: d.VerifyTLS, ControllerSite: d.ControllerSite, InventoryID: d.InventoryID,
		SourceRef: d.SourceRef, Bound: d.InventoryID != nil, Site: d.Site, Role: d.Role, Tags: d.Tags, Note: d.Note,
		Enabled: d.Enabled, PollSeconds: d.PollSeconds, FlowExporterIP: d.FlowExporterIP, Status: d.Status, Failures: d.Failures,
		LastPollAt: d.LastPollAt, LastOKAt: d.LastOKAt, LastError: d.LastError, DownSince: d.DownSince, Alerted: d.Alerted != nil,
		Facts: decode(d.Facts, drivers.Facts{}), CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
		Capabilities: []string{}}
	if d.SSHHostKey != "" {
		v.SSHHostKey = drivers.KeyFingerprint(d.SSHHostKey)
	}
	if p != nil {
		v.PlatformTitle, v.Kind = p.Title, p.Kind
		if v.Transport == "" {
			v.Transport = p.DefaultTransport()
		}
		v.Capabilities = p.Capabilities(v.Transport)
		v.Vendor = p.Vendor
	}
	if v.Facts.Vendor != "" {
		v.Vendor = v.Facts.Vendor
	}
	if v.Bound && snap != nil {
		if inv, ok := snap.Device(*d.InventoryID); ok {
			v.Name, v.Site, v.Role = inv.Name, inv.Site, inv.Role
		} else {
			v.InventoryGone = true
		}
	}
	ifs := decode(d.Interfaces, []IfaceState{})
	v.Counts.Interfaces = len(ifs)
	for _, i := range ifs {
		if i.OperUp != nil && *i.OperUp {
			v.Counts.InterfacesUp++
		}
	}
	v.Counts.Neighbors = len(decode(d.Neighbors, []drivers.Neighbor{}))
	v.Counts.Children = len(decode(d.Children, []drivers.Child{}))
	c := CredentialView{Username: d.Credentials[drivers.FieldUsername], SNMPVersion: d.Credentials[drivers.FieldSNMPVersion],
		SNMPUser: d.Credentials[drivers.FieldSNMPUser], SNMPAuthProtocol: d.Credentials[drivers.FieldSNMPAuthProtocol],
		SNMPPrivProtocol: d.Credentials[drivers.FieldSNMPPrivProtocol], SNMPSource: or(d.Credentials["snmp_source"], SNMPOwn),
		Set: map[string]bool{}}
	for _, f := range drivers.SecretFields {
		c.Set[f] = slices.Contains(d.Secrets, f)
	}
	v.Credentials = c
	v.ExporterIPs = exporterIPs(d, ifs)
	return v
}

func or(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// exporterIPs are the addresses a device may send flows from: the
// configured exporter address, the host and its interface addresses.
func exporterIPs(d store.NetworkDevice, ifs []IfaceState) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(a string) {
		ip := drivers.NormIP(a)
		if ip == "" || seen[ip] || strings.HasPrefix(ip, "fe80:") || strings.HasPrefix(ip, "127.") || ip == "::1" {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	add(d.FlowExporterIP)
	add(d.Host)
	for _, i := range ifs {
		for _, a := range i.Addresses {
			add(a)
		}
	}
	return out
}

func (s *Service) snapshot() *inventory.Snapshot {
	if s.cfg.Inventory == nil {
		return nil
	}
	return s.cfg.Inventory()
}

// Platforms describes the supported platforms.
func (s *Service) Platforms() []drivers.Describe {
	out := make([]drivers.Describe, 0, len(drivers.Platforms))
	for _, p := range drivers.Platforms {
		out = append(out, p.Describe())
	}
	return out
}

// List returns the devices.
func (s *Service) List(ctx context.Context) ([]View, error) {
	rows, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	snap := s.snapshot()
	counts := map[int64]int{}
	if eps, err := s.st.NetworkEndpoints(ctx, 0, 10000); err == nil {
		set, _ := s.Settings(ctx)
		cut := s.cfg.Now().Add(-time.Duration(set.EndpointOfflineMinutes) * time.Minute)
		for _, e := range eps {
			if e.DeviceID != nil && e.LastSeen.After(cut) {
				counts[*e.DeviceID]++
			}
		}
	}
	out := make([]View, 0, len(rows))
	for _, d := range rows {
		v := s.view(d, snap)
		v.Counts.Endpoints = counts[d.ID]
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Get returns a device with what it reported.
func (s *Service) Get(ctx context.Context, id int64) (Detail, error) {
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return Detail{}, notFound(err)
	}
	snap := s.snapshot()
	out := Detail{View: s.view(d, snap), Interfaces: decode(d.Interfaces, []IfaceState{}),
		Neighbors: decode(d.Neighbors, []drivers.Neighbor{}), Children: decode(d.Children, []drivers.Child{})}
	if p, err := drivers.Lookup(d.Platform); err == nil {
		desc := p.Describe()
		out.Platforms = &desc
	}
	if d.InventoryID != nil && snap != nil {
		if inv, ok := snap.Device(*d.InventoryID); ok {
			out.Inventory = inv
		}
	}
	eps, err := s.Endpoints(ctx, EndpointQuery{DeviceID: id, IncludeInfra: true})
	if err != nil {
		return out, err
	}
	out.Endpoints = eps
	out.Counts.Endpoints = 0
	for _, e := range eps {
		if e.Online {
			out.Counts.Endpoints++
		}
	}
	out.Collector = s.Collector(ctx)
	if out.Credentials.SNMPSource == SNMPProfile {
		if pr, ok := s.snmpProfileFor(ctx, d); ok {
			out.SNMP = &SNMPProfileSummary{ID: pr.ID, Name: pr.Name}
		}
	}
	return out, nil
}

// ---------------- input ----------------

// Input creates a device; Patch fields left nil are kept.
type Input struct {
	Platform       *string  `json:"platform"`
	Host           *string  `json:"host"`
	Port           *int     `json:"port"` // 0 = the default port
	Transport      *string  `json:"transport"`
	VerifyTLS      *bool    `json:"verify_tls"`
	ControllerSite *string  `json:"controller_site"`
	InventoryID    *int     `json:"inventory_id"` // 0 = unbind (standalone only without Inventory DB)
	Name           *string  `json:"name"`
	Site           *string  `json:"site"`
	Role           *string  `json:"role"`
	Tags           []string `json:"tags"`
	Note           *string  `json:"note"`
	Enabled        *bool    `json:"enabled"`
	PollSeconds    *int     `json:"poll_seconds"`
	FlowExporterIP *string  `json:"flow_exporter_ip"`
	SNMPSource     *string  `json:"snmp_source"`
	// Credentials: a plain field takes the value; a secret field "" or
	// null keeps the stored one (ClearCredentials removes it).
	Credentials      map[string]*string `json:"credentials"`
	ClearCredentials []string           `json:"clear_credentials"`
	// ID: a test of a saved device (stored secrets and host key).
	ID int64 `json:"id,omitempty"`
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$`)

func str(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

// inventoryConnected reports whether Inventory DB is the source of truth.
func (s *Service) inventoryConnected(ctx context.Context) bool {
	c, err := s.st.InventoryDB(ctx)
	return err == nil && c.Enabled && c.URL != ""
}

// apply merges in into d and validates; creating says whether d is new.
func (s *Service) apply(ctx context.Context, d *store.NetworkDevice, in Input, creating bool) error {
	if in.Platform != nil {
		d.Platform = str(in.Platform)
		if !creating && in.Transport == nil {
			d.Transport = ""
		}
	}
	p, err := drivers.Lookup(d.Platform)
	if err != nil {
		return invalid("Unknown platform %q", d.Platform)
	}
	if in.Host != nil {
		d.Host = str(in.Host)
	}
	if d.Host == "" || (drivers.NormIP(d.Host) == "" && !hostRe.MatchString(d.Host)) {
		return invalid("Enter the IP address or host name of the device")
	}
	if ip := drivers.NormIP(d.Host); ip != "" {
		d.Host = ip
	}
	if in.Port != nil {
		if *in.Port == 0 {
			d.Port = nil
		} else if *in.Port < 1 || *in.Port > 65535 {
			return invalid("Invalid port")
		} else {
			d.Port = in.Port
		}
	}
	if in.Transport != nil {
		d.Transport = str(in.Transport)
	}
	if d.Transport == "" {
		d.Transport = p.DefaultTransport()
	}
	if !p.HasTransport(d.Transport) {
		var names []string
		for _, t := range p.Transports {
			names = append(names, t.Name)
		}
		return invalid("%s: available transports: %s", p.Title, strings.Join(names, ", "))
	}
	if in.VerifyTLS != nil {
		d.VerifyTLS = *in.VerifyTLS
	}
	if in.ControllerSite != nil {
		d.ControllerSite = str(in.ControllerSite)
		if len(d.ControllerSite) > 128 {
			return invalid("The controller site is too long")
		}
	}
	if in.Note != nil {
		d.Note = strings.TrimSpace(*in.Note)
		if len(d.Note) > 4000 {
			return invalid("The note is too long")
		}
	}
	if in.Tags != nil {
		tags := []string{}
		for _, t := range in.Tags {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(tags, t) {
				if len(t) > 32 {
					return invalid("A tag is up to 32 characters")
				}
				tags = append(tags, t)
			}
		}
		if len(tags) > 16 {
			return invalid("Up to 16 tags")
		}
		d.Tags = tags
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if in.PollSeconds != nil {
		d.PollSeconds = *in.PollSeconds
	}
	if d.PollSeconds == 0 {
		d.PollSeconds = 300
	}
	if d.PollSeconds < 60 || d.PollSeconds > 86400 {
		return invalid("Poll interval: 60 to 86400 seconds")
	}
	if in.FlowExporterIP != nil {
		d.FlowExporterIP = str(in.FlowExporterIP)
		if d.FlowExporterIP != "" {
			ip := drivers.NormIP(d.FlowExporterIP)
			if ip == "" {
				return invalid("The flow exporter address must be an IP address")
			}
			d.FlowExporterIP = ip
		}
	}
	if d.Credentials == nil {
		d.Credentials = map[string]string{}
	}
	if in.SNMPSource != nil {
		src := str(in.SNMPSource)
		if src != SNMPOwn && src != SNMPProfile {
			return invalid("SNMP credentials: own or profile")
		}
		d.Credentials["snmp_source"] = src
	}
	for k, v := range in.Credentials {
		if drivers.IsSecret(k) || v == nil {
			continue
		}
		if !slices.Contains(drivers.PlainFields, k) {
			return invalid("Unknown credential field %s", k)
		}
		val := strings.TrimSpace(*v)
		switch k {
		case drivers.FieldSNMPVersion:
			if val != "" && val != "1" && val != "2c" && val != "3" {
				return invalid("SNMP version: 1, 2c or 3")
			}
		case drivers.FieldSNMPAuthProtocol:
			val = strings.ToLower(val)
			if val != "" && !slices.Contains(drivers.SNMPAuthProtocols, val) {
				return invalid("Unknown SNMP authentication protocol")
			}
		case drivers.FieldSNMPPrivProtocol:
			val = strings.ToLower(val)
			if val != "" && !slices.Contains(drivers.SNMPPrivProtocols, val) {
				return invalid("Unknown SNMP privacy protocol")
			}
		}
		if len(val) > 256 {
			return invalid("%s is too long", k)
		}
		if val == "" {
			delete(d.Credentials, k)
		} else {
			d.Credentials[k] = val
		}
	}
	for k, v := range in.Credentials {
		if !drivers.IsSecret(k) && !slices.Contains(drivers.PlainFields, k) {
			return invalid("Unknown credential field %s", k)
		}
		if drivers.IsSecret(k) && v != nil && len(*v) > 16384 {
			return invalid("%s is too long", k)
		}
	}

	// Binding: Inventory DB is the source of truth for the name, site and role.
	connected := s.inventoryConnected(ctx)
	if in.InventoryID != nil {
		if *in.InventoryID == 0 {
			if connected {
				return invalid("Inventory DB is connected: a managed device must be bound to an Inventory DB device")
			}
			d.InventoryID, d.SourceRef = nil, ""
		} else {
			if !connected {
				return invalid("Inventory DB is not connected")
			}
			snap := s.snapshot()
			if snap == nil {
				return invalid("Inventory DB is not loaded yet; try again in a minute")
			}
			inv, ok := snap.Device(*in.InventoryID)
			if !ok || inv.Kind != inventory.KindDevice {
				return invalid("Inventory DB has no device %d", *in.InventoryID)
			}
			id := inv.ID
			d.InventoryID, d.SourceRef = &id, inventory.DeviceRef(id)
			d.Name, d.Site, d.Role = inv.Name, inv.Site, inv.Role
		}
	} else if creating && connected {
		return invalid("Inventory DB is connected: pick the device in Inventory DB")
	}
	if d.InventoryID != nil {
		if (in.Name != nil && str(in.Name) != d.Name) || (in.Site != nil && str(in.Site) != d.Site) ||
			(in.Role != nil && str(in.Role) != d.Role) {
			return invalid("The name, site and role of a bound device come from Inventory DB; change them there")
		}
		return nil
	}
	if in.Name != nil {
		d.Name = str(in.Name)
	}
	if in.Site != nil {
		d.Site = str(in.Site)
	}
	if in.Role != nil {
		d.Role = str(in.Role)
	}
	if d.Name == "" {
		d.Name = d.Host
	}
	if len(d.Name) > 128 || len(d.Site) > 128 {
		return invalid("The name and site are up to 128 characters")
	}
	if d.Role == "" {
		d.Role = p.Kind
	}
	if !slices.Contains(Roles, d.Role) {
		return invalid("Unknown device role")
	}
	return nil
}

// secretsOf returns the secret values of the input (nil / "" = keep).
func secretsOf(in Input) map[string]string {
	out := map[string]string{}
	for k, v := range in.Credentials {
		if drivers.IsSecret(k) && v != nil && *v != "" {
			out[k] = *v
		}
	}
	return out
}

func conflict(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return &httpx.HTTPError{Status: http.StatusConflict, Code: "duplicate_device",
			Msg: "This device is already managed (the same Inventory DB device or the same address)"}
	}
	return err
}

// Create adds a device and starts its first poll.
func (s *Service) Create(ctx context.Context, actor string, in Input) (View, error) {
	d := store.NetworkDevice{Enabled: true, Credentials: map[string]string{}, CreatedBy: actor}
	if in.Platform == nil {
		return View{}, invalid("Choose the platform")
	}
	if err := s.apply(ctx, &d, in, true); err != nil {
		return View{}, err
	}
	sec := secretsOf(in)
	for k := range sec {
		d.Secrets = append(d.Secrets, k)
	}
	sort.Strings(d.Secrets)
	created, err := s.st.CreateNetworkDevice(ctx, d)
	if err != nil {
		return View{}, conflict(err)
	}
	if len(sec) > 0 {
		if err := s.cfg.Vault.Put(ctx, SecretPath(created.ID), sec); err != nil {
			_ = s.st.DeleteNetworkDevice(ctx, created.ID)
			return View{}, fmt.Errorf("credentials not stored in OpenBao: %w", err)
		}
	}
	s.pollLater(created.ID, 0)
	return s.view(created, s.snapshot()), nil
}

// Update changes a device.
func (s *Service) Update(ctx context.Context, id int64, in Input) (View, []string, error) {
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return View{}, nil, notFound(err)
	}
	host, port, site := d.Host, d.Port, d.ControllerSite
	if err := s.apply(ctx, &d, in, false); err != nil {
		return View{}, nil, err
	}
	if d.Host != host || !samePort(d.Port, port) || d.ControllerSite != site {
		d.SSHHostKey = "" // another device: trust its key on the next connection
	}
	sec := secretsOf(in)
	clear := map[string]string{}
	for _, k := range in.ClearCredentials {
		if !drivers.IsSecret(k) {
			if slices.Contains(drivers.PlainFields, k) {
				delete(d.Credentials, k)
				continue
			}
			return View{}, nil, invalid("Unknown credential field %s", k)
		}
		if _, set := sec[k]; !set {
			clear[k] = ""
		}
	}
	changed := []string{}
	for k := range sec {
		changed = append(changed, k)
	}
	for k := range clear {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	if len(sec)+len(clear) > 0 {
		all := map[string]string{}
		for k, v := range sec {
			all[k] = v
		}
		for k := range clear {
			all[k] = ""
		}
		if err := s.cfg.Vault.Put(ctx, SecretPath(id), all); err != nil {
			return View{}, nil, fmt.Errorf("credentials not stored in OpenBao: %w", err)
		}
		set := map[string]bool{}
		for _, k := range d.Secrets {
			set[k] = true
		}
		for k := range sec {
			set[k] = true
		}
		for k := range clear {
			delete(set, k)
		}
		d.Secrets = d.Secrets[:0]
		for k := range set {
			d.Secrets = append(d.Secrets, k)
		}
		sort.Strings(d.Secrets)
	}
	saved, err := s.st.UpdateNetworkDevice(ctx, d)
	if err != nil {
		return View{}, nil, conflict(notFound(err))
	}
	return s.view(saved, s.snapshot()), changed, nil
}

func samePort(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Delete removes a device, its credentials and resolves its alert.
func (s *Service) Delete(ctx context.Context, id int64) (View, error) {
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return View{}, notFound(err)
	}
	v := s.view(d, s.snapshot())
	if err := s.st.DeleteNetworkDevice(ctx, id); err != nil {
		return v, notFound(err)
	}
	if err := s.cfg.Vault.Delete(ctx, SecretPath(id)); err != nil {
		s.log.Warn("device credentials not deleted from OpenBao", "id", id, "err", err)
	}
	if d.Alerted != nil && s.cfg.Events != nil {
		_ = s.cfg.Events.Deliver(ctx, []detector.Event{s.event(ctx, d, v.Name, detector.StatusResolved)})
	}
	return v, nil
}

// ResetHostKey forgets the pinned SSH host key.
func (s *Service) ResetHostKey(ctx context.Context, id int64) (View, error) {
	if err := s.st.SetDeviceHostKey(ctx, id, ""); err != nil {
		return View{}, notFound(err)
	}
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return View{}, notFound(err)
	}
	return s.view(d, s.snapshot()), nil
}

// SetPositions stores map positions (device id → [x, y], null = automatic).
func (s *Service) SetPositions(ctx context.Context, pos map[string]*[2]float64) error {
	out := map[int64]*[2]float64{}
	for k, v := range pos {
		var id int64
		if _, err := fmt.Sscan(strings.TrimPrefix(k, "dev:"), &id); err != nil || id <= 0 {
			continue
		}
		out[id] = v
	}
	if len(out) > 5000 {
		return invalid("Too many positions")
	}
	return s.st.SetDevicePositions(ctx, out)
}

// ---------------- Inventory DB ----------------

// Candidate is an Inventory DB device that can be managed.
type Candidate struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Ref          string `json:"ref"`
	Site         string `json:"site"`
	Role         string `json:"role"`
	Status       string `json:"status"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Platform     string `json:"platform"`       // Inventory DB platform
	Host         string `json:"host"`           // primary address
	Guess        string `json:"platform_guess"` // a Flow platform key
}

// Candidates are the Inventory DB devices not managed yet.
type Candidates struct {
	Connected bool        `json:"connected"`
	Loaded    bool        `json:"loaded"`
	Devices   []Candidate `json:"devices"`
}

// guessPlatform maps Inventory DB manufacturer / platform names to a Flow platform.
func guessPlatform(text string) string {
	t := strings.ToLower(text)
	for _, g := range []struct{ re, key string }{
		{"routeros|mikrotik", "mikrotik"}, {"nx-?os|nexus", "cisco_nxos"}, {"meraki", "meraki"}, {"cisco|ios", "cisco_ios"},
		{"junos|juniper", "juniper"}, {"huawei|vrp", "huawei"}, {"comware|h3c", "hp_comware"}, {"aos-cx|aruba ?cx", "aruba_cx"},
		{"procurve|arubaos|aruba", "aruba_os"}, {"os10", "dell_os10"}, {"dell", "dell_nseries"}, {"fortinet|fortigate", "fortigate"},
		{"opnsense", "opnsense"}, {"pfsense|netgate", "pfsense"}, {"openwrt", "openwrt"}, {"keenetic", "keenetic"},
		{"omada", "omada"}, {"unifi|ubiquiti", "unifi"}, {"edgeos|vyos", "edgeos"}, {"zyxel", "zyxel"}, {"eltex", "eltex"},
		{"jetstream", "tplink_jetstream"}, {"tp-?link", "tplink"}, {"netgear", "netgear"}, {"d-?link", "dlink"},
		{"idrac|ilo|xclarity|supermicro", "redfish"}, {"linux|debian|ubuntu|proxmox", "linux"},
	} {
		if regexp.MustCompile(g.re).MatchString(t) {
			return g.key
		}
	}
	return ""
}

// InventoryCandidates lists the Inventory DB devices not managed yet.
func (s *Service) InventoryCandidates(ctx context.Context, q string) (Candidates, error) {
	out := Candidates{Connected: s.inventoryConnected(ctx), Devices: []Candidate{}}
	snap := s.snapshot()
	if snap == nil {
		return out, nil
	}
	out.Loaded = true
	rows, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return out, err
	}
	managed := map[int]bool{}
	for _, d := range rows {
		if d.InventoryID != nil {
			managed[*d.InventoryID] = true
		}
	}
	q = strings.ToLower(strings.TrimSpace(q))
	for _, d := range snap.Devices() {
		if d.Kind != inventory.KindDevice || managed[d.ID] {
			continue
		}
		c := Candidate{ID: d.ID, Name: d.Name, Ref: d.Ref, Site: d.Site, Role: d.Role, Status: d.Status, Manufacturer: d.Manufacturer,
			Model: d.Model, Platform: d.Platform, Guess: guessPlatform(d.Platform + " " + d.Manufacturer + " " + d.Model)}
		switch {
		case d.PrimaryIP4.IsValid():
			c.Host = d.PrimaryIP4.String()
		case d.PrimaryIP6.IsValid():
			c.Host = d.PrimaryIP6.String()
		case len(d.Addresses) > 0:
			c.Host = d.Addresses[0].String()
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name+" "+c.Host+" "+c.Site+" "+c.Model+" "+c.Manufacturer), q) {
			continue
		}
		out.Devices = append(out.Devices, c)
		if len(out.Devices) >= 500 {
			break
		}
	}
	sort.SliceStable(out.Devices, func(i, j int) bool {
		return strings.ToLower(out.Devices[i].Name) < strings.ToLower(out.Devices[j].Name)
	})
	return out, nil
}

// ---------------- driver plumbing ----------------

func (s *Service) resolve(ref string) (string, error) {
	if s.cfg.Vault == nil {
		return "", errors.New("OpenBao is not configured")
	}
	return secrets.Value(s.cfg.Vault, ref)
}

func (s *Service) addrOf(ctx context.Context, host string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), true
	}
	addrs, err := s.cfg.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, false
	}
	return addrs[0].Unmap(), true
}

func (s *Service) snmpSettings(ctx context.Context) snmp.Settings {
	var set snmp.Settings
	_, _ = s.st.Setting(ctx, settingSNMP, &set)
	if n, err := set.Normalize(); err == nil {
		return n
	}
	return set
}

// snmpProfileFor is the Flow SNMP profile covering the device (its host,
// else its flow exporter address).
func (s *Service) snmpProfileFor(ctx context.Context, d store.NetworkDevice) (snmp.Profile, bool) {
	set := s.snmpSettings(ctx)
	for _, h := range []string{d.Host, d.FlowExporterIP} {
		if h == "" {
			continue
		}
		if a, ok := s.addrOf(ctx, h); ok {
			if p, ok := set.ProfileFor(a); ok {
				return p, true
			}
		}
	}
	return snmp.Profile{}, false
}

// credentials resolves the credentials of a device: its own secrets from
// OpenBao (override replaces them, for an unsaved test), the Flow SNMP
// profile when the device uses one, and the gNMI profile for gnmi.
func (s *Service) credentials(ctx context.Context, d store.NetworkDevice, override map[string]string) (drivers.Credentials, error) {
	var c drivers.Credentials
	fields := c.Fields()
	for _, k := range drivers.PlainFields {
		if v := d.Credentials[k]; v != "" {
			*fields[k] = v
		}
	}
	if d.ID > 0 {
		for _, k := range d.Secrets {
			if _, ok := override[k]; ok {
				continue
			}
			v, err := s.resolve(s.cfg.Vault.Ref(SecretPath(d.ID), k))
			if err != nil {
				return c, fmt.Errorf("credentials of the device in OpenBao: %w", err)
			}
			if f, ok := fields[k]; ok {
				*f = v
			}
		}
	}
	for k, v := range override {
		if f, ok := fields[k]; ok {
			*f = v
		}
	}
	if d.Credentials["snmp_source"] == SNMPProfile {
		pr, ok := s.snmpProfileFor(ctx, d)
		if !ok {
			return c, &drivers.Error{Msg: "No SNMP profile of Flow covers " + d.Host + " (Settings → SNMP)"}
		}
		sc, err := snmp.ResolveCredentials(pr, s.resolve)
		if err != nil {
			return c, err
		}
		c.SNMPVersion, c.SNMPCommunity, c.SNMPUser, c.SNMPContext = pr.Version, sc.Community, pr.Username, pr.ContextName
		c.SNMPAuthProtocol, c.SNMPPrivProtocol = strings.ToLower(pr.AuthProtocol), strings.ToLower(pr.PrivProtocol)
		c.SNMPAuthPassword, c.SNMPPrivPassword = "", ""
		switch pr.SecurityLevel {
		case snmp.AuthNoPriv:
			c.SNMPAuthPassword = sc.Auth
		case snmp.AuthPriv, "":
			if pr.Version == snmp.Version3 {
				c.SNMPAuthPassword, c.SNMPPrivPassword = sc.Auth, sc.Priv
			}
		}
	}
	if d.Platform == "gnmi" {
		host := d.Host
		c.GNMI = func(ctx context.Context) ([]drivers.Interface, error) {
			var set gnmi.Settings
			_, _ = s.st.Setting(ctx, settingGNMI, &set)
			if n, err := set.Normalize(); err == nil {
				set = n
			}
			a, ok := s.addrOf(ctx, host)
			if !ok {
				return nil, fmt.Errorf("%s does not resolve", host)
			}
			pr, ok := set.ProfileFor(a)
			if !ok {
				return nil, errors.New("no gNMI profile of Flow covers " + host + " (Settings → gNMI)")
			}
			gc, err := gnmi.ResolveCredentials(pr, s.resolve)
			if err != nil {
				return nil, err
			}
			ifs, err := s.cfg.GNMIGet(ctx, a, pr, gc, set)
			if err != nil {
				return nil, err
			}
			idx := make([]uint32, 0, len(ifs))
			for k := range ifs {
				idx = append(idx, k)
			}
			slices.Sort(idx)
			out := make([]drivers.Interface, 0, len(ifs))
			for _, k := range idx {
				i := ifs[k]
				it := drivers.Interface{Name: i.Name, Index: drivers.P(int64(k)), Description: i.Descr}
				if i.Speed > 0 {
					it.SpeedMbps = drivers.P(int64(i.Speed / 1_000_000))
				}
				out = append(out, it)
			}
			return out, nil
		}
	}
	return c, nil
}

func target(d store.NetworkDevice) drivers.Target {
	t := drivers.Target{Host: d.Host, Transport: d.Transport, VerifyTLS: d.VerifyTLS, Site: d.ControllerSite, SSHHostKey: d.SSHHostKey}
	if d.Port != nil {
		t.Port = *d.Port
	}
	return t
}

func (s *Service) driver(ctx context.Context, d store.NetworkDevice, override map[string]string) (drivers.Driver, *drivers.Platform, error) {
	p, err := drivers.Lookup(d.Platform)
	if err != nil {
		return nil, nil, invalid("Unknown platform %q", d.Platform)
	}
	c, err := s.credentials(ctx, d, override)
	if err != nil {
		return nil, p, err
	}
	drv, err := s.cfg.Driver(p, target(d), c)
	return drv, p, err
}

// collect runs one poll of a device (at most 3 minutes).
func (s *Service) collect(ctx context.Context, d store.NetworkDevice, override map[string]string) (*drivers.Snapshot, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	drv, _, err := s.driver(ctx, d, override)
	if err != nil {
		return nil, "", err
	}
	defer drv.Close()
	snap, err := drv.Collect(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, drv.HostKey(), &drivers.Error{Msg: "Poll timed out (3 min)"}
	}
	return snap, drv.HostKey(), err
}

// TestResult is what a test connection found.
type TestResult struct {
	OK         bool          `json:"ok"`
	Facts      drivers.Facts `json:"facts"`
	Interfaces int           `json:"interfaces"`
	Neighbors  int           `json:"neighbors"`
	Endpoints  int           `json:"endpoints"`
	Children   int           `json:"children"`
	HostKey    string        `json:"host_key"` // fingerprint seen
}

// Test connects with unsaved parameters (in.ID: the stored secrets and the
// host key of a saved device) and returns what a poll would collect.
func (s *Service) Test(ctx context.Context, in Input) (TestResult, error) {
	d := store.NetworkDevice{Enabled: true, Credentials: map[string]string{}}
	if in.ID > 0 {
		saved, err := s.st.NetworkDevice(ctx, in.ID)
		if err != nil {
			return TestResult{}, notFound(err)
		}
		d = saved
	} else if in.Platform == nil {
		return TestResult{}, invalid("Choose the platform")
	}
	// The binding does not matter for a test.
	in.InventoryID, in.Name, in.Site, in.Role = nil, nil, nil, nil
	host, port := d.Host, d.Port
	keep := d.InventoryID
	d.InventoryID = nil
	if err := s.applyTest(ctx, &d, in); err != nil {
		return TestResult{}, err
	}
	d.InventoryID = keep
	if d.Host != host || !samePort(d.Port, port) {
		d.SSHHostKey = ""
	}
	override := secretsOf(in)
	for _, k := range in.ClearCredentials {
		override[k] = ""
	}
	snap, key, err := s.collect(ctx, d, override)
	if err != nil {
		return TestResult{}, deviceErr(err)
	}
	r := TestResult{OK: true, Facts: snap.Facts, Interfaces: len(snap.Interfaces), Neighbors: len(snap.Neighbors),
		Endpoints: len(snap.Endpoints), Children: len(snap.Children)}
	if key != "" {
		r.HostKey = drivers.KeyFingerprint(key)
	}
	return r, nil
}

// applyTest validates the connection fields only.
func (s *Service) applyTest(ctx context.Context, d *store.NetworkDevice, in Input) error {
	// A standalone record with a placeholder name and role: apply checks
	// the connection fields; the binding rules are skipped (no InventoryID).
	saved := *d
	err := s.apply(ctx, d, in, false)
	if err != nil {
		return err
	}
	d.Name, d.Site, d.Role = saved.Name, saved.Site, saved.Role
	return nil
}

// Discovered is an answering address with the device managing it, if any.
type Discovered struct {
	drivers.Found
	Known    bool  `json:"known"`
	DeviceID int64 `json:"device_id,omitempty"`
}

// Discover scans an address or a subnet (at most /22).
func (s *Service) Discover(ctx context.Context, target, community string) ([]Discovered, error) {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 64 || len(community) > 64 {
		return nil, invalid("Enter an address, a host name or a subnet (up to /22)")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var found []drivers.Found
	if _, err := netip.ParsePrefix(target); err == nil || drivers.NormIP(target) != "" {
		f, err := s.cfg.Prober.Scan(ctx, target, community)
		if err != nil && len(f) == 0 {
			var de *drivers.Error
			if errors.As(err, &de) {
				return nil, invalid("%s", de.Msg)
			}
			return nil, err
		}
		found = f
	} else if hostRe.MatchString(target) {
		f := s.cfg.Prober.Probe(ctx, target, community)
		if f.Reachable {
			found = []drivers.Found{f}
		}
	} else {
		return nil, invalid("Enter an address, a host name or a subnet (up to /22)")
	}
	rows, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]int64{}
	for _, d := range rows {
		known[strings.ToLower(d.Host)] = d.ID
		if d.FlowExporterIP != "" {
			known[d.FlowExporterIP] = d.ID
		}
	}
	out := make([]Discovered, 0, len(found))
	for _, f := range found {
		id, ok := known[strings.ToLower(f.Host)]
		out = append(out, Discovered{Found: f, Known: ok, DeviceID: id})
	}
	return out, nil
}
