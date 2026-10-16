package devices

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/detector"
	"github.com/sbrw-evc/network/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// Polling, clients, settings applied on devices, and the down / up events.

// Scheduler constants.
const (
	tickEvery     = 15 * time.Second
	actionTimeout = 5 * time.Minute
	repollDelay   = 3 * time.Second
	freshWindow   = 30 * time.Minute // sightings merged into a client
	maxOutput     = 200_000
	// SignalDeviceDown is the Umbrella signal of an unreachable device.
	SignalDeviceDown = "use.device.down"
)

// sourceRank orders sightings: the most specific attachment point wins.
var sourceRank = map[string]int{drivers.SourceWiFi: 5, drivers.SourceController: 4, drivers.SourceBridge: 3,
	drivers.SourceDHCP: 2, drivers.SourceARP: 1}

// PollResult is the outcome of a poll.
type PollResult struct {
	OK       bool   `json:"ok"`
	Status   string `json:"status"`
	Failures int    `json:"failures"`
	Error    string `json:"error"`
}

// errMessage is what a failed poll records.
func errMessage(err error) string {
	var de *drivers.Error
	if errors.As(err, &de) {
		return de.Msg
	}
	var he *httpx.HTTPError
	if errors.As(err, &he) {
		return he.Msg
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Poll timed out (3 min)"
	}
	return err.Error()
}

// Poll polls a device now (one poll per device at a time).
func (s *Service) Poll(ctx context.Context, id int64) (PollResult, error) {
	s.mu.Lock()
	if s.running[id] {
		s.mu.Unlock()
		return PollResult{}, &httpx.HTTPError{Status: http.StatusConflict, Code: "poll_running", Msg: "A poll of this device is already running"}
	}
	s.running[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, id)
		s.mu.Unlock()
	}()
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return PollResult{}, ctx.Err()
	}
	defer func() { <-s.sem }()
	return s.poll(ctx, id)
}

func (s *Service) poll(ctx context.Context, id int64) (PollResult, error) {
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return PollResult{}, notFound(err)
	}
	started := s.cfg.Now()
	snap, key, err := s.collect(ctx, d, nil)
	if err == nil && snap == nil {
		err = errors.New("the driver returned nothing")
	}
	if err != nil {
		msg := errMessage(err)
		var de *drivers.Error
		if !errors.As(err, &de) {
			s.log.Warn("device poll failed", "id", id, "host", d.Host, "err", err)
		}
		status, failures, serr := s.st.SaveDevicePoll(ctx, id, store.DevicePoll{At: started, Error: msg})
		if serr != nil {
			return PollResult{}, serr
		}
		return PollResult{Status: status, Failures: failures, Error: msg}, nil
	}
	elapsed := 0.0
	if d.LastOKAt != nil {
		elapsed = started.Sub(*d.LastOKAt).Seconds()
	}
	ifs := withRates(decode(d.Interfaces, []IfaceState{}), snap.Interfaces, elapsed)
	p := store.DevicePoll{At: started, OK: true, HostKey: key, Facts: mustJSON(snap.Facts), Interfaces: mustJSON(ifs),
		Neighbors: mustJSON(nonNilSlice(snap.Neighbors)), Children: mustJSON(nonNilSlice(snap.Children))}
	if d.InventoryID == nil {
		p.Name = truncate(strings.TrimSpace(snap.Facts.Hostname), 128)
	}
	status, failures, err := s.st.SaveDevicePoll(ctx, id, p)
	if err != nil {
		return PollResult{}, err
	}
	if err := s.storeEndpoints(ctx, id, snap.Endpoints, started); err != nil {
		s.log.Warn("device clients not stored", "id", id, "err", err)
	}
	return PollResult{OK: true, Status: status, Failures: failures}, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// withRates computes the rates of the interfaces from the byte counters of
// the previous successful poll elapsed seconds ago.
func withRates(prev []IfaceState, cur []drivers.Interface, elapsed float64) []IfaceState {
	old := map[string]IfaceState{}
	for _, i := range prev {
		old[i.Name] = i
	}
	out := make([]IfaceState, 0, len(cur))
	for _, i := range cur {
		st := IfaceState{Interface: i}
		o, ok := old[i.Name]
		rate := func(a, b *uint64) *float64 {
			if !ok || elapsed <= 0 || a == nil || b == nil || *b < *a {
				return nil
			}
			v := math.Round(float64(*b-*a)*8/elapsed*10) / 10
			return &v
		}
		st.RxBps, st.TxBps = rate(o.RxBytes, i.RxBytes), rate(o.TxBytes, i.TxBytes)
		if i.SpeedMbps != nil && *i.SpeedMbps > 0 && (st.RxBps != nil || st.TxBps != nil) {
			hi := 0.0
			for _, r := range []*float64{st.RxBps, st.TxBps} {
				if r != nil && *r > hi {
					hi = *r
				}
			}
			u := math.Round(hi/(float64(*i.SpeedMbps)*1e4)*10) / 10
			st.Utilization = &u
		}
		out = append(out, st)
	}
	return out
}

// ---------------- clients ----------------

func isClientMAC(mac string) bool {
	return mac != "" && !strings.HasPrefix(mac, "01:00:5e") && !strings.HasPrefix(mac, "33:33") && mac != "ff:ff:ff:ff:ff:ff"
}

func intp(v *int64) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}

// storeEndpoints replaces what a device saw and re-merges those clients.
func (s *Service) storeEndpoints(ctx context.Context, deviceID int64, eps []drivers.Endpoint, at time.Time) error {
	type key struct{ mac, source string }
	merged := map[key]*store.EndpointSighting{}
	var order []key
	for _, e := range eps {
		mac := drivers.NormMAC(e.MAC)
		if !isClientMAC(mac) {
			continue
		}
		src := e.Source
		if _, ok := sourceRank[src]; !ok {
			src = drivers.SourceARP
		}
		k := key{mac, src}
		cur := merged[k]
		if cur == nil {
			cur = &store.EndpointSighting{MAC: mac, DeviceID: deviceID, Source: src, SeenAt: at}
			merged[k] = cur
			order = append(order, k)
		}
		fill := func(dst *string, v string, n int) {
			if *dst == "" && v != "" {
				*dst = truncate(v, n)
			}
		}
		fill(&cur.IP, drivers.NormIP(e.IP), 64)
		fill(&cur.Hostname, e.Hostname, 128)
		fill(&cur.Interface, e.Interface, 128)
		fill(&cur.SSID, e.SSID, 128)
		fill(&cur.AttachedTo, drivers.NormMAC(e.AttachedTo), 64)
		fill(&cur.Port, e.Port, 64)
		if cur.Signal == nil {
			cur.Signal = intp(e.Signal)
		}
		if cur.VLAN == nil {
			cur.VLAN = intp(e.VLAN)
		}
		cur.Blocked = cur.Blocked || e.Blocked
	}
	rows := make([]store.EndpointSighting, 0, len(order))
	macs := map[string]bool{}
	for _, k := range order {
		rows = append(rows, *merged[k])
		macs[k.mac] = true
	}
	if err := s.st.ReplaceSightings(ctx, deviceID, rows); err != nil {
		return err
	}
	list := make([]string, 0, len(macs))
	for m := range macs {
		list = append(list, m)
	}
	return s.rebuildEndpoints(ctx, list)
}

// rebuildEndpoints merges the fresh sightings of each MAC into one client:
// the best attachment point, any known address and name.
func (s *Service) rebuildEndpoints(ctx context.Context, macs []string) error {
	sort.Strings(macs)
	now := s.cfg.Now()
	for i := 0; i < len(macs); i += 500 {
		chunk := macs[i:min(i+500, len(macs))]
		rows, err := s.st.Sightings(ctx, chunk, now.Add(-freshWindow))
		if err != nil {
			return err
		}
		by := map[string][]store.EndpointSighting{}
		for _, r := range rows {
			by[r.MAC] = append(by[r.MAC], r)
		}
		existing, err := s.st.EndpointsByMAC(ctx, chunk)
		if err != nil {
			return err
		}
		known := map[string]store.NetworkEndpoint{}
		for _, e := range existing {
			known[e.MAC] = e
		}
		out := make([]store.NetworkEndpoint, 0, len(by))
		for _, mac := range chunk {
			sights := by[mac]
			if len(sights) == 0 {
				continue
			}
			out = append(out, mergeSightings(mac, sights, known[mac], now, s.cfg.OUI))
		}
		if err := s.st.UpsertEndpoints(ctx, out); err != nil {
			return err
		}
	}
	return nil
}

// mergeSightings builds the client of a MAC from its sightings.
func mergeSightings(mac string, sights []store.EndpointSighting, prev store.NetworkEndpoint, now time.Time, oui *OUI) store.NetworkEndpoint {
	ranked := slices.Clone(sights)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if sourceRank[a.Source] != sourceRank[b.Source] {
			return sourceRank[a.Source] > sourceRank[b.Source]
		}
		return a.SeenAt.After(b.SeenAt)
	})
	best := ranked[0]
	e := prev
	e.MAC = mac
	if e.FirstSeen.IsZero() {
		e.FirstSeen = now
	}
	ip := ""
	for _, r := range ranked {
		if r.IP != "" {
			ip = r.IP
			break
		}
	}
	e.IP = or(ip, prev.IP)
	host := ""
	for _, r := range sights {
		if r.Hostname != "" {
			host = r.Hostname
			break
		}
	}
	e.Hostname = or(host, prev.Hostname)
	id := best.DeviceID
	e.DeviceID = &id
	e.Interface, e.Source, e.AttachedTo, e.Port, e.SSID = best.Interface, best.Source, best.AttachedTo, best.Port, best.SSID
	e.Signal = best.Signal
	if best.VLAN != nil {
		e.VLAN = best.VLAN
	}
	e.Blocked = false
	e.LastSeen = time.Time{}
	for _, r := range sights {
		e.Blocked = e.Blocked || r.Blocked
		if r.SeenAt.After(e.LastSeen) {
			e.LastSeen = r.SeenAt
		}
	}
	if e.Vendor == "" && oui != nil {
		e.Vendor = oui.Vendor(mac)
	}
	return e
}

// EndpointView is a client in the API.
type EndpointView struct {
	store.NetworkEndpoint
	Name       string `json:"name"` // alias, else hostname
	DeviceName string `json:"device_name"`
	Online     bool   `json:"online"`
}

// EndpointQuery filters clients.
type EndpointQuery struct {
	Q        string
	Online   *bool
	DeviceID int64
	// IncludeInfra keeps the MACs of network equipment (managed devices,
	// controller children, neighbours), which are not clients.
	IncludeInfra bool
	Limit        int
}

// infraMACs are the MACs of network equipment.
func infraMACs(devs []store.NetworkDevice) map[string]bool {
	out := map[string]bool{}
	add := func(m string) {
		if m = drivers.NormMAC(m); m != "" {
			out[m] = true
		}
	}
	for _, d := range devs {
		add(decode(d.Facts, drivers.Facts{}).MAC)
		for _, i := range decode(d.Interfaces, []IfaceState{}) {
			add(i.MAC)
		}
		for _, c := range decode(d.Children, []drivers.Child{}) {
			add(c.MAC)
		}
		for _, n := range decode(d.Neighbors, []drivers.Neighbor{}) {
			add(n.RemoteMAC)
		}
	}
	return out
}

func (s *Service) offlineAfter(ctx context.Context) time.Duration {
	set, _ := s.Settings(ctx)
	return time.Duration(set.EndpointOfflineMinutes) * time.Minute
}

func (s *Service) endpointView(e store.NetworkEndpoint, names map[int64]string, offline time.Duration) EndpointView {
	v := EndpointView{NetworkEndpoint: e, Name: or(e.Alias, e.Hostname), Online: s.cfg.Now().Sub(e.LastSeen) <= offline}
	if e.DeviceID != nil {
		v.DeviceName = names[*e.DeviceID]
	}
	return v
}

func (s *Service) deviceNames(devs []store.NetworkDevice) map[int64]string {
	snap := s.snapshot()
	names := map[int64]string{}
	for _, d := range devs {
		names[d.ID] = d.Name
		if d.InventoryID != nil && snap != nil {
			if inv, ok := snap.Device(*d.InventoryID); ok {
				names[d.ID] = inv.Name
			}
		}
	}
	return names
}

// Endpoints lists the clients, newest first.
func (s *Service) Endpoints(ctx context.Context, q EndpointQuery) ([]EndpointView, error) {
	rows, err := s.st.NetworkEndpoints(ctx, q.DeviceID, q.Limit)
	if err != nil {
		return nil, err
	}
	devs, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	names := s.deviceNames(devs)
	infra := map[string]bool{}
	if !q.IncludeInfra {
		infra = infraMACs(devs)
	}
	offline := s.offlineAfter(ctx)
	needle := strings.ToLower(strings.TrimSpace(q.Q))
	out := []EndpointView{}
	for _, e := range rows {
		if infra[e.MAC] {
			continue
		}
		v := s.endpointView(e, names, offline)
		if q.Online != nil && v.Online != *q.Online {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(strings.Join([]string{v.MAC, v.IP, v.Hostname, v.Alias, v.Vendor,
			v.DeviceName, v.SSID, v.Note}, "\x00")), needle) {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func normMAC(mac string) (string, error) {
	m := drivers.NormMAC(mac)
	if m == "" {
		return "", httpx.BadRequest("invalid_mac", "Invalid MAC address")
	}
	return m, nil
}

func endpointNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return httpx.NotFound("network client not found")
	}
	return err
}

// EndpointDetail is a client with where devices saw it.
type EndpointDetail struct {
	EndpointView
	Sightings []store.EndpointSighting `json:"sightings"`
}

// Endpoint returns a client and its sightings.
func (s *Service) Endpoint(ctx context.Context, mac string) (EndpointDetail, error) {
	m, err := normMAC(mac)
	if err != nil {
		return EndpointDetail{}, err
	}
	e, err := s.st.NetworkEndpointByMAC(ctx, m)
	if err != nil {
		return EndpointDetail{}, endpointNotFound(err)
	}
	devs, err := s.st.NetworkDevices(ctx)
	if err != nil {
		return EndpointDetail{}, err
	}
	sights, err := s.st.EndpointSightings(ctx, m)
	if err != nil {
		return EndpointDetail{}, err
	}
	return EndpointDetail{EndpointView: s.endpointView(e, s.deviceNames(devs), s.offlineAfter(ctx)), Sightings: sights}, nil
}

// UpdateEndpoint changes the alias and / or the note of a client.
func (s *Service) UpdateEndpoint(ctx context.Context, mac string, alias, note *string) (EndpointView, error) {
	m, err := normMAC(mac)
	if err != nil {
		return EndpointView{}, err
	}
	if alias != nil {
		a := strings.TrimSpace(*alias)
		if len(a) > 128 {
			return EndpointView{}, httpx.BadRequest("invalid_endpoint", "The name is up to 128 characters")
		}
		alias = &a
	}
	if note != nil {
		n := strings.TrimSpace(*note)
		if len(n) > 4000 {
			return EndpointView{}, httpx.BadRequest("invalid_endpoint", "The note is too long")
		}
		note = &n
	}
	e, err := s.st.UpdateEndpointNames(ctx, m, alias, note)
	if err != nil {
		return EndpointView{}, endpointNotFound(err)
	}
	devs, _ := s.st.NetworkDevices(ctx)
	return s.endpointView(e, s.deviceNames(devs), s.offlineAfter(ctx)), nil
}

// ForgetEndpoint removes a client and its sightings.
func (s *Service) ForgetEndpoint(ctx context.Context, mac string) error {
	m, err := normMAC(mac)
	if err != nil {
		return err
	}
	return endpointNotFound(s.st.ForgetEndpoint(ctx, m))
}

// BlockEndpoint blocks or unblocks a client on the first device that saw it
// and can block clients; it returns that device.
func (s *Service) BlockEndpoint(ctx context.Context, mac string, blocked bool) (View, ActionResult, error) {
	m, err := normMAC(mac)
	if err != nil {
		return View{}, ActionResult{}, err
	}
	sights, err := s.st.EndpointSightings(ctx, m)
	if err != nil {
		return View{}, ActionResult{}, err
	}
	for _, sg := range sights {
		d, err := s.st.NetworkDevice(ctx, sg.DeviceID)
		if err != nil {
			continue
		}
		p, err := drivers.Lookup(d.Platform)
		if err != nil || !slices.Contains(p.Capabilities(d.Transport), drivers.ActionEndpointBlock) {
			continue
		}
		res, err := s.Apply(ctx, d.ID, drivers.ActionEndpointBlock, drivers.Params{MAC: m, Blocked: &blocked})
		return s.view(d, s.snapshot()), res, err
	}
	return View{}, ActionResult{}, httpx.BadRequest("unsupported_action",
		"No device that saw this client can block it (a UniFi, Omada or Meraki controller or a Keenetic router is required)")
}

// ---------------- actions ----------------

// ActionResult is what a device answered.
type ActionResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// Apply runs an action on a device. Parameters are validated strictly; the
// flow export defaults to the collector of this installation.
func (s *Service) Apply(ctx context.Context, id int64, action string, params drivers.Params) (ActionResult, error) {
	d, err := s.st.NetworkDevice(ctx, id)
	if err != nil {
		return ActionResult{}, notFound(err)
	}
	p, err := drivers.Lookup(d.Platform)
	if err != nil {
		return ActionResult{}, invalid("Unknown platform %q", d.Platform)
	}
	if !slices.Contains(drivers.Actions, action) {
		return ActionResult{}, httpx.BadRequest("unknown_action", "Unknown action "+action)
	}
	transport := or(d.Transport, p.DefaultTransport())
	if !slices.Contains(p.Capabilities(transport), action) {
		return ActionResult{}, httpx.BadRequest("unsupported_action",
			fmt.Sprintf("%s: %s is not supported over %s", p.Title, drivers.ActionTitles[action], transport))
	}
	if action == drivers.ActionFlowExport {
		col := s.Collector(ctx)
		if params.Collector == "" {
			if col.IP == "" {
				return ActionResult{}, httpx.BadRequest("collector_unknown",
					"The address of the flow collector is not known: set it in the device settings or the public URL")
			}
			params.Collector = col.IP
		}
		if params.Port == 0 {
			params.Port = col.NetFlowPort
			if params.Protocol == "sflow" {
				params.Port = col.SFlowPort
			}
		}
	}
	params, err = drivers.ValidateAction(action, params)
	if err != nil {
		var de *drivers.Error
		if errors.As(err, &de) {
			return ActionResult{}, httpx.BadRequest("invalid_params", de.Msg)
		}
		return ActionResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	drv, _, err := s.driver(ctx, d, nil)
	if err != nil {
		return ActionResult{}, deviceErr(err)
	}
	defer drv.Close()
	var out string
	if action == drivers.ActionBackup {
		out, err = drv.Backup(ctx)
	} else {
		out, err = drv.Apply(ctx, action, params)
	}
	if key := drv.HostKey(); key != "" && d.SSHHostKey == "" {
		_ = s.st.SetDeviceHostKey(ctx, id, key)
	}
	if err != nil {
		return ActionResult{}, deviceErr(err)
	}
	if !slices.Contains(AdminActions, action) {
		s.pollLater(id, repollDelay)
	}
	return ActionResult{OK: true, Output: truncate(out, maxOutput)}, nil
}

// Backup returns the configuration of a device.
func (s *Service) Backup(ctx context.Context, id int64) (string, error) {
	r, err := s.Apply(ctx, id, drivers.ActionBackup, drivers.Params{})
	return r.Output, err
}

// ---------------- scheduler ----------------

// pollLater polls a device after delay in the background.
func (s *Service) pollLater(id int64, delay time.Duration) {
	s.repoll.Add(1)
	go func() {
		defer s.repoll.Done()
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-s.bg.Done():
			return
		case <-t.C:
		}
		if _, err := s.Poll(s.bg, id); err != nil && !errors.Is(err, context.Canceled) {
			var he *httpx.HTTPError
			if !errors.As(err, &he) {
				s.log.Warn("device poll failed", "id", id, "err", err)
			}
		}
	}()
}

// Close stops the background polls and waits for them.
func (s *Service) Close() {
	s.stop()
	s.repoll.Wait()
}

// Wait waits for the background polls (tests).
func (s *Service) Wait() { s.repoll.Wait() }

// Run polls the due devices until ctx ends. Every replica may run it: a
// PostgreSQL advisory lock lets one of them poll per tick.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick runs one round of the scheduler: due polls, the Inventory DB cache,
// the Umbrella events, the clean-up of old clients and the OUI database.
func (s *Service) Tick(ctx context.Context) {
	release, ok, err := s.st.TryLock(ctx, store.LockKey("devices-poll"))
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("device scheduler: lock not taken", "err", err)
		}
		return
	}
	if !ok {
		return
	}
	defer release()
	set, _ := s.Settings(ctx)
	devs, err := s.st.NetworkDevices(ctx)
	if err != nil {
		s.log.Warn("device scheduler: devices not read", "err", err)
		return
	}
	s.cacheInventory(ctx, devs)
	now := s.cfg.Now()
	var due []int64
	s.mu.Lock()
	for _, d := range devs {
		if !d.Enabled || s.running[d.ID] {
			continue
		}
		if d.LastPollAt == nil || now.Sub(*d.LastPollAt) >= time.Duration(d.PollSeconds)*time.Second-5*time.Second {
			due = append(due, d.ID)
		}
	}
	s.mu.Unlock()
	if len(due) > 0 {
		lim := make(chan struct{}, set.Concurrency)
		var wg sync.WaitGroup
		for _, id := range due {
			lim <- struct{}{}
			wg.Go(func() {
				defer func() { <-lim }()
				if _, err := s.Poll(ctx, id); err != nil && ctx.Err() == nil {
					var he *httpx.HTTPError
					if !errors.As(err, &he) {
						s.log.Warn("device poll failed", "id", id, "err", err)
					}
				}
			})
		}
		wg.Wait()
		if devs, err = s.st.NetworkDevices(ctx); err != nil {
			return
		}
	}
	s.reconcileEvents(ctx, devs)
	s.housekeeping(ctx, set)
}

// cacheInventory refreshes the name, site and role cached from Inventory DB.
func (s *Service) cacheInventory(ctx context.Context, devs []store.NetworkDevice) {
	snap := s.snapshot()
	if snap == nil {
		return
	}
	for i, d := range devs {
		if d.InventoryID == nil {
			continue
		}
		inv, ok := snap.Device(*d.InventoryID)
		if !ok || (inv.Name == d.Name && inv.Site == d.Site && inv.Role == d.Role) {
			continue
		}
		if err := s.st.CacheDeviceInventory(ctx, d.ID, inv.Name, inv.Site, inv.Role); err == nil {
			devs[i].Name, devs[i].Site, devs[i].Role = inv.Name, inv.Site, inv.Role
		}
	}
}

func (s *Service) housekeeping(ctx context.Context, set Settings) {
	s.mu.Lock()
	due := s.cfg.Now().Sub(s.lastPurge) >= time.Hour
	if due {
		s.lastPurge = s.cfg.Now()
	}
	s.mu.Unlock()
	if !due {
		return
	}
	before := s.cfg.Now().Add(-time.Duration(set.EndpointRetentionDays) * 24 * time.Hour)
	if err := s.st.PurgeEndpoints(ctx, before); err != nil {
		s.log.Warn("old clients not purged", "err", err)
	}
	if s.cfg.OUI != nil {
		go s.cfg.OUI.Refresh(s.bg)
	}
}

// ---------------- Umbrella events ----------------

// sinkConfigured reports whether the event sink can deliver (a Sender with
// no ingest URL would only fill its outbox).
func (s *Service) sinkConfigured() bool {
	if s.cfg.Events == nil {
		return false
	}
	if st, ok := s.cfg.Events.(interface{ Status() detector.SenderStatus }); ok {
		return st.Status().Configured
	}
	return true
}

// reconcileEvents sends a firing event for each device that went down and
// a resolved one for each device that came back (or was disabled).
func (s *Service) reconcileEvents(ctx context.Context, devs []store.NetworkDevice) {
	if !s.sinkConfigured() {
		return
	}
	type mark struct {
		id    int64
		since *time.Time
	}
	var events []detector.Event
	var marks []mark
	for _, d := range devs {
		down := d.Enabled && d.Status == "down" && d.DownSince != nil
		if d.Alerted != nil && (!down || !d.Alerted.Equal(*d.DownSince)) {
			events = append(events, s.event(ctx, d, d.Name, detector.StatusResolved))
			marks = append(marks, mark{d.ID, nil})
		}
		if down && (d.Alerted == nil || !d.Alerted.Equal(*d.DownSince)) {
			fd := d
			fd.Alerted = d.DownSince
			events = append(events, s.event(ctx, fd, d.Name, detector.StatusFiring))
			marks = append(marks, mark{d.ID, d.DownSince})
		}
	}
	if len(events) == 0 {
		return
	}
	// A failed delivery stays in the sender's outbox and is retried.
	if err := s.cfg.Events.Deliver(ctx, events); err != nil {
		s.log.Warn("device events queued for Umbrella", "events", len(events), "err", err)
	}
	for _, m := range marks {
		if err := s.st.SetDeviceAlerted(ctx, m.id, m.since); err != nil {
			s.log.Warn("device alert state not saved", "id", m.id, "err", err)
		}
	}
}

// DeviceEventID is the event id of a down episode of a device.
func DeviceEventID(id int64, since time.Time) string {
	h := sha256.Sum256([]byte(SignalDeviceDown + "\x00" + strconv.FormatInt(id, 10) + "\x00" + since.UTC().Format(time.RFC3339Nano)))
	return "flow-" + hex.EncodeToString(h[:10])
}

// event is the Umbrella event of the down episode of d that started at
// d.Alerted (else d.DownSince).
func (s *Service) event(ctx context.Context, d store.NetworkDevice, name, status string) detector.Event {
	since := s.cfg.Now()
	if d.Alerted != nil {
		since = *d.Alerted
	} else if d.DownSince != nil {
		since = *d.DownSince
	}
	var g setup.General
	_, _ = s.st.Setting(ctx, setup.SettingGeneral, &g)
	name = or(name, d.Host)
	title := "Устройство недоступно: " + name
	if g.Language == detector.LangEN {
		title = "Device is unreachable: " + name
	}
	labels := map[string]string{"source": "umbrella-flow", "device_id": strconv.FormatInt(d.ID, 10), "platform": d.Platform,
		"host": d.Host}
	if d.Site != "" {
		labels["site"] = d.Site
	}
	if d.Role != "" {
		labels["role"] = d.Role
	}
	if d.LastError != "" {
		labels["error"] = truncate(d.LastError, 300)
	}
	ev := detector.Event{ID: DeviceEventID(d.ID, since), Status: status, Signal: SignalDeviceDown, Method: "USE",
		Severity: "critical", Title: title, CI: name, SourceRef: d.SourceRef, IP: drivers.NormIP(d.Host), Labels: labels,
		StartsAt: since.UTC().Format(time.RFC3339)}
	if status == detector.StatusResolved {
		ev.EndsAt = s.cfg.Now().UTC().Format(time.RFC3339)
	}
	if base := strings.TrimRight(g.PublicURL, "/"); base != "" {
		ev.Links = &detector.Links{Flow: base + "/devices/" + strconv.FormatInt(d.ID, 10)}
	}
	return ev
}
