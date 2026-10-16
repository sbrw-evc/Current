package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Tables of migration 00008: managed network devices, where they saw
// clients, and the clients merged by MAC (internal/devices).

// NetworkDevice is a managed device: management data and live state.
type NetworkDevice struct {
	ID             int64             `json:"id"`
	Platform       string            `json:"platform"`
	Host           string            `json:"host"`
	Port           *int              `json:"port"`
	Transport      string            `json:"transport"`
	VerifyTLS      bool              `json:"verify_tls"`
	ControllerSite string            `json:"controller_site"`
	InventoryID    *int              `json:"inventory_id"`
	SourceRef      string            `json:"source_ref"`
	Name           string            `json:"name"`
	Site           string            `json:"site"`
	Role           string            `json:"role"`
	Tags           []string          `json:"tags"`
	Note           string            `json:"note"`
	Enabled        bool              `json:"enabled"`
	PollSeconds    int               `json:"poll_seconds"`
	FlowExporterIP string            `json:"flow_exporter_ip"`
	Credentials    map[string]string `json:"credentials"` // non-secret fields
	Secrets        []string          `json:"secrets"`     // secret fields set in OpenBao
	SSHHostKey     string            `json:"ssh_host_key"`

	Status     string          `json:"status"`
	Failures   int             `json:"failures"`
	LastPollAt *time.Time      `json:"last_poll_at"`
	LastOKAt   *time.Time      `json:"last_ok_at"`
	LastError  string          `json:"last_error"`
	DownSince  *time.Time      `json:"down_since"`
	Alerted    *time.Time      `json:"alerted_since"`
	Facts      json.RawMessage `json:"facts"`
	Interfaces json.RawMessage `json:"interfaces"`
	Neighbors  json.RawMessage `json:"neighbors"`
	Children   json.RawMessage `json:"children"`
	MapX       *float64        `json:"map_x"`
	MapY       *float64        `json:"map_y"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

const deviceCols = `id, platform, host, port, transport, verify_tls, controller_site, inventory_id, source_ref, name, site, role,
	tags, note, enabled, poll_seconds, flow_exporter_ip, credentials, secrets, ssh_host_key, status, failures, last_poll_at,
	last_ok_at, last_error, down_since, alerted_since, facts, interfaces, neighbors, children, map_x, map_y, created_by, created_at,
	updated_at`

func scanDevice(row pgx.Row) (NetworkDevice, error) {
	var d NetworkDevice
	var creds []byte
	err := row.Scan(&d.ID, &d.Platform, &d.Host, &d.Port, &d.Transport, &d.VerifyTLS, &d.ControllerSite, &d.InventoryID,
		&d.SourceRef, &d.Name, &d.Site, &d.Role, &d.Tags, &d.Note, &d.Enabled, &d.PollSeconds, &d.FlowExporterIP, &creds,
		&d.Secrets, &d.SSHHostKey, &d.Status, &d.Failures, &d.LastPollAt, &d.LastOKAt, &d.LastError, &d.DownSince, &d.Alerted,
		&d.Facts, &d.Interfaces, &d.Neighbors, &d.Children, &d.MapX, &d.MapY, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return d, pgErr(err)
	}
	d.Credentials = map[string]string{}
	_ = json.Unmarshal(creds, &d.Credentials)
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.Secrets == nil {
		d.Secrets = []string{}
	}
	return d, nil
}

// NetworkDevices lists the managed devices by name.
func (s *Store) NetworkDevices(ctx context.Context) ([]NetworkDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM network_devices ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NetworkDevice{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// NetworkDevice returns one device.
func (s *Store) NetworkDevice(ctx context.Context, id int64) (NetworkDevice, error) {
	return scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM network_devices WHERE id = $1`, id))
}

func credsJSON(m map[string]string) []byte {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return b
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// CreateNetworkDevice inserts the management fields of d and returns the device.
func (s *Store) CreateNetworkDevice(ctx context.Context, d NetworkDevice) (NetworkDevice, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO network_devices (platform, host, port, transport, verify_tls, controller_site,
		inventory_id, source_ref, name, site, role, tags, note, enabled, poll_seconds, flow_exporter_ip, credentials, secrets,
		created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) RETURNING id`,
		d.Platform, d.Host, d.Port, d.Transport, d.VerifyTLS, d.ControllerSite, d.InventoryID, d.SourceRef, d.Name, d.Site, d.Role,
		nonNil(d.Tags), d.Note, d.Enabled, d.PollSeconds, d.FlowExporterIP, credsJSON(d.Credentials), nonNil(d.Secrets),
		d.CreatedBy).Scan(&id)
	if err != nil {
		return NetworkDevice{}, pgErr(err)
	}
	return s.NetworkDevice(ctx, id)
}

// UpdateNetworkDevice writes the management fields of d (not the live state).
func (s *Store) UpdateNetworkDevice(ctx context.Context, d NetworkDevice) (NetworkDevice, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE network_devices SET platform = $2, host = $3, port = $4, transport = $5, verify_tls = $6,
		controller_site = $7, inventory_id = $8, source_ref = $9, name = $10, site = $11, role = $12, tags = $13, note = $14,
		enabled = $15, poll_seconds = $16, flow_exporter_ip = $17, credentials = $18, secrets = $19, ssh_host_key = $20,
		updated_at = now() WHERE id = $1`,
		d.ID, d.Platform, d.Host, d.Port, d.Transport, d.VerifyTLS, d.ControllerSite, d.InventoryID, d.SourceRef, d.Name, d.Site,
		d.Role, nonNil(d.Tags), d.Note, d.Enabled, d.PollSeconds, d.FlowExporterIP, credsJSON(d.Credentials), nonNil(d.Secrets),
		d.SSHHostKey)
	if err != nil {
		return NetworkDevice{}, pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return NetworkDevice{}, ErrNotFound
	}
	return s.NetworkDevice(ctx, d.ID)
}

// DeleteNetworkDevice removes a device with its sightings.
func (s *Store) DeleteNetworkDevice(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM network_devices WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return pgErr(err)
}

// SetDeviceHostKey replaces the pinned SSH host key ("" = trust the next one).
func (s *Store) SetDeviceHostKey(ctx context.Context, id int64, key string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE network_devices SET ssh_host_key = $2, updated_at = now() WHERE id = $1`, id, key)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DevicePoll is the outcome of one poll.
type DevicePoll struct {
	At         time.Time
	OK         bool
	Error      string // failed poll
	HostKey    string // learned SSH key, kept when none is pinned
	Name       string // the device's own name: set when the record has none
	Facts      json.RawMessage
	Interfaces json.RawMessage
	Neighbors  json.RawMessage
	Children   json.RawMessage
}

// DownAfter is the number of failed polls in a row that make a device down.
const DownAfter = 2

// SaveDevicePoll records a poll and returns the new status and failures.
// A success clears the failures; DownAfter failures in a row make the
// device down (down_since is the first of them that crossed the line).
func (s *Store) SaveDevicePoll(ctx context.Context, id int64, p DevicePoll) (status string, failures int, err error) {
	if p.OK {
		err = s.pool.QueryRow(ctx, `UPDATE network_devices SET status = 'up', failures = 0, last_error = '', last_poll_at = $2,
			last_ok_at = $2, down_since = NULL, facts = $3, interfaces = $4, neighbors = $5, children = $6,
			ssh_host_key = CASE WHEN ssh_host_key = '' THEN $7 ELSE ssh_host_key END,
			name = CASE WHEN name = '' OR name = host THEN coalesce(nullif($8, ''), name) ELSE name END
			WHERE id = $1 RETURNING status, failures`,
			id, p.At, jsonOr(p.Facts, "{}"), jsonOr(p.Interfaces, "[]"), jsonOr(p.Neighbors, "[]"), jsonOr(p.Children, "[]"),
			p.HostKey, p.Name).Scan(&status, &failures)
		return status, failures, pgErr(err)
	}
	msg := p.Error
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	err = s.pool.QueryRow(ctx, `UPDATE network_devices SET failures = failures + 1,
		status = CASE WHEN failures + 1 >= $4 THEN 'down' ELSE 'error' END,
		down_since = CASE WHEN failures + 1 >= $4 THEN coalesce(down_since, $2) ELSE down_since END,
		last_error = $3, last_poll_at = $2 WHERE id = $1 RETURNING status, failures`, id, p.At, msg, DownAfter).Scan(&status, &failures)
	return status, failures, pgErr(err)
}

func jsonOr(v json.RawMessage, def string) []byte {
	if len(v) == 0 {
		return []byte(def)
	}
	return v
}

// SetDeviceAlerted records that the firing event of the down episode that
// started at since went to Umbrella (nil: its resolved event went).
func (s *Store) SetDeviceAlerted(ctx context.Context, id int64, since *time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET alerted_since = $2 WHERE id = $1`, id, since)
	return err
}

// CacheDeviceInventory refreshes the name, site and role cached from Inventory DB.
func (s *Store) CacheDeviceInventory(ctx context.Context, id int64, name, site, role string) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_devices SET name = $2, site = $3, role = $4
		WHERE id = $1 AND (name, site, role) IS DISTINCT FROM ($2, $3, $4)`, id, name, site, role)
	return err
}

// SetDevicePositions stores the map positions of devices (nil = automatic).
func (s *Store) SetDevicePositions(ctx context.Context, pos map[int64]*[2]float64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		for id, xy := range pos {
			var x, y *float64
			if xy != nil {
				x, y = &xy[0], &xy[1]
			}
			if _, err := tx.Exec(ctx, `UPDATE network_devices SET map_x = $2, map_y = $3 WHERE id = $1`, id, x, y); err != nil {
				return err
			}
		}
		return nil
	})
}

// EndpointSighting is where a device saw a MAC.
type EndpointSighting struct {
	MAC        string    `json:"mac"`
	DeviceID   int64     `json:"device_id"`
	Source     string    `json:"source"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	Interface  string    `json:"interface"`
	SSID       string    `json:"ssid"`
	Signal     *int      `json:"signal"`
	VLAN       *int      `json:"vlan"`
	AttachedTo string    `json:"attached_to"`
	Port       string    `json:"port"`
	Blocked    bool      `json:"blocked"`
	SeenAt     time.Time `json:"seen_at"`
}

const sightingCols = `mac, device_id, source, ip, hostname, interface, ssid, signal, vlan, attached_to, port, blocked, seen_at`

// ReplaceSightings replaces what a device saw with rows.
func (s *Store) ReplaceSightings(ctx context.Context, deviceID int64, rows []EndpointSighting) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_endpoint_sightings WHERE device_id = $1`, deviceID); err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"device_endpoint_sightings"}, strings.Split(strings.ReplaceAll(sightingCols, " ", ""), ","),
			pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
				r := rows[i]
				return []any{r.MAC, deviceID, r.Source, r.IP, r.Hostname, r.Interface, r.SSID, r.Signal, r.VLAN, r.AttachedTo,
					r.Port, r.Blocked, r.SeenAt}, nil
			}))
		return err
	})
}

func scanSightings(rows pgx.Rows) ([]EndpointSighting, error) {
	defer rows.Close()
	out := []EndpointSighting{}
	for rows.Next() {
		var r EndpointSighting
		if err := rows.Scan(&r.MAC, &r.DeviceID, &r.Source, &r.IP, &r.Hostname, &r.Interface, &r.SSID, &r.Signal, &r.VLAN,
			&r.AttachedTo, &r.Port, &r.Blocked, &r.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Sightings returns the sightings of the MACs seen since.
func (s *Store) Sightings(ctx context.Context, macs []string, since time.Time) ([]EndpointSighting, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sightingCols+` FROM device_endpoint_sightings WHERE mac = ANY($1) AND seen_at >= $2
		ORDER BY mac, seen_at DESC`, macs, since)
	if err != nil {
		return nil, err
	}
	return scanSightings(rows)
}

// NetworkEndpoint is a client merged from its sightings.
type NetworkEndpoint struct {
	MAC        string    `json:"mac"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	Alias      string    `json:"alias"`
	Note       string    `json:"note"`
	Vendor     string    `json:"vendor"`
	DeviceID   *int64    `json:"device_id"`
	Interface  string    `json:"interface"`
	Source     string    `json:"source"`
	AttachedTo string    `json:"attached_to"`
	Port       string    `json:"port"`
	SSID       string    `json:"ssid"`
	Signal     *int      `json:"signal"`
	VLAN       *int      `json:"vlan"`
	Blocked    bool      `json:"blocked"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

const endpointCols = `mac, ip, hostname, alias, note, vendor, device_id, interface, source, attached_to, port, ssid, signal, vlan,
	blocked, first_seen, last_seen`

func scanEndpoint(row pgx.Row) (NetworkEndpoint, error) {
	var e NetworkEndpoint
	err := row.Scan(&e.MAC, &e.IP, &e.Hostname, &e.Alias, &e.Note, &e.Vendor, &e.DeviceID, &e.Interface, &e.Source, &e.AttachedTo,
		&e.Port, &e.SSID, &e.Signal, &e.VLAN, &e.Blocked, &e.FirstSeen, &e.LastSeen)
	return e, pgErr(err)
}

func scanEndpoints(rows pgx.Rows) ([]NetworkEndpoint, error) {
	defer rows.Close()
	out := []NetworkEndpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// NetworkEndpoints lists clients, newest first; deviceID 0 = all.
func (s *Store) NetworkEndpoints(ctx context.Context, deviceID int64, limit int) ([]NetworkEndpoint, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	rows, err := s.pool.Query(ctx, `SELECT `+endpointCols+` FROM network_endpoints WHERE ($1 = 0 OR device_id = $1)
		ORDER BY last_seen DESC, mac LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	return scanEndpoints(rows)
}

// EndpointsByMAC returns the stored clients of the MACs.
func (s *Store) EndpointsByMAC(ctx context.Context, macs []string) ([]NetworkEndpoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+endpointCols+` FROM network_endpoints WHERE mac = ANY($1)`, macs)
	if err != nil {
		return nil, err
	}
	return scanEndpoints(rows)
}

// NetworkEndpointByMAC returns one client.
func (s *Store) NetworkEndpointByMAC(ctx context.Context, mac string) (NetworkEndpoint, error) {
	return scanEndpoint(s.pool.QueryRow(ctx, `SELECT `+endpointCols+` FROM network_endpoints WHERE mac = $1`, mac))
}

// UpsertEndpoints writes merged clients (alias and note are kept).
func (s *Store) UpsertEndpoints(ctx context.Context, eps []NetworkEndpoint) error {
	if len(eps) == 0 {
		return nil
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, e := range eps {
			b.Queue(`INSERT INTO network_endpoints (mac, ip, hostname, vendor, device_id, interface, source, attached_to, port, ssid,
				signal, vlan, blocked, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
				ON CONFLICT (mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname,
				vendor = CASE WHEN excluded.vendor <> '' THEN excluded.vendor ELSE network_endpoints.vendor END,
				device_id = excluded.device_id, interface = excluded.interface, source = excluded.source,
				attached_to = excluded.attached_to, port = excluded.port, ssid = excluded.ssid, signal = excluded.signal,
				vlan = excluded.vlan, blocked = excluded.blocked, last_seen = excluded.last_seen`,
				e.MAC, e.IP, e.Hostname, e.Vendor, e.DeviceID, e.Interface, e.Source, e.AttachedTo, e.Port, e.SSID, e.Signal, e.VLAN,
				e.Blocked, e.FirstSeen, e.LastSeen)
		}
		return tx.SendBatch(ctx, b).Close()
	})
}

// UpdateEndpointNames changes the alias and / or the note of a client.
func (s *Store) UpdateEndpointNames(ctx context.Context, mac string, alias, note *string) (NetworkEndpoint, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE network_endpoints SET alias = coalesce($2, alias), note = coalesce($3, note) WHERE mac = $1`,
		mac, alias, note)
	if err != nil {
		return NetworkEndpoint{}, err
	}
	if tag.RowsAffected() == 0 {
		return NetworkEndpoint{}, ErrNotFound
	}
	return s.NetworkEndpointByMAC(ctx, mac)
}

// ForgetEndpoint removes a client and its sightings.
func (s *Store) ForgetEndpoint(ctx context.Context, mac string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_endpoint_sightings WHERE mac = $1`, mac); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM network_endpoints WHERE mac = $1`, mac)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// EndpointSightings returns where devices saw a MAC.
func (s *Store) EndpointSightings(ctx context.Context, mac string) ([]EndpointSighting, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sightingCols+` FROM device_endpoint_sightings WHERE mac = $1 ORDER BY seen_at DESC`, mac)
	if err != nil {
		return nil, err
	}
	return scanSightings(rows)
}

// PurgeEndpoints removes unnamed clients and sightings older than before.
func (s *Store) PurgeEndpoints(ctx context.Context, before time.Time) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM network_endpoints WHERE last_seen < $1 AND alias = '' AND note = ''`, before); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM device_endpoint_sightings WHERE seen_at < $1`, before)
		return err
	})
}
