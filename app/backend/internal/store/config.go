package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- settings (key -> JSON)

// Setting reads the JSON value of key into out; found is false when the key is absent.
func (s *Store) Setting(ctx context.Context, key string, out any) (found bool, err error) {
	var raw []byte
	err = s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, out)
}

// PutSetting stores v as the JSON value of key.
func (s *Store) PutSetting(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, key, raw)
	return err
}

// ---- saved views

type SavedView struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	OwnerID   int64           `json:"owner_id"`
	Owner     string          `json:"owner"`
	Shared    bool            `json:"shared"`
	Request   json.RawMessage `json:"request"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

const viewCols = `v.id, v.name, v.owner_id, u.username, v.shared, v.request, v.created_at, v.updated_at`

func scanView(row pgx.Row) (SavedView, error) {
	var v SavedView
	var raw []byte
	err := row.Scan(&v.ID, &v.Name, &v.OwnerID, &v.Owner, &v.Shared, &raw, &v.CreatedAt, &v.UpdatedAt)
	v.Request = raw
	return v, pgErr(err)
}

// SavedViews lists the views the user owns and the shared ones.
func (s *Store) SavedViews(ctx context.Context, userID int64) ([]SavedView, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+viewCols+` FROM saved_views v JOIN users u ON u.id = v.owner_id
		WHERE v.owner_id = $1 OR v.shared ORDER BY lower(v.name), v.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedView{}
	for rows.Next() {
		v, err := scanView(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) SavedView(ctx context.Context, id int64) (SavedView, error) {
	return scanView(s.pool.QueryRow(ctx, `SELECT `+viewCols+` FROM saved_views v JOIN users u ON u.id = v.owner_id WHERE v.id = $1`, id))
}

func (s *Store) CreateSavedView(ctx context.Context, ownerID int64, name string, shared bool, request json.RawMessage) (SavedView, error) {
	var id int64
	if err := s.pool.QueryRow(ctx, `INSERT INTO saved_views (name, owner_id, shared, request) VALUES ($1, $2, $3, $4) RETURNING id`,
		strings.TrimSpace(name), ownerID, shared, []byte(request)).Scan(&id); err != nil {
		return SavedView{}, pgErr(err)
	}
	return s.SavedView(ctx, id)
}

func (s *Store) UpdateSavedView(ctx context.Context, id int64, name string, shared bool, request json.RawMessage) (SavedView, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE saved_views SET name = $2, shared = $3, request = $4, updated_at = now() WHERE id = $1`,
		id, strings.TrimSpace(name), shared, []byte(request))
	if err != nil {
		return SavedView{}, pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return SavedView{}, ErrNotFound
	}
	return s.SavedView(ctx, id)
}

func (s *Store) DeleteSavedView(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saved_views WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- classifiers

// Classifier kinds.
const (
	ClassifierExporter  = "exporter"
	ClassifierInterface = "interface"
)

// ClassifierKinds lists the kinds in display order.
var ClassifierKinds = []string{ClassifierExporter, ClassifierInterface}

// Classifiers returns the ordered rules of every kind (every kind present, maybe empty).
func (s *Store) Classifiers(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	for _, k := range ClassifierKinds {
		out[k] = []string{}
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, rule FROM classifiers ORDER BY kind, position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, r string
		if err := rows.Scan(&k, &r); err != nil {
			return nil, err
		}
		out[k] = append(out[k], r)
	}
	return out, rows.Err()
}

// SetClassifiers replaces the rules of the given kinds in one transaction.
func (s *Store) SetClassifiers(ctx context.Context, rules map[string][]string) error {
	for k := range rules {
		if !slices.Contains(ClassifierKinds, k) {
			return fmt.Errorf("unknown classifier kind %q", k)
		}
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		for k, rs := range rules {
			if _, err := tx.Exec(ctx, `DELETE FROM classifiers WHERE kind = $1`, k); err != nil {
				return err
			}
			for i, r := range rs {
				if _, err := tx.Exec(ctx, `INSERT INTO classifiers (kind, position, rule) VALUES ($1, $2, $3)`, k, i, r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ---- Ledger connection

type SyncStats struct {
	Devices    int `json:"devices"`
	Interfaces int `json:"interfaces"`
	Prefixes   int `json:"prefixes"`
	Circuits   int `json:"circuits"`
}

type SyncResult struct {
	At    time.Time `json:"at"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	SyncStats
}

type InventoryDB struct {
	Enabled   bool
	URL       string
	TokenRef  string // openbao:// reference (or the token itself without OpenBao)
	Interval  time.Duration
	UpdatedAt time.Time
	LastSync  *SyncResult
}

func (s *Store) InventoryDB(ctx context.Context) (InventoryDB, error) {
	var c InventoryDB
	var secs int
	var at *time.Time
	var ok *bool
	var errText string
	var stats []byte
	err := s.pool.QueryRow(ctx, `SELECT enabled, url, token_ref, interval_seconds, updated_at, last_sync_at, last_sync_ok,
		last_sync_error, last_sync_stats FROM inventory_db WHERE id = 1`).
		Scan(&c.Enabled, &c.URL, &c.TokenRef, &secs, &c.UpdatedAt, &at, &ok, &errText, &stats)
	if err != nil {
		return c, pgErr(err)
	}
	c.Interval = time.Duration(secs) * time.Second
	if at != nil {
		r := &SyncResult{At: *at, Error: errText}
		if ok != nil {
			r.OK = *ok
		}
		_ = json.Unmarshal(stats, &r.SyncStats)
		c.LastSync = r
	}
	return c, nil
}

// SetInventoryDB stores the connection settings (not the last sync).
func (s *Store) SetInventoryDB(ctx context.Context, c InventoryDB) error {
	secs := int(c.Interval / time.Second)
	if secs < 60 {
		secs = 60
	}
	_, err := s.pool.Exec(ctx, `UPDATE inventory_db SET enabled = $1, url = $2, token_ref = $3, interval_seconds = $4, updated_at = now() WHERE id = 1`,
		c.Enabled, strings.TrimSpace(c.URL), c.TokenRef, secs)
	return pgErr(err)
}

// RecordInventorySync stores the result of a synchronization.
func (s *Store) RecordInventorySync(ctx context.Context, r SyncResult) error {
	stats, _ := json.Marshal(r.SyncStats)
	_, err := s.pool.Exec(ctx, `UPDATE inventory_db SET last_sync_at = $1, last_sync_ok = $2, last_sync_error = $3, last_sync_stats = $4 WHERE id = 1`,
		r.At, r.OK, r.Error, stats)
	return err
}

// ---- sampling overrides

type SamplingOverride struct {
	Exporter netip.Prefix `json:"exporter"` // a single address is a /32 or /128
	IfIndex  uint32       `json:"if_index"` // 0 = every interface
	Rate     uint64       `json:"rate"`
	Comment  string       `json:"comment"`
}

func (s *Store) SamplingOverrides(ctx context.Context) ([]SamplingOverride, error) {
	rows, err := s.pool.Query(ctx, `SELECT exporter, if_index, rate, comment FROM sampling_overrides ORDER BY exporter, if_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SamplingOverride{}
	for rows.Next() {
		var o SamplingOverride
		var ifIndex, rate int64
		if err := rows.Scan(&o.Exporter, &ifIndex, &rate, &o.Comment); err != nil {
			return nil, err
		}
		o.IfIndex, o.Rate = uint32(ifIndex), uint64(rate)
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetSamplingOverrides replaces all overrides.
func (s *Store) SetSamplingOverrides(ctx context.Context, in []SamplingOverride) error {
	return pgErr(s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sampling_overrides`); err != nil {
			return err
		}
		for _, o := range in {
			if _, err := tx.Exec(ctx, `INSERT INTO sampling_overrides (exporter, if_index, rate, comment) VALUES ($1, $2, $3, $4)`,
				o.Exporter.Masked(), int64(o.IfIndex), int64(o.Rate), o.Comment); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ---- audit log

type AuditEntry struct {
	ID     int64           `json:"id"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Target string          `json:"target,omitempty"`
	Remote string          `json:"remote,omitempty"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

// Audit appends an entry; detail is marshalled to JSON (nil = {}).
func (s *Store) Audit(ctx context.Context, actor, action, target, remote string, detail any) error {
	raw := []byte("{}")
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		raw = b
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (actor, action, target, remote, detail) VALUES ($1, $2, $3, $4, $5)`,
		actor, action, target, remote, raw)
	return err
}

// AuditLog returns up to limit entries older than beforeID (0 = newest), newest first.
func (s *Store) AuditLog(ctx context.Context, limit int, beforeID int64) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, actor, action, target, remote, detail FROM audit_log
		WHERE $1 = 0 OR id < $1 ORDER BY id DESC LIMIT $2`, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var raw []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Remote, &raw); err != nil {
			return nil, err
		}
		e.Detail = raw
		out = append(out, e)
	}
	return out, rows.Err()
}
