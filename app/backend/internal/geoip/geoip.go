// Package geoip looks up country, city and AS of addresses in MMDB files:
// MaxMind GeoLite2 / GeoIP2 Country, City and ASN, and IPinfo Lite
// (country_code, asn "AS123", as_name). Files are reloaded when they change.
package geoip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info is the result of a lookup; empty fields are unknown.
type Info struct {
	Country string `json:"country"` // ISO 3166-1 alpha-2
	City    string `json:"city"`
	ASN     uint32 `json:"asn"`
	ASName  string `json:"as_name"`
}

// Config of the GeoIP databases.
type Config struct {
	// Databases are MMDB files, e.g. GeoLite2-City.mmdb and
	// GeoLite2-ASN.mmdb, or one IPinfo Lite file. For each field the first
	// database with a value wins.
	Databases []string
	// CheckInterval between modification checks for hot reload (default
	// 1 min; negative disables).
	CheckInterval time.Duration
	Logger        *slog.Logger
}

type schema int

const (
	schemaMaxMind schema = iota
	schemaIPinfo
)

type mmRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	City struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	ASN   uint32 `maxminddb:"autonomous_system_number"`
	ASOrg string `maxminddb:"autonomous_system_organization"`
}

type ipinfoRecord struct {
	CountryCode string `maxminddb:"country_code"`
	City        string `maxminddb:"city"`
	ASN         string `maxminddb:"asn"`
	ASName      string `maxminddb:"as_name"`
	// Some IPinfo ASN databases use "name".
	Name string `maxminddb:"name"`
}

type file struct {
	path   string
	reader *maxminddb.Reader
	schema schema
	mtime  time.Time
	size   int64
	dbType string

	// Decoded records by data offset: many networks share a record, and
	// decoding dominates the lookup cost.
	cache  sync.Map // uintptr -> Info
	cached atomic.Int64
}

const maxCachedRecords = 500_000

func openFile(path string) (*file, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Read into memory instead of mmap: a replaced reader is then simply
	// garbage-collected, without racing in-flight lookups on Close.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("geoip: %s: %w", path, err)
	}
	f := &file{path: path, reader: r, mtime: st.ModTime(), size: st.Size(), dbType: r.Metadata.DatabaseType}
	t := strings.ToLower(f.dbType)
	switch {
	case strings.Contains(t, "geoip") || strings.Contains(t, "geolite") || strings.Contains(t, "dbip") || strings.Contains(t, "db-ip"):
		f.schema = schemaMaxMind
	case strings.Contains(t, "ipinfo"):
		f.schema = schemaIPinfo
	default:
		f.schema = detectSchema(r)
	}
	return f, nil
}

// detectSchema probes a well-known address when the database type is not
// recognised.
func detectSchema(r *maxminddb.Reader) schema {
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"} {
		res := r.Lookup(netip.MustParseAddr(a))
		if !res.Found() {
			continue
		}
		var m map[string]any
		if res.Decode(&m) == nil {
			if _, ok := m["country_code"]; ok {
				return schemaIPinfo
			}
			if _, ok := m["as_name"]; ok {
				return schemaIPinfo
			}
			return schemaMaxMind
		}
	}
	return schemaMaxMind
}

// ParseASN parses "AS123", "as123" or "123".
func ParseASN(s string) uint32 {
	s = strings.TrimSpace(s)
	if len(s) > 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func (f *file) lookup(a netip.Addr, info *Info) {
	res := f.reader.Lookup(a)
	if !res.Found() {
		return
	}
	off := res.Offset()
	if v, ok := f.cache.Load(off); ok {
		merge(info, v.(Info))
		return
	}
	var got Info
	f.decode(res, &got)
	if f.cached.Load() < maxCachedRecords {
		if _, loaded := f.cache.LoadOrStore(off, got); !loaded {
			f.cached.Add(1)
		}
	}
	merge(info, got)
}

func merge(dst *Info, src Info) {
	if dst.Country == "" {
		dst.Country = src.Country
	}
	if dst.City == "" {
		dst.City = src.City
	}
	if dst.ASN == 0 && src.ASN != 0 {
		dst.ASN, dst.ASName = src.ASN, src.ASName
	}
}

func (f *file) decode(res maxminddb.Result, info *Info) {
	switch f.schema {
	case schemaMaxMind:
		var r mmRecord
		if res.Decode(&r) != nil {
			return
		}
		if info.Country == "" {
			info.Country = r.Country.ISOCode
			if info.Country == "" {
				info.Country = r.RegisteredCountry.ISOCode
			}
		}
		if info.City == "" {
			info.City = r.City.Names.EN
		}
		if info.ASN == 0 && r.ASN != 0 {
			info.ASN, info.ASName = r.ASN, r.ASOrg
		}
	case schemaIPinfo:
		var r ipinfoRecord
		if res.Decode(&r) != nil {
			return
		}
		if info.Country == "" {
			info.Country = strings.ToUpper(r.CountryCode)
		}
		if info.City == "" {
			info.City = r.City
		}
		if info.ASN == 0 {
			if n := ParseASN(r.ASN); n != 0 {
				info.ASN = n
				info.ASName = r.ASName
				if info.ASName == "" {
					info.ASName = r.Name
				}
			}
		}
	}
}

// DB is a set of MMDB files with hot reload. Lookups are lock-free.
type DB struct {
	cfg   Config
	log   *slog.Logger
	files atomic.Pointer[[]*file]
	mu    sync.Mutex
}

// Open loads every database. A database that fails to load is an error.
func Open(cfg Config) (*DB, error) {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	d := &DB{cfg: cfg, log: cfg.Logger}
	var fs []*file
	for _, p := range cfg.Databases {
		if strings.TrimSpace(p) == "" {
			continue
		}
		f, err := openFile(p)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}
	d.files.Store(&fs)
	return d, nil
}

// Lookup returns what the databases know about addr.
func (d *DB) Lookup(addr netip.Addr) Info {
	var info Info
	if d == nil || !addr.IsValid() {
		return info
	}
	addr = addr.Unmap()
	for _, f := range *d.files.Load() {
		f.lookup(addr, &info)
		if info.Country != "" && info.City != "" && info.ASN != 0 {
			break
		}
	}
	return info
}

// Databases describes the loaded files (for the settings page).
func (d *DB) Databases() []DatabaseInfo {
	var out []DatabaseInfo
	for _, f := range *d.files.Load() {
		out = append(out, DatabaseInfo{Path: f.path, Type: f.dbType, Modified: f.mtime,
			Built: f.reader.Metadata.BuildTime()})
	}
	return out
}

// DatabaseInfo describes a loaded file.
type DatabaseInfo struct {
	Path     string    `json:"path"`
	Type     string    `json:"type"`
	Modified time.Time `json:"modified"`
	Built    time.Time `json:"built"`
}

// Reload re-opens files whose size or modification time changed. A file
// that fails to load keeps its previous version.
func (d *DB) Reload() (changed bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := *d.files.Load()
	next := make([]*file, len(old))
	var errs []error
	for i, f := range old {
		next[i] = f
		st, serr := os.Stat(f.path)
		if serr != nil {
			errs = append(errs, serr)
			continue
		}
		if st.ModTime().Equal(f.mtime) && st.Size() == f.size {
			continue
		}
		nf, oerr := openFile(f.path)
		if oerr != nil {
			errs = append(errs, oerr)
			continue
		}
		next[i] = nf
		changed = true
		d.log.Info("geoip database reloaded", "path", f.path, "type", nf.dbType)
	}
	if changed {
		d.files.Store(&next)
	}
	return changed, errors.Join(errs...)
}

// Run checks the files for changes every CheckInterval until ctx is done.
func (d *DB) Run(ctx context.Context) {
	if d.cfg.CheckInterval < 0 {
		return
	}
	t := time.NewTicker(d.cfg.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := d.Reload(); err != nil {
				d.log.Warn("geoip reload failed", "error", err)
			}
		}
	}
}
