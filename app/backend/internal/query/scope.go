package query

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
)

// Visibility scopes (docs/integrations.md §3.2). A user whose role has the
// permission scope:umbrella sees only the flows of the CIs Beacon lets them
// see: (SrcCI IN refs OR DstCI IN refs OR SrcAddr IN ips OR DstAddr IN ips).
//
// The restriction is applied centrally: the HTTP layer puts a ScopeFunc into
// the request context and ScopedConn, which wraps the ClickHouse connection
// every read path uses (visualize, flow search, widgets, exporters, filter
// value completion, Ledger status…), replaces each flow table of a
// query with a filtered subquery. Without a ScopeFunc in the context queries
// run unchanged (administrators, roles without scope:umbrella, background
// jobs).

// Scope is the set of flows a user may see. A nil *Scope means unrestricted.
// An empty Scope (no refs, no addresses) matches nothing.
type Scope struct {
	// Refs are Ledger source_refs matched against SrcCI / DstCI.
	Refs []string
	// Prefixes are addresses (as /32 or /128) and prefixes matched against
	// SrcAddr / DstAddr.
	Prefixes []netip.Prefix
}

// NewScope builds a scope from refs and addresses or prefixes in text;
// invalid addresses are skipped, duplicates removed.
func NewScope(refs, ips []string) *Scope {
	s := &Scope{Refs: []string{}, Prefixes: []netip.Prefix{}}
	seenRef := map[string]bool{}
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r != "" && !seenRef[r] {
			seenRef[r] = true
			s.Refs = append(s.Refs, r)
		}
	}
	seenIP := map[netip.Prefix]bool{}
	for _, v := range ips {
		v = strings.TrimSpace(v)
		var p netip.Prefix
		if strings.Contains(v, "/") {
			pp, err := netip.ParsePrefix(v)
			if err != nil {
				continue
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(v)
			if err != nil {
				continue
			}
			a = a.Unmap().WithZone("")
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !seenIP[p] {
			seenIP[p] = true
			s.Prefixes = append(s.Prefixes, p)
		}
	}
	sort.Strings(s.Refs)
	sort.Slice(s.Prefixes, func(i, j int) bool { return s.Prefixes[i].String() < s.Prefixes[j].String() })
	return s
}

// Empty reports whether the scope matches nothing.
func (s *Scope) Empty() bool { return s != nil && len(s.Refs) == 0 && len(s.Prefixes) == 0 }

func chString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// v6 renders an address as a ClickHouse IPv6 literal (IPv4 as IPv4-mapped,
// as Current stores it).
func v6(a netip.Addr) string {
	if a.Is4() {
		a = netip.AddrFrom16(a.As16())
	}
	return "toIPv6('" + a.String() + "')"
}

// lastAddr returns the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for k := 0; k < 8; k++ {
			if i*8+k >= bits {
				b[i] |= 0x80 >> k
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// SQL returns the boolean condition of the scope. raw tells whether the table
// has the address columns (the raw table); on the aggregated tables, which
// have no addresses, only the CI part applies, which is stricter.
func (s *Scope) SQL(raw bool) string {
	if s == nil {
		return "1"
	}
	var parts []string
	if len(s.Refs) > 0 {
		q := make([]string, len(s.Refs))
		for i, r := range s.Refs {
			q[i] = chString(r)
		}
		list := strings.Join(q, ", ")
		parts = append(parts, "SrcCI IN ("+list+")", "DstCI IN ("+list+")")
	}
	if raw && len(s.Prefixes) > 0 {
		var exact []string
		var ranges []netip.Prefix
		for _, p := range s.Prefixes {
			if p.IsSingleIP() {
				exact = append(exact, v6(p.Addr()))
			} else {
				ranges = append(ranges, p)
			}
		}
		for _, col := range []string{"SrcAddr", "DstAddr"} {
			if len(exact) > 0 {
				parts = append(parts, col+" IN ("+strings.Join(exact, ", ")+")")
			}
			for _, p := range ranges {
				parts = append(parts, fmt.Sprintf("%s BETWEEN %s AND %s", col, v6(p.Addr()), v6(lastAddr(p))))
			}
		}
	}
	if len(parts) == 0 {
		return "0"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// ScopeFunc resolves the scope of the request (nil = unrestricted). It is
// called for every query, so it should cache.
type ScopeFunc func(ctx context.Context) (*Scope, error)

type scopeKey struct{}

// WithScopeFunc returns a context whose ClickHouse queries (through
// ScopedConn) are restricted to the scope f resolves.
func WithScopeFunc(ctx context.Context, f ScopeFunc) context.Context {
	if f == nil {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, f)
}

// WithScope returns a context restricted to s (nil = unrestricted).
func WithScope(ctx context.Context, s *Scope) context.Context {
	if s == nil {
		return ctx
	}
	return WithScopeFunc(ctx, func(context.Context) (*Scope, error) { return s, nil })
}

// Scoped reports whether the context carries a scope resolver (the caller
// is a restricted user), without resolving it.
func Scoped(ctx context.Context) bool {
	_, ok := ctx.Value(scopeKey{}).(ScopeFunc)
	return ok
}

// ScopeFrom resolves the scope of the context: nil without a resolver.
// Resolution errors are *ScopeError.
func ScopeFrom(ctx context.Context) (*Scope, error) {
	f, ok := ctx.Value(scopeKey{}).(ScopeFunc)
	if !ok {
		return nil, nil
	}
	s, err := f(ctx)
	if err != nil {
		var se *ScopeError
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, &ScopeError{Err: err}
	}
	return s, nil
}

// scopeColumns lists the columns the scope reads, so that the resolution
// choice prefers the raw table (with addresses) when the scope has some.
func scopeColumns(ctx context.Context) []string {
	s, err := ScopeFrom(ctx)
	if err != nil || s == nil || len(s.Prefixes) == 0 {
		return nil
	}
	return []string{"SrcAddr", "DstAddr"}
}

// ScopeError: the visibility scope could not be determined (Beacon is
// unreachable, not configured…). Queries fail closed with HTTP 503.
type ScopeError struct{ Err error }

func (e *ScopeError) Error() string {
	return "your visibility scope could not be loaded from Beacon, so no traffic is shown: " + e.Err.Error()
}
func (e *ScopeError) Unwrap() error     { return e.Err }
func (e *ScopeError) HTTPStatus() int   { return http.StatusServiceUnavailable }
func (e *ScopeError) ErrorCode() string { return "scope_unavailable" }

// ErrScopeWrite: a restricted context tried to write or to read flows in a
// form the scope cannot restrict.
var ErrScopeWrite = errors.New("this query cannot be restricted to the visibility scope")

// ScopedConn wraps conn so that every read in a context with a scope
// (WithScopeFunc) reads the flow tables of cfg through the scope filter, and
// fails closed when the scope cannot be resolved. Queries in contexts
// without a scope pass unchanged.
func ScopedConn(conn driver.Conn, cfg chstore.Config) driver.Conn {
	if conn == nil {
		return nil
	}
	if sc, ok := conn.(*scopedConn); ok {
		conn = sc.Conn
	}
	cfg = cfg.WithDefaults()
	tables := []string{cfg.Raw().Table}
	for _, r := range cfg.Rollups() {
		tables = append(tables, r.Table)
	}
	alt := make([]string, len(tables))
	for i, t := range tables {
		alt[i] = regexp.QuoteMeta(t)
	}
	db := regexp.QuoteMeta(cfg.Database)
	tbl := "(" + strings.Join(alt, "|") + ")"
	// `db`.`table`, db.table, `db`.table, db.`table`
	re := regexp.MustCompile("(?:`" + db + "`|\\b" + db + ")\\.(?:`" + tbl + "`|" + tbl + "\\b)")
	// A flow table without the database: FROM flows / JOIN `flows_1h`.
	bare := regexp.MustCompile("(?i)\\b(?:FROM|JOIN)\\s+`?" + tbl + "\\b`?")
	return &scopedConn{Conn: conn, cfg: cfg, re: re, bare: bare, raw: cfg.Raw().Table}
}

type scopedConn struct {
	driver.Conn
	cfg  chstore.Config
	re   *regexp.Regexp
	bare *regexp.Regexp
	raw  string
}

// maxPlainQuery: above this size the query gets a larger max_query_size
// (large scopes).
const maxPlainQuery = 200 << 10

// Restrict rewrites sql for scope s (exported for tests and other wrappers).
func (c *scopedConn) restrict(sql string, s *Scope) (string, error) {
	if s == nil {
		return sql, nil
	}
	rawCond, aggCond := s.SQL(true), s.SQL(false)
	if c.bare.MatchString(sql) {
		return "", ErrScopeWrite
	}
	out := c.re.ReplaceAllStringFunc(sql, func(m string) string {
		sub := c.re.FindStringSubmatch(m)
		t := sub[1]
		if t == "" {
			t = sub[2]
		}
		cond := aggCond
		if t == c.raw {
			cond = rawCond
		}
		return "(SELECT * FROM " + c.cfg.Table(t) + " WHERE " + cond + ")"
	})
	return out, nil
}

func (c *scopedConn) prepare(ctx context.Context, sql string) (context.Context, string, error) {
	if !Scoped(ctx) {
		return ctx, sql, nil
	}
	s, err := ScopeFrom(ctx)
	if err != nil {
		return ctx, "", err
	}
	out, err := c.restrict(sql, s)
	if err != nil {
		return ctx, "", err
	}
	if len(out) > maxPlainQuery {
		ctx = clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_query_size": 2*len(out) + 1<<20}))
	}
	return ctx, out, nil
}

func (c *scopedConn) Query(ctx context.Context, sql string, args ...any) (driver.Rows, error) {
	ctx, sql, err := c.prepare(ctx, sql)
	if err != nil {
		return nil, err
	}
	return c.Conn.Query(ctx, sql, args...)
}

func (c *scopedConn) QueryRow(ctx context.Context, sql string, args ...any) driver.Row {
	ctx, sql, err := c.prepare(ctx, sql)
	if err != nil {
		return errRow{err}
	}
	return c.Conn.QueryRow(ctx, sql, args...)
}

func (c *scopedConn) Select(ctx context.Context, dest any, sql string, args ...any) error {
	ctx, sql, err := c.prepare(ctx, sql)
	if err != nil {
		return err
	}
	return c.Conn.Select(ctx, dest, sql, args...)
}

func (c *scopedConn) QueryFormat(ctx context.Context, format, sql string, args ...any) (io.ReadCloser, error) {
	ctx, sql, err := c.prepare(ctx, sql)
	if err != nil {
		return nil, err
	}
	return c.Conn.QueryFormat(ctx, format, sql, args...)
}

// Writes are refused in a restricted context.

func (c *scopedConn) Exec(ctx context.Context, sql string, args ...any) error {
	if Scoped(ctx) {
		return ErrScopeWrite
	}
	return c.Conn.Exec(ctx, sql, args...)
}

func (c *scopedConn) PrepareBatch(ctx context.Context, sql string, opts ...driver.PrepareBatchOption) (driver.Batch, error) {
	if Scoped(ctx) {
		return nil, ErrScopeWrite
	}
	return c.Conn.PrepareBatch(ctx, sql, opts...)
}

func (c *scopedConn) InsertFormat(ctx context.Context, format, sql string, data io.Reader) error {
	if Scoped(ctx) {
		return ErrScopeWrite
	}
	return c.Conn.InsertFormat(ctx, format, sql, data)
}

func (c *scopedConn) AsyncInsert(ctx context.Context, sql string, wait bool, args ...any) error {
	if Scoped(ctx) {
		return ErrScopeWrite
	}
	return c.Conn.AsyncInsert(ctx, sql, wait, args...)
}

type errRow struct{ err error }

func (r errRow) Err() error           { return r.err }
func (r errRow) Scan(...any) error    { return r.err }
func (r errRow) ScanStruct(any) error { return r.err }
