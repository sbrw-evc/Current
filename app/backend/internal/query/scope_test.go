package query_test

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/network/app/backend/internal/query"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

// recConn records the queries and answers with no rows.
type recConn struct {
	driver.Conn // nil: unexpected methods panic
	mu          sync.Mutex
	sqls        []string
	execs       int
}

func (c *recConn) rec(sql string) {
	c.mu.Lock()
	c.sqls = append(c.sqls, sql)
	c.mu.Unlock()
}

func (c *recConn) Query(_ context.Context, sql string, _ ...any) (driver.Rows, error) {
	c.rec(sql)
	return emptyRows{}, nil
}

func (c *recConn) QueryRow(_ context.Context, sql string, _ ...any) driver.Row {
	c.rec(sql)
	return okRow{}
}

func (c *recConn) Select(_ context.Context, _ any, sql string, _ ...any) error {
	c.rec(sql)
	return nil
}

func (c *recConn) Exec(context.Context, string, ...any) error { c.execs++; return nil }

func (c *recConn) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.sqls
	c.sqls = nil
	return out
}

type emptyRows struct{}

func (emptyRows) Next() bool                       { return false }
func (emptyRows) Scan(...any) error                { return nil }
func (emptyRows) ScanStruct(any) error             { return nil }
func (emptyRows) ColumnTypes() []driver.ColumnType { return nil }
func (emptyRows) Totals(...any) error              { return nil }
func (emptyRows) Columns() []string                { return nil }
func (emptyRows) Close() error                     { return nil }
func (emptyRows) Err() error                       { return nil }
func (emptyRows) HasData() bool                    { return false }

type okRow struct{}

func (okRow) Err() error           { return nil }
func (okRow) Scan(...any) error    { return nil }
func (okRow) ScanStruct(any) error { return nil }

func TestNewScopeAndSQL(t *testing.T) {
	s := query.NewScope([]string{"inventory-db:dcim.device:100", " ", "inventory-db:dcim.device:100", "it's"},
		[]string{"10.0.0.5", "::ffff:10.0.0.6", "10.1.0.0/16", "2001:db8::/64", "bad"})
	if len(s.Refs) != 2 || len(s.Prefixes) != 4 {
		t.Fatalf("%+v", s)
	}
	raw := s.SQL(true)
	for _, want := range []string{
		`SrcCI IN ('inventory-db:dcim.device:100', 'it\'s')`,
		`DstCI IN (`,
		`SrcAddr IN (toIPv6('::ffff:10.0.0.5'), toIPv6('::ffff:10.0.0.6'))`,
		`DstAddr IN (`,
		`SrcAddr BETWEEN toIPv6('::ffff:10.1.0.0') AND toIPv6('::ffff:10.1.255.255')`,
		`DstAddr BETWEEN toIPv6('2001:db8::') AND toIPv6('2001:db8::ffff:ffff:ffff:ffff')`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("raw scope SQL lacks %q:\n%s", want, raw)
		}
	}
	if agg := s.SQL(false); strings.Contains(agg, "Addr") || !strings.Contains(agg, "SrcCI IN") {
		t.Errorf("aggregate scope SQL: %s", agg)
	}
	if got := query.NewScope(nil, nil).SQL(true); got != "0" {
		t.Errorf("empty scope = %q, want 0", got)
	}
	if got := query.NewScope(nil, []string{"10.0.0.1"}).SQL(false); got != "0" {
		t.Errorf("address-only scope on aggregates = %q, want 0", got)
	}
	var nilScope *query.Scope
	if nilScope.SQL(true) != "1" {
		t.Error("nil scope must be unrestricted")
	}
}

var flowTable = regexp.MustCompile("`(\\w+)`\\.`(flows(?:_1m|_5m|_1h)?)`")

// checkScoped asserts that every flow table of every query is read through
// the scope filter.
func checkScoped(t *testing.T, path string, sqls []string, db string) {
	t.Helper()
	if len(sqls) == 0 {
		t.Errorf("%s: no query ran", path)
		return
	}
	for _, sql := range sqls {
		locs := flowTable.FindAllStringSubmatchIndex(sql, -1)
		if len(locs) == 0 {
			t.Errorf("%s: query reads no flow table:\n%s", path, sql)
		}
		for _, l := range locs {
			if sql[l[2]:l[3]] != db {
				continue
			}
			before := sql[:l[0]]
			after := sql[l[1]:]
			if !strings.HasSuffix(before, "(SELECT * FROM ") || !strings.HasPrefix(after, " WHERE (SrcCI IN ('inventory-db:dcim.device:100')") {
				t.Errorf("%s: table %s not restricted:\n%s", path, sql[l[0]:l[1]], sql)
			}
			if sql[l[4]:l[5]] == "flows" && !strings.Contains(after[:min(len(after), 400)], "SrcAddr IN (toIPv6('::ffff:10.0.0.5'))") {
				t.Errorf("%s: raw table without the address part:\n%s", path, sql)
			}
		}
	}
}

// TestScopeEveryPath runs every Querier entry point used by the API with a
// scoped context and checks that each query is restricted, and that the
// same calls without a scope run unchanged.
func TestScopeEveryPath(t *testing.T) {
	rec := &recConn{}
	cfg := chstore.Config{Database: "flowdb"}
	conn := query.ScopedConn(rec, cfg)
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	q := query.New(conn, query.Config{Storage: cfg, Now: func() time.Time { return now }})
	scope := query.NewScope([]string{"inventory-db:dcim.device:100"}, []string{"10.0.0.5"})
	scoped := query.WithScope(context.Background(), scope)

	start := now.Add(-time.Hour)
	paths := map[string]func(ctx context.Context) error{
		"visualize stacked": func(ctx context.Context) error {
			_, err := q.Visualize(ctx, query.VisualizeRequest{Start: start, End: now, Dimensions: []string{"SrcAS"}})
			return err
		},
		"visualize long range (aggregates)": func(ctx context.Context) error {
			_, err := q.Visualize(ctx, query.VisualizeRequest{Start: now.Add(-25 * 24 * time.Hour), End: now, Dimensions: []string{"SrcAS"}})
			return err
		},
		"visualize bidirectional": func(ctx context.Context) error {
			_, err := q.Visualize(ctx, query.VisualizeRequest{Start: start, End: now, Dimensions: []string{"SrcAS"}, Bidirectional: true})
			return err
		},
		"visualize sankey": func(ctx context.Context) error {
			_, err := q.Visualize(ctx, query.VisualizeRequest{Start: start, End: now, Dimensions: []string{"SrcAS", "DstAS"}, Graph: query.GraphSankey})
			return err
		},
		"flows search": func(ctx context.Context) error {
			_, err := q.SearchFlows(ctx, query.FlowsSearchRequest{Start: start, End: now, Filter: "Proto = tcp"})
			return err
		},
		"widget summary": func(ctx context.Context) error { _, err := q.WidgetSummary(ctx); return err },
		"widget top":     func(ctx context.Context) error { _, err := q.WidgetTop(ctx, "src-as", 0); return err },
		"widget graph":   func(ctx context.Context) error { _, err := q.WidgetGraph(ctx, 0); return err },
		"last flow":      func(ctx context.Context) error { _, err := q.LastFlow(ctx); return err },
		"exporters":      func(ctx context.Context) error { _, err := q.Exporters(ctx, 0); return err },
		"inventory-db status": func(ctx context.Context) error {
			_, err := q.ObjectTraffic(ctx, query.ObjectTrafficRequest{Type: query.ObjectDevice,
				Targets: []query.ObjectTarget{{ID: "1", Ref: "inventory-db:dcim.device:1"}}})
			return err
		},
		"inventory-db prefix addresses": func(ctx context.Context) error {
			_, err := q.PrefixAddresses(ctx, netip.MustParsePrefix("10.0.0.0/24"), "", 0)
			return err
		},
	}
	for name, run := range paths {
		if err := run(scoped); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		checkScoped(t, name, rec.take(), "flowdb")
		if err := run(context.Background()); err != nil {
			t.Errorf("%s unscoped: %v", name, err)
		}
		for _, sql := range rec.take() {
			if strings.Contains(sql, "SELECT * FROM `flowdb`") {
				t.Errorf("%s: unscoped query was rewritten:\n%s", name, sql)
			}
		}
	}

	// A scope with addresses forces the raw table where it still covers the range.
	if _, err := q.Visualize(scoped, query.VisualizeRequest{Start: now.Add(-3 * 24 * time.Hour), End: now, Points: 50}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range rec.take() {
		if !strings.Contains(sql, "`flowdb`.`flows` WHERE") {
			t.Errorf("address scope should read the raw table:\n%s", sql)
		}
	}
}

func TestScopedConnFailsClosed(t *testing.T) {
	rec := &recConn{}
	conn := query.ScopedConn(rec, chstore.Config{})
	boom := errors.New("connection refused")
	ctx := query.WithScopeFunc(context.Background(), func(context.Context) (*query.Scope, error) { return nil, boom })
	_, err := conn.Query(ctx, "SELECT 1 FROM `flow`.`flows`")
	var se *query.ScopeError
	if !errors.As(err, &se) || !errors.Is(err, boom) || se.HTTPStatus() != 503 || se.ErrorCode() != "scope_unavailable" {
		t.Fatalf("err = %v", err)
	}
	if err := conn.QueryRow(ctx, "SELECT count() FROM flow.flows_1h").Err(); !errors.As(err, &se) {
		t.Fatalf("QueryRow err = %v", err)
	}
	if len(rec.take()) != 0 {
		t.Fatal("a query ran without its scope")
	}

	// Bare table names cannot be restricted reliably: refused.
	ok := query.WithScope(context.Background(), query.NewScope([]string{"x"}, nil))
	if _, err := conn.Query(ok, "SELECT 1 FROM flows_1h"); !errors.Is(err, query.ErrScopeWrite) {
		t.Fatalf("bare table: %v", err)
	}
	// Writes are refused in a restricted context, allowed otherwise.
	if err := conn.Exec(ok, "ALTER TABLE flow.flows DELETE WHERE 1"); !errors.Is(err, query.ErrScopeWrite) {
		t.Fatalf("exec: %v", err)
	}
	if err := conn.Exec(context.Background(), "SELECT 1"); err != nil || rec.execs != 1 {
		t.Fatalf("unscoped exec: %v", err)
	}
	// Unquoted and mixed forms are rewritten; other tables are not.
	if _, err := conn.Query(ok, "SELECT * FROM flow.flows JOIN flow.asn_names USING x WHERE y IN (SELECT 1 FROM `flow`.flows_5m)"); err != nil {
		t.Fatal(err)
	}
	got := rec.take()[0]
	if strings.Count(got, "(SELECT * FROM `flow`.`flows") != 2 || !strings.Contains(got, "flow.asn_names") {
		t.Fatalf("rewrite: %s", got)
	}
	// An unrestricted resolution (mode "all") leaves the query unchanged.
	all := query.WithScopeFunc(context.Background(), func(context.Context) (*query.Scope, error) { return nil, nil })
	if _, err := conn.Query(all, "SELECT 1 FROM flow.flows"); err != nil {
		t.Fatal(err)
	}
	if got := rec.take()[0]; got != "SELECT 1 FROM flow.flows" {
		t.Fatalf("unrestricted: %s", got)
	}
}

func TestDependencyPairsQuery(t *testing.T) {
	rec := &recConn{}
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	q := query.New(rec, query.Config{Now: func() time.Time { return now }})
	if _, err := q.DependencyPairs(context.Background(), query.DependencyParams{MinFlows: 50, MinDays: 9}); err != nil {
		t.Fatal(err)
	}
	sql := rec.take()[0]
	for _, want := range []string{
		"FROM `flow`.`flows`",
		"DstPort <= SrcPort AS srv_dst",
		"SrcCI != '' AND DstCI != '' AND SrcCI != DstCI",
		"HAVING flows >= 50 AND days_seen >= 7", // min_days capped by the period
		"LIMIT 500",
		"toDateTime(1791194400)", // 7 days before now
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("dependency SQL lacks %q:\n%s", want, sql)
		}
	}
}
