package wiring_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/sbrw-evc/network/app/backend/internal/query"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/wiring"
)

// sqlConn records the queries and answers with no rows.
type sqlConn struct {
	driver.Conn
	sqls []string
}

func (c *sqlConn) Query(_ context.Context, sql string, _ ...any) (driver.Rows, error) {
	c.sqls = append(c.sqls, sql)
	return noRows{}, nil
}

type noRows struct{ driver.Rows }

func (noRows) Next() bool   { return false }
func (noRows) Err() error   { return nil }
func (noRows) Close() error { return nil }

// Filter value completion reads ClickHouse through the same scoped
// connection: a restricted user only gets values of their own flows.
func TestFilterCompletionScoped(t *testing.T) {
	rec := &sqlConn{}
	cfg := chstore.Config{}
	f := &wiring.Filter{Conn: query.ScopedConn(rec, cfg), Storage: cfg}
	ctx := query.WithScope(context.Background(), query.NewScope([]string{"inventory-db:dcim.device:7"}, []string{"10.0.0.9"}))
	for _, col := range []string{"SrcCI", "SrcPort"} { // aggregated (flows_1h) and raw columns
		req, _ := json.Marshal(map[string]string{"what": "value", "column": col, "prefix": ""})
		if _, err := f.Complete(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.sqls) != 2 {
		t.Fatalf("%d queries", len(rec.sqls))
	}
	if !strings.Contains(rec.sqls[0], "(SELECT * FROM `flow`.`flows_1h` WHERE (SrcCI IN ('inventory-db:dcim.device:7')") {
		t.Errorf("aggregate completion not scoped:\n%s", rec.sqls[0])
	}
	if !strings.Contains(rec.sqls[1], "(SELECT * FROM `flow`.`flows` WHERE (") || !strings.Contains(rec.sqls[1], "SrcAddr IN (toIPv6('::ffff:10.0.0.9'))") {
		t.Errorf("raw completion not scoped:\n%s", rec.sqls[1])
	}
	// Failing closed.
	bad := query.WithScopeFunc(context.Background(), func(context.Context) (*query.Scope, error) { return nil, context.DeadlineExceeded })
	req, _ := json.Marshal(map[string]string{"what": "value", "column": "SrcCI", "prefix": "a"})
	if _, err := f.Complete(bad, req); err == nil || !strings.Contains(err.Error(), "visibility scope") {
		t.Fatal(err)
	}
}
