package wiring

import (
	"context"
	"testing"

	"github.com/sbrw-evc/current/app/backend/internal/query"
	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse/chtest"
)

// TestASNamesAcrossProcesses: names learned by the enricher's GeoIP are
// persisted and read back by the api role's querier hook.
func TestASNamesAcrossProcesses(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}
	if err := conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+db); err != nil {
		t.Fatal(err)
	}
	if err := chstore.EnsureASNames(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	g := &GeoSwap{}
	g.names.Store(uint32(13335), "Cloudflare, Inc.")
	g.names.Store(uint32(64500), "Example Net")
	p := &ASNamePersister{Geo: g, Conn: conn, Storage: cfg}
	if n, err := p.Flush(ctx); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, err := p.Flush(ctx); err != nil || n != 0 {
		t.Fatal("unchanged names written again", n, err)
	}
	g.names.Store(uint32(64500), "Example Net 2")
	if n, err := p.Flush(ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	api := &query.ASNames{Conn: conn, Storage: cfg}
	if api.Name(13335) != "Cloudflare, Inc." || api.Name(64500) != "Example Net 2" {
		t.Fatal(api.Name(13335), api.Name(64500))
	}
}
