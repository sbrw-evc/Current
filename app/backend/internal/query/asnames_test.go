package query_test

import (
	"context"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/query"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

func TestBuiltinASNames(t *testing.T) {
	for asn, want := range map[uint32]string{13335: "Cloudflare", 15169: "Google", 12389: "Rostelecom", 64512: ""} {
		if got := query.BuiltinASName(asn); got != want {
			t.Errorf("AS%d: %q, want %q", asn, got, want)
		}
	}
	var nilNames *query.ASNames
	if nilNames.Name(13335) != "Cloudflare" {
		t.Error("nil ASNames must fall back to the built-in list")
	}
	local := &query.ASNames{Local: func(asn uint32) string {
		if asn == 13335 {
			return "CLOUDFLARENET"
		}
		return ""
	}}
	if local.Name(13335) != "CLOUDFLARENET" || local.Name(15169) != "Google" || local.Name(64512) != "" {
		t.Error("local hook, then built-in")
	}
}

func TestASNamesFromClickHouse(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	if err := chstore.WriteASNames(ctx, conn, cfg, map[uint32]string{13335: "Cloudflare, Inc.", 65001: "Example Transit"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	a := &query.ASNames{Conn: conn, Storage: cfg}
	// the first lookup waits for the initial load
	if got := a.Name(65001); got != "Example Transit" {
		t.Fatalf("AS65001: %q", got)
	}
	if got := a.Name(13335); got != "Cloudflare, Inc." {
		t.Fatalf("AS13335: %q", got)
	}
	if got := a.Name(15169); got != "Google" {
		t.Fatalf("built-in fallback: %q", got)
	}
	// new names arrive with the next refresh
	if err := chstore.WriteASNames(ctx, conn, cfg, map[uint32]string{65002: "Other"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.Load(ctx); err != nil || a.Name(65002) != "Other" || a.Len() != 3 {
		t.Fatal(err, a.Len())
	}
}
