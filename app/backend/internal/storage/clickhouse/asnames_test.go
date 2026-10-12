package clickhouse_test

import (
	"context"
	"testing"
	"time"

	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
	"github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse/chtest"
)

func TestASNamesRoundTrip(t *testing.T) {
	conn, db := chtest.Conn(t)
	ctx := context.Background()
	cfg := chstore.Config{Database: db}
	if err := chstore.Migrate(ctx, conn, cfg); err != nil {
		t.Fatal(err)
	}
	if err := chstore.EnsureASNames(ctx, conn, cfg); err != nil { // idempotent
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour)
	if err := chstore.WriteASNames(ctx, conn, cfg, map[uint32]string{13335: "CLOUDFLARENET", 15169: "GOOGLE", 0: "zero", 1: ""}, t0); err != nil {
		t.Fatal(err)
	}
	if err := chstore.WriteASNames(ctx, conn, cfg, map[uint32]string{13335: "Cloudflare, Inc."}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	m, err := chstore.ReadASNames(ctx, conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m[13335] != "Cloudflare, Inc." || m[15169] != "GOOGLE" {
		t.Fatalf("%v", m)
	}
	if err := chstore.WriteASNames(ctx, conn, cfg, nil, t0); err != nil {
		t.Fatal(err)
	}
}
