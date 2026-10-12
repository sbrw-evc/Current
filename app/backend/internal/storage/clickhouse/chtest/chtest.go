// Package chtest gives integration tests a ClickHouse connection and a
// throw-away database name.
//
// FLOW_TEST_CLICKHOUSE selects the server (host:port of the native protocol,
// default 127.0.0.1:9000); "off" skips the tests.
package chtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Addr returns the server address, or "" when the tests are disabled.
func Addr() string {
	v := os.Getenv("FLOW_TEST_CLICKHOUSE")
	switch v {
	case "off":
		return ""
	case "":
		return "127.0.0.1:9000"
	}
	return v
}

// Conn connects to the test server and returns a unique database name
// (flow_test_<random>) that is dropped when the test ends. The database is
// not created. The test is skipped when ClickHouse is disabled or
// unreachable.
func Conn(t testing.TB) (driver.Conn, string) {
	t.Helper()
	addr := Addr()
	if addr == "" {
		t.Skip("FLOW_TEST_CLICKHOUSE=off")
	}
	conn, err := ch.Open(&ch.Options{Addr: []string{addr}, Auth: ch.Auth{Username: "default"}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Skipf("clickhouse at %s: %v", addr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		t.Skipf("clickhouse at %s unreachable: %v", addr, err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	db := "flow_test_" + hex.EncodeToString(b[:])
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+db+" SYNC"); err != nil {
			t.Logf("drop %s: %v", db, err)
		}
		conn.Close()
	})
	return conn, db
}
