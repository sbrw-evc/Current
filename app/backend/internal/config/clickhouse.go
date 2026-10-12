package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Options returns clickhouse-go options for the connection; database "" uses
// the server default database (for checks before the Flow database exists).
func (c ClickHouse) Options(password, database string) *clickhouse.Options {
	o := &clickhouse.Options{
		Addr:        c.Addrs(),
		Auth:        clickhouse.Auth{Database: database, Username: c.Username, Password: password},
		DialTimeout: 10 * time.Second,
		ClientInfo:  clickhouse.ClientInfo{Products: []struct{ Name, Version string }{{Name: "umbrella-flow", Version: "1"}}},
	}
	if c.Secure {
		o.TLS = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.SkipVerify}
	}
	return o
}

// Open connects to ClickHouse (database "" = server default) and pings it.
func (c ClickHouse) Open(ctx context.Context, password, database string) (driver.Conn, error) {
	conn, err := clickhouse.Open(c.Options(password, database))
	if err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := conn.Ping(pctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ClickHouse %s: %w", c.Addr, err)
	}
	return conn, nil
}
