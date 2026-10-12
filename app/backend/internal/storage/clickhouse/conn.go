package clickhouse

import (
	"context"
	"fmt"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ConnConfig is how to reach ClickHouse over the native protocol.
type ConnConfig struct {
	Addr     []string // host:port, default 127.0.0.1:9000
	Username string   // default "default"
	Password string
	// Database is not set on the connection: every statement qualifies its
	// tables with Config.Database, so the database may not exist yet.
	DialTimeout time.Duration // default 5s
	MaxOpenConn int           // default 10
}

// Open connects to ClickHouse and pings it.
func Open(ctx context.Context, cc ConnConfig) (driver.Conn, error) {
	if len(cc.Addr) == 0 {
		cc.Addr = []string{"127.0.0.1:9000"}
	}
	if cc.Username == "" {
		cc.Username = "default"
	}
	if cc.DialTimeout <= 0 {
		cc.DialTimeout = 5 * time.Second
	}
	if cc.MaxOpenConn <= 0 {
		cc.MaxOpenConn = 10
	}
	conn, err := ch.Open(&ch.Options{
		Addr:         cc.Addr,
		Auth:         ch.Auth{Username: cc.Username, Password: cc.Password},
		DialTimeout:  cc.DialTimeout,
		MaxOpenConns: cc.MaxOpenConn,
		Compression:  &ch.Compression{Method: ch.CompressionLZ4},
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clickhouse: ping: %w", err)
	}
	return conn, nil
}
