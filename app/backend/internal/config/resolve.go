package config

import (
	"fmt"

	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

// PostgresDSN returns the PostgreSQL DSN, resolving openbao:// references.
func (f File) PostgresDSN(r secrets.Resolver) (string, error) {
	if f.Postgres.DSN != "" {
		v, err := secrets.Value(r, f.Postgres.DSN)
		if err != nil {
			return "", fmt.Errorf("PostgreSQL DSN: %w", err)
		}
		return v, nil
	}
	pw, err := secrets.Value(r, f.Postgres.Password)
	if err != nil {
		return "", fmt.Errorf("PostgreSQL password: %w", err)
	}
	return f.Postgres.BuildDSN(pw), nil
}

// ClickHousePassword returns the ClickHouse password, resolving an openbao:// reference.
func (f File) ClickHousePassword(r secrets.Resolver) (string, error) {
	v, err := secrets.Value(r, f.ClickHouse.Password)
	if err != nil {
		return "", fmt.Errorf("ClickHouse password: %w", err)
	}
	return v, nil
}

// NATSToken returns the NATS token, resolving an openbao:// reference.
func (f File) NATSToken(r secrets.Resolver) (string, error) {
	v, err := secrets.Value(r, f.NATS.Token)
	if err != nil {
		return "", fmt.Errorf("NATS token: %w", err)
	}
	return v, nil
}
