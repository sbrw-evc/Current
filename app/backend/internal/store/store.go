// Package store is the PostgreSQL configuration database: relational tables
// created by goose migrations embedded in the binary, and typed repository
// functions for users, roles, sessions, settings, saved views, classifiers,
// the Ledger connection, sampling overrides and the audit log.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	// ErrNotFound: no such row.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a unique key is taken, or the row is still referenced.
	ErrConflict = errors.New("conflict")
	// ErrBuiltin: built-in roles cannot be renamed or deleted.
	ErrBuiltin = errors.New("built-in role")
)

// Store is a PostgreSQL connection pool with the repository methods.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL and checks the connection. It does not migrate.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("PostgreSQL DSN: %w", err)
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	}
	if cfg.ConnConfig.RuntimeParams["application_name"] == "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = "current"
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("PostgreSQL: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PostgreSQL %s: %w", Where(dsn), err)
	}
	return &Store{pool: pool}, nil
}

// Where describes the server and database of a DSN without the password.
func Where(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%s:%d/%s", cfg.Host, cfg.Port, cfg.Database)
}

// Close closes the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Ping checks the connection.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool exposes the pool for packages that keep their own tables.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate applies the embedded migrations. A PostgreSQL advisory lock keeps
// several instances from migrating at once.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, 0)
}

// migrate applies the migrations up to version (0 = all; negative: down to -version).
func (s *Store) migrate(ctx context.Context, version int64) error {
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, sub,
		goose.WithDisableGlobalRegistry(true), goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	var res []*goose.MigrationResult
	switch {
	case version < 0:
		res, err = p.DownTo(ctx, -version)
	case version > 0:
		res, err = p.UpTo(ctx, version)
	default:
		res, err = p.Up(ctx)
	}
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	for _, r := range res {
		slog.Info("postgres migration applied", "version", r.Source.Version, "file", r.Source.Path, "took", r.Duration)
	}
	return nil
}

// Version returns the current migration version.
func (s *Store) Version(ctx context.Context) (int64, error) {
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT coalesce(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v)
	return v, err
}

// IsEmpty reports whether the database has no Current state yet: no users and
// no settings (a fresh database, or not migrated). People come from Keystone, so a
// completed setup with nobody signed in yet is told by its settings.
func (s *Store) IsEmpty(ctx context.Context) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.settings') IS NOT NULL`).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return true, nil
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM users) + (SELECT count(*) FROM settings)`).Scan(&n)
	return n == 0, err
}

func pgErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s", ErrConflict, pe.Detail)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: still in use", ErrConflict)
		}
	}
	return err
}

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}
