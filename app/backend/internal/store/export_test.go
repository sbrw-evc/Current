package store

import "context"

// MigrateTo applies the migrations up to version (migration tests).
func MigrateTo(ctx context.Context, s *Store, version int64) error { return s.migrate(ctx, version) }
