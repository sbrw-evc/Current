package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// People synchronized from Keystone (migration 00007, docs/identity-federation.md).

// SPAUser is a person as Keystone gives them.
type SPAUser struct {
	ExternalID string // the Keystone user ID (sub)
	Username   string
	Name       string
	Email      string
	RoleID     int64
}

// ErrUsernameTaken: another enabled Keystone account has the user name.
var ErrUsernameTaken = errors.New("the user name belongs to another Keystone account")

// SPABinding tells how UpsertSPAUser found the account.
type SPABinding int

const (
	SPAUpdated SPABinding = iota // the account bound to the sub
	SPABound                     // a legacy account with the user name, bound now
	SPACreated                   // a new account
)

// UpsertSPAUser creates or refreshes (and enables) the account bound to the
// Keystone user ID. A legacy account with the same user name is bound to it once;
// from then on only the ID counts. A disabled Keystone account holding the user
// name (a person removed from Keystone whose name was given to someone else) is
// renamed out of the way.
func (s *Store) UpsertSPAUser(ctx context.Context, in SPAUser) (User, SPABinding, error) {
	in.Username, in.Name, in.Email = strings.TrimSpace(in.Username), strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if in.Name == "" {
		in.Name = in.Username
	}
	var id int64
	how := SPAUpdated
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var other int64
		var source string
		var disabled bool
		err := tx.QueryRow(ctx, `SELECT id, source, disabled FROM users WHERE lower(username) = lower($1) AND NOT (source = 'spa' AND external_id = $2)`,
			in.Username, in.ExternalID).Scan(&other, &source, &disabled)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			other = 0
		case err != nil:
			return err
		}
		var mine int64
		err = tx.QueryRow(ctx, `SELECT id FROM users WHERE source = 'spa' AND external_id = $1 FOR UPDATE`, in.ExternalID).Scan(&mine)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if other != 0 {
			switch {
			case source == SourceLegacy && mine == 0:
				// Bind the legacy account (once).
				how = SPABound
				return tx.QueryRow(ctx, `UPDATE users SET source = 'spa', external_id = $2, name = $3, email = $4, role_id = $5,
					disabled = false, updated_at = now() WHERE id = $1 RETURNING id`, other, in.ExternalID, in.Name, in.Email, in.RoleID).Scan(&id)
			case disabled:
				if _, err := tx.Exec(ctx, `UPDATE users SET username = username || '~' || id::text, updated_at = now() WHERE id = $1`, other); err != nil {
					return err
				}
			default:
				return ErrUsernameTaken
			}
		}
		if mine != 0 {
			return tx.QueryRow(ctx, `UPDATE users SET username = $2, name = $3, email = $4, role_id = $5, disabled = false, updated_at = now()
				WHERE id = $1 RETURNING id`, mine, in.Username, in.Name, in.Email, in.RoleID).Scan(&id)
		}
		how = SPACreated
		return tx.QueryRow(ctx, `INSERT INTO users (username, name, email, source, external_id, role_id)
			VALUES ($1, $2, $3, 'spa', $4, $5) RETURNING id`, in.Username, in.Name, in.Email, in.ExternalID, in.RoleID).Scan(&id)
	})
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			return User{}, how, err
		}
		return User{}, how, pgErr(err)
	}
	u, err := s.UserByID(ctx, id)
	return u, how, err
}

// UserBySPA finds the account bound to a Keystone user ID.
func (s *Store) UserBySPA(ctx context.Context, externalID string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id
		WHERE u.source = 'spa' AND u.external_id = $1`, externalID))
}

// DisableSPAUser disables the account of a Keystone user ID; it reports the
// account ID when it was enabled.
func (s *Store) DisableSPAUser(ctx context.Context, externalID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `UPDATE users SET disabled = true, updated_at = now()
		WHERE source = 'spa' AND external_id = $1 AND NOT disabled RETURNING id`, externalID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// DisableAbsent disables the Keystone accounts whose ID is not in keep and every
// legacy account (no Keystone person claimed it), and returns their IDs.
func (s *Store) DisableAbsent(ctx context.Context, keep []string) ([]int64, error) {
	if keep == nil {
		keep = []string{}
	}
	rows, err := s.pool.Query(ctx, `UPDATE users SET disabled = true, updated_at = now()
		WHERE NOT disabled AND (source = 'legacy' OR NOT (external_id = ANY($1))) RETURNING id`, keep)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// SPAUserCounts are the accounts by state, for the settings page.
type SPAUserCounts struct {
	Enabled  int `json:"enabled"`
	Disabled int `json:"disabled"`
	Legacy   int `json:"legacy"`
}

func (s *Store) CountSPAUsers(ctx context.Context) (SPAUserCounts, error) {
	var c SPAUserCounts
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE source = 'spa' AND NOT disabled),
		count(*) FILTER (WHERE source = 'spa' AND disabled), count(*) FILTER (WHERE source = 'legacy') FROM users`).
		Scan(&c.Enabled, &c.Disabled, &c.Legacy)
	return c, err
}

// TryLock takes a PostgreSQL session advisory lock (one replica runs a
// schedule) and returns its release; ok is false when another holds it.
func (s *Store) TryLock(ctx context.Context, key int64) (release func(), ok bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil || !ok {
		conn.Release()
		return nil, false, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		conn.Release()
	}, true, nil
}

// LockKey is a stable advisory lock key for a name.
func LockKey(name string) int64 {
	var h uint64 = 14695981039346656037
	for _, c := range []byte("flow:" + name) {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return int64(h >> 1)
}
