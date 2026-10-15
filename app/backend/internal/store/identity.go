package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Sources of accounts made by Umbrella Identity (docs/identity-federation.md).
const (
	SourceGoogle   = "google"
	SourceApple    = "apple"
	SourceOIDC     = "oidc"
	SourceUmbrella = "umbrella"
)

// Passkey is a WebAuthn credential of a user. HubID is set for passkeys
// synchronized from Umbrella Monitoring.
type Passkey struct {
	ID             int64      `json:"id"`
	UserID         int64      `json:"user_id"`
	Name           string     `json:"name"`
	CredentialID   []byte     `json:"-"`
	PublicKey      []byte     `json:"-"`
	UserHandle     []byte     `json:"-"`
	SignCount      uint32     `json:"-"`
	AAGUID         []byte     `json:"-"`
	Transports     []string   `json:"transports"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	HubID          string     `json:"hub_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

const passkeyCols = `id, user_id, name, credential_id, public_key, user_handle, sign_count, aaguid, transports,
	backup_eligible, backup_state, hub_id, created_at, last_used_at`

func scanPasskey(row pgx.Row) (Passkey, error) {
	var k Passkey
	var count int64
	err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.CredentialID, &k.PublicKey, &k.UserHandle, &count, &k.AAGUID, &k.Transports,
		&k.BackupEligible, &k.BackupState, &k.HubID, &k.CreatedAt, &k.LastUsedAt)
	k.SignCount = uint32(count)
	if k.Transports == nil {
		k.Transports = []string{}
	}
	return k, pgErr(err)
}

// Passkeys lists the passkeys of a user, newest first.
func (s *Store) Passkeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Passkey{}
	for rows.Next() {
		k, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// PasskeyByCredential finds a passkey by its credential ID.
func (s *Store) PasskeyByCredential(ctx context.Context, credentialID []byte) (Passkey, error) {
	return scanPasskey(s.pool.QueryRow(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE credential_id = $1`, credentialID))
}

// CountPasskeys counts the passkeys of a user.
func (s *Store) CountPasskeys(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM passkeys WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// AddPasskey stores a new passkey.
func (s *Store) AddPasskey(ctx context.Context, k Passkey) (Passkey, error) {
	if k.Transports == nil {
		k.Transports = []string{}
	}
	return scanPasskey(s.pool.QueryRow(ctx, `INSERT INTO passkeys (user_id, name, credential_id, public_key, user_handle,
		sign_count, aaguid, transports, backup_eligible, backup_state, hub_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, coalesce($12, now())) RETURNING `+passkeyCols,
		k.UserID, k.Name, k.CredentialID, k.PublicKey, k.UserHandle, int64(k.SignCount), nonNil(k.AAGUID), k.Transports,
		k.BackupEligible, k.BackupState, k.HubID, nullTime(k.CreatedAt)))
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// TouchPasskey records a sign-in with a passkey.
func (s *Store) TouchPasskey(ctx context.Context, id int64, signCount uint32, backupState bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE passkeys SET sign_count = $2, backup_state = $3, last_used_at = now() WHERE id = $1`,
		id, int64(signCount), backupState)
	return err
}

// RenamePasskey renames a passkey of a user.
func (s *Store) RenamePasskey(ctx context.Context, userID, id int64, name string) (Passkey, error) {
	return scanPasskey(s.pool.QueryRow(ctx, `UPDATE passkeys SET name = $3 WHERE user_id = $1 AND id = $2 RETURNING `+passkeyCols,
		userID, id, name))
}

// DeletePasskey removes a passkey of a user (id 0: all of them).
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM passkeys WHERE user_id = $1 AND ($2 = 0 OR id = $2)`, userID, id)
	if err != nil {
		return 0, err
	}
	if id != 0 && tag.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	return tag.RowsAffected(), nil
}

// ReplaceHubPasskeys replaces the synchronized passkeys of a user.
func (s *Store) ReplaceHubPasskeys(ctx context.Context, userID int64, keys []Passkey) error {
	return pgErr(s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM passkeys WHERE user_id = $1 AND hub_id <> ''`, userID); err != nil {
			return err
		}
		for _, k := range keys {
			if k.Transports == nil {
				k.Transports = []string{}
			}
			// A credential registered locally as well keeps its local row.
			if _, err := tx.Exec(ctx, `INSERT INTO passkeys (user_id, name, credential_id, public_key, user_handle, sign_count,
				aaguid, transports, backup_eligible, hub_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
				ON CONFLICT (credential_id) DO NOTHING`, userID, k.Name, k.CredentialID, k.PublicKey, k.UserHandle, int64(k.SignCount),
				nonNil(k.AAGUID), k.Transports, k.BackupEligible, k.HubID, k.CreatedAt); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ExternalUser is a person as an external provider or the Umbrella hub gives them.
type ExternalUser struct {
	Source     string
	ExternalID string
	Username   string
	Name       string
	Email      string
	RoleID     int64
	Disabled   bool
}

// ErrUsernameTaken: another account has the user name.
var ErrUsernameTaken = errors.New("the user name belongs to another account")

// UpsertExternalUser creates or refreshes the account bound to (source,
// external ID). linkUsername lets an account of linkSources with the same
// user name be taken over (bound to the provider) instead of refused.
func (s *Store) UpsertExternalUser(ctx context.Context, in ExternalUser, linkSources ...string) (User, bool, error) {
	in.Username, in.Name, in.Email = strings.TrimSpace(in.Username), strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if in.Name == "" {
		in.Name = in.Username
	}
	var id int64
	created := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE users SET username = $3, name = $4, email = $5, role_id = $6, disabled = $7, updated_at = now()
			WHERE source = $1 AND external_id = $2 RETURNING id`, in.Source, in.ExternalID, in.Username, in.Name, in.Email,
			in.RoleID, in.Disabled).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var other int64
		var source string
		err = tx.QueryRow(ctx, `SELECT id, source FROM users WHERE lower(username) = lower($1)`, in.Username).Scan(&other, &source)
		switch {
		case err == nil:
			for _, ls := range linkSources {
				if ls == source {
					return tx.QueryRow(ctx, `UPDATE users SET source = $2, external_id = $3, name = $4, email = $5, role_id = $6,
						disabled = $7, updated_at = now() WHERE id = $1 RETURNING id`, other, in.Source, in.ExternalID, in.Name,
						in.Email, in.RoleID, in.Disabled).Scan(&id)
				}
			}
			return ErrUsernameTaken
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		created = true
		return tx.QueryRow(ctx, `INSERT INTO users (username, name, email, source, external_id, role_id, disabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, in.Username, in.Name, in.Email, in.Source, in.ExternalID,
			in.RoleID, in.Disabled).Scan(&id)
	})
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			return User{}, false, err
		}
		return User{}, false, pgErr(err)
	}
	u, err := s.UserByID(ctx, id)
	return u, created, err
}

// UserByExternal finds the account bound to (source, external ID).
func (s *Store) UserByExternal(ctx context.Context, source, externalID string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id
		WHERE u.source = $1 AND u.external_id = $2`, source, externalID))
}

// UserByEmail finds an account by its e-mail address (the oldest one).
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id
		WHERE lower(u.email) = lower($1) AND u.email <> '' ORDER BY u.id LIMIT 1`, strings.TrimSpace(email)))
}

// DisableMissing disables the accounts of source whose external ID is not in
// keep and returns their IDs.
func (s *Store) DisableMissing(ctx context.Context, source string, keep []string) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `UPDATE users SET disabled = true, updated_at = now()
		WHERE source = $1 AND NOT disabled AND NOT (external_id = ANY($2)) RETURNING id`, source, keep)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
