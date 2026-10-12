package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/network/app/backend/internal/access"
)

// Tables of migration 00003: service accounts, API tokens and Microsoft
// Entra ID users.

// SourceEntra marks users signed in through Microsoft Entra ID.
const SourceEntra = "entra"

// ServiceAccount is a machine identity with a role; its tokens carry the role.
type ServiceAccount struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	RoleID      int64     `json:"role_id"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	Tokens      int       `json:"tokens"` // active (not revoked, not expired)
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const accountCols = `a.id, a.name, a.description, a.role_id, r.name, a.disabled,
	(SELECT count(*) FROM api_tokens t WHERE t.service_account_id = a.id AND t.revoked_at IS NULL
		AND (t.expires_at IS NULL OR t.expires_at > now())),
	a.created_by, a.created_at, a.updated_at`

func scanAccount(row pgx.Row) (ServiceAccount, error) {
	var a ServiceAccount
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.RoleID, &a.Role, &a.Disabled, &a.Tokens, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	return a, pgErr(err)
}

func (s *Store) ServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accountCols+` FROM service_accounts a JOIN roles r ON r.id = a.role_id ORDER BY lower(a.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceAccount{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ServiceAccount(ctx context.Context, id int64) (ServiceAccount, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM service_accounts a JOIN roles r ON r.id = a.role_id WHERE a.id = $1`, id))
}

func (s *Store) CreateServiceAccount(ctx context.Context, name, description string, roleID int64, createdBy string) (ServiceAccount, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO service_accounts (name, description, role_id, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
		strings.TrimSpace(name), strings.TrimSpace(description), roleID, createdBy).Scan(&id)
	if err != nil {
		return ServiceAccount{}, pgErr(err)
	}
	return s.ServiceAccount(ctx, id)
}

// DeleteServiceAccount removes the account and all its tokens.
func (s *Store) DeleteServiceAccount(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return pgErr(err)
}

// RolePermissions returns the permissions of a role.
func (s *Store) RolePermissions(ctx context.Context, roleID int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT permission FROM role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return nil, err
	}
	perms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return access.NewSet(perms).List(), err
}

// APIToken is an issued token without its secret.
type APIToken struct {
	ID               int64      `json:"id"`
	ServiceAccountID int64      `json:"service_account_id"`
	ServiceAccount   string     `json:"service_account"`
	Name             string     `json:"name"`
	Display          string     `json:"display"`
	ExpiresAt        *time.Time `json:"expires_at"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	LastUsedFrom     string     `json:"last_used_from"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at"`
	RevokedBy        string     `json:"revoked_by"`
}

// Active reports whether the token can be used at now.
func (t APIToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt))
}

const tokenCols = `t.id, t.service_account_id, a.name, t.name, t.display, t.expires_at, t.last_used_at, t.last_used_from,
	t.created_by, t.created_at, t.revoked_at, t.revoked_by`

func scanToken(row pgx.Row) (APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.ServiceAccountID, &t.ServiceAccount, &t.Name, &t.Display, &t.ExpiresAt, &t.LastUsedAt, &t.LastUsedFrom,
		&t.CreatedBy, &t.CreatedAt, &t.RevokedAt, &t.RevokedBy)
	return t, pgErr(err)
}

// APITokens lists tokens, newest first (accountID 0 = all accounts).
func (s *Store) APITokens(ctx context.Context, accountID int64) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tokenCols+` FROM api_tokens t JOIN service_accounts a ON a.id = t.service_account_id
		WHERE $1 = 0 OR t.service_account_id = $1 ORDER BY t.created_at DESC, t.id DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) APIToken(ctx context.Context, id int64) (APIToken, error) {
	return scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM api_tokens t JOIN service_accounts a ON a.id = t.service_account_id WHERE t.id = $1`, id))
}

// NewAPIToken is the input of CreateAPIToken.
type NewAPIToken struct {
	ServiceAccountID int64
	Name             string
	Hash             string // HMAC of the token
	Display          string
	ExpiresAt        *time.Time
	CreatedBy        string
}

func (s *Store) CreateAPIToken(ctx context.Context, in NewAPIToken) (APIToken, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO api_tokens (service_account_id, name, token_hash, display, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		in.ServiceAccountID, strings.TrimSpace(in.Name), in.Hash, in.Display, in.ExpiresAt, in.CreatedBy).Scan(&id)
	if err != nil {
		return APIToken{}, pgErr(err)
	}
	return s.APIToken(ctx, id)
}

// RevokeAPIToken marks the token revoked (kept for the audit trail).
func (s *Store) RevokeAPIToken(ctx context.Context, id int64, by string) (APIToken, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = coalesce(revoked_at, now()),
		revoked_by = CASE WHEN revoked_at IS NULL THEN $2 ELSE revoked_by END WHERE id = $1`, id, by)
	if err != nil {
		return APIToken{}, pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return APIToken{}, ErrNotFound
	}
	return s.APIToken(ctx, id)
}

// TokenPrincipal is what a bearer token resolves to.
type TokenPrincipal struct {
	Token   APIToken
	Account ServiceAccount
}

// TokenByHash finds a token by its HMAC, with its service account.
func (s *Store) TokenByHash(ctx context.Context, hash string) (TokenPrincipal, error) {
	var out TokenPrincipal
	t, err := scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM api_tokens t JOIN service_accounts a ON a.id = t.service_account_id
		WHERE t.token_hash = $1`, hash))
	if err != nil {
		return out, err
	}
	out.Token = t
	out.Account, err = s.ServiceAccount(ctx, t.ServiceAccountID)
	return out, err
}

// TouchAPIToken records a use; it reports whether the address is new for
// the token (a use from a new address is audited).
func (s *Store) TouchAPIToken(ctx context.Context, id int64, remote string, at time.Time) (newAddress bool, err error) {
	var prev string
	err = s.pool.QueryRow(ctx, `UPDATE api_tokens t SET last_used_at = $3, last_used_from = $2
		FROM (SELECT id, last_used_from FROM api_tokens WHERE id = $1 FOR UPDATE) old
		WHERE t.id = old.id RETURNING old.last_used_from`, id, remote, at).Scan(&prev)
	if err != nil {
		return false, pgErr(err)
	}
	return prev != remote, nil
}

// ---- Microsoft Entra ID users

// UpsertEntraUser creates or refreshes a user signed in through Microsoft
// Entra ID with the role of its groups (or the default role); created
// reports a first sign-in. A local or LDAP user with the same name is not
// taken over.
func (s *Store) UpsertEntraUser(ctx context.Context, username, name, email string, roleID int64) (User, bool, error) {
	username = strings.TrimSpace(username)
	var id int64
	var created bool
	err := s.pool.QueryRow(ctx, `INSERT INTO users (username, name, email, source, role_id) VALUES ($1, $2, $3, 'entra', $4)
		ON CONFLICT (lower(username)) DO UPDATE SET name = excluded.name, email = excluded.email,
			role_id = excluded.role_id, updated_at = now()
		WHERE users.source = 'entra'
		RETURNING id, xmax = 0`, username, name, email, roleID).Scan(&id, &created)
	if err != nil {
		if err == pgx.ErrNoRows {
			return User{}, false, fmt.Errorf("%w: a %s user %q exists", ErrConflict, "non-Entra", username)
		}
		return User{}, false, pgErr(err)
	}
	u, err := s.UserByID(ctx, id)
	return u, created, err
}
