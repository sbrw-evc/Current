package store

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/current/app/backend/internal/access"
)

// User sources: every person signs in through Keystone. A legacy account was made
// before Current moved to Keystone; it is bound to its Keystone person by the user name on
// the first Keystone sign-in or synchronization, or disabled by it.
const (
	SourceSPA    = "spa"
	SourceLegacy = "legacy"
)

// Role idents of the built-in roles in the catalogue published to Keystone.
const (
	IdentAdmin  = "admin"
	IdentViewer = "viewer"
)

type Role struct {
	ID int64 `json:"id"`
	// Ident is the stable identifier of the role in Keystone (the role catalogue,
	// the "roles" claim); it does not change when the role is renamed.
	Ident       string    `json:"ident"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Builtin     bool      `json:"builtin"`
	Permissions []string  `json:"permissions"`
	Users       int       `json:"users"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// User is a person, synchronized from Keystone (read-only in Current).
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Source      string     `json:"source"`
	RoleID      int64      `json:"role_id"`
	Role        string     `json:"role"`
	RoleIdent   string     `json:"role_ident"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
	// ExternalID is the Keystone user ID (the sub of the ID token) of the account.
	ExternalID string `json:"spa_id,omitempty"`
}

// ---- roles

const roleCols = `r.id, r.ident, r.name, r.description, r.builtin, r.created_at, r.updated_at,
	coalesce((SELECT array_agg(permission ORDER BY permission) FROM role_permissions p WHERE p.role_id = r.id), '{}'),
	(SELECT count(*) FROM users u WHERE u.role_id = r.id)`

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Ident, &r.Name, &r.Description, &r.Builtin, &r.CreatedAt, &r.UpdatedAt, &r.Permissions, &r.Users)
	r.Permissions = access.NewSet(r.Permissions).List()
	return r, pgErr(err)
}

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+roleCols+` FROM roles r ORDER BY r.builtin DESC, lower(r.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RoleByID(ctx context.Context, id int64) (Role, error) {
	return scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM roles r WHERE r.id = $1`, id))
}

func (s *Store) RoleByName(ctx context.Context, name string) (Role, error) {
	return scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM roles r WHERE lower(r.name) = lower($1)`, name))
}

// RoleByIdent finds a role by its Keystone identifier.
func (s *Store) RoleByIdent(ctx context.Context, ident string) (Role, error) {
	return scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM roles r WHERE r.ident = $1`, ident))
}

var notIdent = regexp.MustCompile(`[^a-z0-9_.:]+`)

// identFor makes the identifier of a new role from its name: lower-case
// letters, digits and . _ : - (as Keystone requires), or "role" for names in other
// alphabets.
func identFor(name string) string {
	id := strings.Trim(notIdent.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(id) > 56 {
		id = strings.TrimRight(id[:56], "-")
	}
	if id == "" || id == IdentAdmin || id == IdentViewer {
		id = "role"
	}
	return id
}

func setPerms(ctx context.Context, tx pgx.Tx, roleID int64, perms []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return err
	}
	perms = access.Normalize(perms)
	if len(perms) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO role_permissions (role_id, permission) SELECT $1, unnest($2::text[])`, roleID, perms)
	return err
}

// CreateRole adds a custom role; unknown permissions are dropped.
func (s *Store) CreateRole(ctx context.Context, name, description string, perms []string) (Role, error) {
	var id int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		base := identFor(name)
		ident := base
		for n := 2; ; n++ {
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE ident = $1)`, ident).Scan(&taken); err != nil {
				return err
			}
			if !taken && ident != "role" {
				break
			}
			ident = base + "-" + strconv.Itoa(n)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO roles (ident, name, description) VALUES ($1, $2, $3) RETURNING id`,
			ident, strings.TrimSpace(name), strings.TrimSpace(description)).Scan(&id); err != nil {
			return err
		}
		return setPerms(ctx, tx, id, perms)
	})
	if err != nil {
		return Role{}, pgErr(err)
	}
	return s.RoleByID(ctx, id)
}

// UpdateRole changes a custom role. Built-in roles cannot be changed.
func (s *Store) UpdateRole(ctx context.Context, id int64, name, description string, perms []string) (Role, error) {
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var builtin bool
		if err := tx.QueryRow(ctx, `SELECT builtin FROM roles WHERE id = $1 FOR UPDATE`, id).Scan(&builtin); err != nil {
			return err
		}
		if builtin {
			return ErrBuiltin
		}
		if _, err := tx.Exec(ctx, `UPDATE roles SET name = $2, description = $3, updated_at = now() WHERE id = $1`,
			id, strings.TrimSpace(name), strings.TrimSpace(description)); err != nil {
			return err
		}
		return setPerms(ctx, tx, id, perms)
	})
	if err != nil {
		return Role{}, pgErr(err)
	}
	return s.RoleByID(ctx, id)
}

// DeleteRole removes a custom role that no user has.
func (s *Store) DeleteRole(ctx context.Context, id int64) error {
	return pgErr(s.tx(ctx, func(tx pgx.Tx) error {
		var builtin bool
		if err := tx.QueryRow(ctx, `SELECT builtin FROM roles WHERE id = $1 FOR UPDATE`, id).Scan(&builtin); err != nil {
			return err
		}
		if builtin {
			return ErrBuiltin
		}
		_, err := tx.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
		return err
	}))
}

// EnsureBuiltinRoles creates Administrator ("admin" in Keystone) and Viewer
// ("viewer") and resets their permissions to the catalog (new permissions
// reach Administrator on upgrade).
func (s *Store) EnsureBuiltinRoles(ctx context.Context) error {
	idents := map[string]string{access.RoleAdministrator: IdentAdmin, access.RoleViewer: IdentViewer}
	return s.tx(ctx, func(tx pgx.Tx) error {
		for _, b := range access.BuiltinRoles() {
			var id int64
			ident := idents[b.Name]
			err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE lower(name) = lower($1)`, b.Name).Scan(&id)
			if err == pgx.ErrNoRows {
				err = tx.QueryRow(ctx, `INSERT INTO roles (ident, name, description, builtin) VALUES ($1, $2, $3, true) RETURNING id`,
					ident, b.Name, b.Description).Scan(&id)
			} else if err == nil {
				// A custom role holding the ident gives it up.
				if _, err = tx.Exec(ctx, `UPDATE roles SET ident = 'role-' || id WHERE ident = $1 AND id <> $2`, ident, id); err == nil {
					_, err = tx.Exec(ctx, `UPDATE roles SET builtin = true, description = $2, ident = $3 WHERE id = $1`, id, b.Description, ident)
				}
			}
			if err != nil {
				return err
			}
			if err := setPerms(ctx, tx, id, b.Permissions); err != nil {
				return err
			}
		}
		return nil
	})
}

// Permissions returns the permissions of the user's role.
func (s *Store) Permissions(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.permission FROM users u JOIN role_permissions p ON p.role_id = u.role_id WHERE u.id = $1`, userID)
	if err != nil {
		return nil, err
	}
	perms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return access.NewSet(perms).List(), err
}

// ---- users

const userCols = `u.id, u.username, u.name, u.email, u.source, u.role_id, r.name, r.ident, u.disabled,
	u.created_at, u.updated_at, u.last_login_at, u.external_id`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.Source, &u.RoleID, &u.Role, &u.RoleIdent, &u.Disabled,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt, &u.ExternalID)
	return u, pgErr(err)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id ORDER BY lower(u.username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, id))
}

// UserByUsername finds a user, ignoring case.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE lower(u.username) = lower($1)`,
		strings.TrimSpace(username)))
}

// NewUser is the input of CreateUser.
type NewUser struct {
	Username string
	Name     string
	Email    string
	RoleID   int64
	Disabled bool
}

// CreateUser adds a legacy account (one made before Keystone: imports and tests).
// People come from Keystone through UpsertSPAUser.
func (s *Store) CreateUser(ctx context.Context, in NewUser) (User, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO users (username, name, email, source, role_id, disabled)
		VALUES ($1, $2, $3, 'legacy', $4, $5) RETURNING id`,
		strings.TrimSpace(in.Username), strings.TrimSpace(in.Name), strings.TrimSpace(in.Email), in.RoleID, in.Disabled).Scan(&id)
	if err != nil {
		return User{}, pgErr(err)
	}
	return s.UserByID(ctx, id)
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

// CountEnabledAdmins counts enabled users whose role has users:edit and roles:edit,
// so a role change cannot take the administration away from everybody.
func (s *Store) CountEnabledAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users u WHERE NOT u.disabled
		AND EXISTS (SELECT 1 FROM role_permissions p WHERE p.role_id = u.role_id AND p.permission = $1)
		AND EXISTS (SELECT 1 FROM role_permissions p WHERE p.role_id = u.role_id AND p.permission = $2)`,
		access.UsersEdit, access.RolesEdit).Scan(&n)
	return n, err
}
