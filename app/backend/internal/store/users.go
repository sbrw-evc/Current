package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/network/app/backend/internal/access"
)

// User sources.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
)

type Role struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Builtin     bool      `json:"builtin"`
	Permissions []string  `json:"permissions"`
	Users       int       `json:"users"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Source      string     `json:"source"`
	PasswordRef string     `json:"-"` // openbao:// reference to the password hash
	RoleID      int64      `json:"role_id"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// ---- roles

const roleCols = `r.id, r.name, r.description, r.builtin, r.created_at, r.updated_at,
	coalesce((SELECT array_agg(permission ORDER BY permission) FROM role_permissions p WHERE p.role_id = r.id), '{}'),
	(SELECT count(*) FROM users u WHERE u.role_id = r.id)`

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Builtin, &r.CreatedAt, &r.UpdatedAt, &r.Permissions, &r.Users)
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
		if err := tx.QueryRow(ctx, `INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id`,
			strings.TrimSpace(name), strings.TrimSpace(description)).Scan(&id); err != nil {
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

// EnsureBuiltinRoles creates Administrator and Viewer and resets their
// permissions to the catalog (new permissions reach Administrator on upgrade).
func (s *Store) EnsureBuiltinRoles(ctx context.Context) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		for _, b := range access.BuiltinRoles() {
			var id int64
			err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE lower(name) = lower($1)`, b.Name).Scan(&id)
			if err == pgx.ErrNoRows {
				err = tx.QueryRow(ctx, `INSERT INTO roles (name, description, builtin) VALUES ($1, $2, true) RETURNING id`,
					b.Name, b.Description).Scan(&id)
			} else if err == nil {
				_, err = tx.Exec(ctx, `UPDATE roles SET builtin = true, description = $2 WHERE id = $1`, id, b.Description)
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

const userCols = `u.id, u.username, u.name, u.email, u.source, u.password_ref, u.role_id, r.name, u.disabled,
	u.created_at, u.updated_at, u.last_login_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.Source, &u.PasswordRef, &u.RoleID, &u.Role, &u.Disabled,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
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
	Source   string
	RoleID   int64
	Disabled bool
}

func (s *Store) CreateUser(ctx context.Context, in NewUser) (User, error) {
	if in.Source == "" {
		in.Source = SourceLocal
	}
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO users (username, name, email, source, role_id, disabled)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		strings.TrimSpace(in.Username), strings.TrimSpace(in.Name), strings.TrimSpace(in.Email), in.Source,
		in.RoleID, in.Disabled).Scan(&id)
	if err != nil {
		return User{}, pgErr(err)
	}
	return s.UserByID(ctx, id)
}

// UserUpdate changes the given fields (nil = keep).
type UserUpdate struct {
	Name     *string
	Email    *string
	RoleID   *int64
	Disabled *bool
}

func (s *Store) UpdateUser(ctx context.Context, id int64, in UserUpdate) (User, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET
		name = coalesce($2, name), email = coalesce($3, email), role_id = coalesce($4, role_id),
		disabled = coalesce($5, disabled), updated_at = now() WHERE id = $1`, id, in.Name, in.Email, in.RoleID, in.Disabled)
	if err != nil {
		return User{}, pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return User{}, ErrNotFound
	}
	return s.UserByID(ctx, id)
}

// SetPasswordRef stores the OpenBao reference of a local user's password hash.
func (s *Store) SetPasswordRef(ctx context.Context, id int64, ref string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET password_ref = $2, updated_at = now() WHERE id = $1`, id, ref)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return pgErr(err)
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return pgErr(err)
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

// CountEnabledAdmins counts enabled users whose role has users:edit and roles:edit,
// so the last administrator cannot lock everybody out.
func (s *Store) CountEnabledAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users u WHERE NOT u.disabled
		AND EXISTS (SELECT 1 FROM role_permissions p WHERE p.role_id = u.role_id AND p.permission = $1)
		AND EXISTS (SELECT 1 FROM role_permissions p WHERE p.role_id = u.role_id AND p.permission = $2)`,
		access.UsersEdit, access.RolesEdit).Scan(&n)
	return n, err
}

// UpsertDirectoryUser creates or refreshes a user signed in through LDAP / AD.
// A local user with the same name is not taken over.
func (s *Store) UpsertDirectoryUser(ctx context.Context, username, name, email string, roleID int64) (User, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO users (username, name, email, source, role_id) VALUES ($1, $2, $3, 'ldap', $4)
		ON CONFLICT (lower(username)) DO UPDATE SET name = excluded.name, email = excluded.email, role_id = excluded.role_id,
			updated_at = now() WHERE users.source = 'ldap'
		RETURNING id`, strings.TrimSpace(username), name, email, roleID).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return User{}, fmt.Errorf("%w: a local user %q exists", ErrConflict, username)
		}
		return User{}, pgErr(err)
	}
	return s.UserByID(ctx, id)
}

// ---- directory group -> role

type GroupRole struct {
	GroupDN string `json:"group_dn"`
	RoleID  int64  `json:"role_id"`
	Role    string `json:"role"`
}

// GroupRoles lists the mappings in priority order.
func (s *Store) GroupRoles(ctx context.Context) ([]GroupRole, error) {
	rows, err := s.pool.Query(ctx, `SELECT g.group_dn, g.role_id, r.name FROM group_roles g JOIN roles r ON r.id = g.role_id ORDER BY g.position, g.group_dn`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupRole{}
	for rows.Next() {
		var g GroupRole
		if err := rows.Scan(&g.GroupDN, &g.RoleID, &g.Role); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGroupRoles replaces the mappings; the slice order is the priority.
func (s *Store) SetGroupRoles(ctx context.Context, in []GroupRole) error {
	return pgErr(s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM group_roles`); err != nil {
			return err
		}
		for i, g := range in {
			if _, err := tx.Exec(ctx, `INSERT INTO group_roles (group_dn, role_id, position) VALUES ($1, $2, $3)`, g.GroupDN, g.RoleID, i); err != nil {
				return err
			}
		}
		return nil
	}))
}
