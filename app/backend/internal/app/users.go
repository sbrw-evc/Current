package app

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/directory"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// ---- users

func (a *App) listUsers(w http.ResponseWriter, r *http.Request, p *Principal) {
	users, err := a.st.ListUsers(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": users})
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		RoleID   int64  `json:"role_id"`
		Disabled bool   `json:"disabled"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	in.Username = strings.TrimSpace(in.Username)
	if !setup.UsernameRe.MatchString(in.Username) {
		httpx.Error(w, http.StatusBadRequest, "invalid_username", "user name: 2-64 letters, digits, . _ @ -")
		return
	}
	if err := a.checkPassword(ctx, in.Password, in.Username); err != nil {
		httpx.Err(w, err)
		return
	}
	if _, err := a.st.RoleByID(ctx, in.RoleID); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such role")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = in.Username
	}
	u, err := a.st.CreateUser(ctx, store.NewUser{Username: in.Username, Name: name, Email: in.Email,
		RoleID: in.RoleID, Disabled: in.Disabled})
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.setPassword(ctx, u, in.Password, ""); err != nil {
		_ = a.st.DeleteUser(ctx, u.ID)
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "user.create", u.Username, map[string]string{"role": u.Role})
	httpx.JSON(w, http.StatusCreated, u)
}

// isAdmin: the user can manage users and roles (cannot be locked out).
func (a *App) isAdmin(ctx context.Context, roleID int64) (bool, error) {
	role, err := a.st.RoleByID(ctx, roleID)
	if err != nil {
		return false, err
	}
	s := access.NewSet(role.Permissions)
	return s.Has(access.UsersEdit) && s.Has(access.RolesEdit), nil
}

// keepsAnAdmin refuses changes that leave no enabled administrator.
func (a *App) keepsAnAdmin(ctx context.Context, u store.User, newRoleID int64, disabled bool) error {
	if u.Disabled {
		return nil
	}
	was, err := a.isAdmin(ctx, u.RoleID)
	if err != nil || !was {
		return err
	}
	still := !disabled
	if still {
		if still, err = a.isAdmin(ctx, newRoleID); err != nil {
			return err
		}
	}
	if still {
		return nil
	}
	n, err := a.st.CountEnabledAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return &httpx.HTTPError{Status: http.StatusConflict, Code: "last_admin", Msg: "this is the last enabled administrator"}
	}
	return nil
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		RoleID   *int64  `json:"role_id"`
		Disabled *bool   `json:"disabled"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	newRole, disabled := u.RoleID, u.Disabled
	if in.RoleID != nil {
		if _, err := a.st.RoleByID(ctx, *in.RoleID); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such role")
			return
		}
		newRole = *in.RoleID
	}
	if in.Disabled != nil {
		disabled = *in.Disabled
	}
	if err := a.keepsAnAdmin(ctx, u, newRole, disabled); err != nil {
		httpx.Err(w, err)
		return
	}
	u, err = a.st.UpdateUser(ctx, id, store.UserUpdate{Name: in.Name, Email: in.Email, RoleID: in.RoleID, Disabled: in.Disabled})
	if err != nil {
		storeErr(w, err)
		return
	}
	if u.Disabled {
		_ = a.sessions.DeleteUser(ctx, u.ID, "")
	}
	a.audit(ctx, p, "user.update", u.Username, map[string]any{"role": u.Role, "disabled": u.Disabled})
	httpx.JSON(w, http.StatusOK, u)
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if id == p.User.ID {
		httpx.Error(w, http.StatusConflict, "cannot_delete_self", "you cannot delete yourself")
		return
	}
	u, err := a.st.UserByID(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.keepsAnAdmin(ctx, u, u.RoleID, true); err != nil {
		httpx.Err(w, err)
		return
	}
	if err := a.st.DeleteUser(ctx, id); err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "user.delete", u.Username, nil)
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) setUserPassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if u.Source != store.SourceLocal {
		httpx.Error(w, http.StatusConflict, "directory_user", "the password of a directory user is changed in the directory")
		return
	}
	keep := ""
	if u.ID == p.User.ID {
		keep = p.Session.ID
	}
	if err := a.setPassword(ctx, u, in.Password, keep); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "user.password", u.Username, nil)
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- roles

func (a *App) listRoles(w http.ResponseWriter, r *http.Request, p *Principal) {
	roles, err := a.st.ListRoles(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": roles})
}

type roleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (in roleInput) check() error {
	if n := strings.TrimSpace(in.Name); n == "" || len(n) > 64 {
		return httpx.BadRequest("invalid_name", "the role name must have 1-64 characters")
	}
	for _, perm := range in.Permissions {
		if !access.Valid(perm) {
			return httpx.BadRequest("invalid_permission", "unknown permission "+perm)
		}
	}
	return nil
}

func (a *App) createRole(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in roleInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := in.check(); err != nil {
		httpx.Err(w, err)
		return
	}
	role, err := a.st.CreateRole(r.Context(), in.Name, in.Description, in.Permissions)
	if err != nil {
		storeErr(w, err)
		return
	}
	a.audit(r.Context(), p, "role.create", role.Name, map[string]any{"permissions": role.Permissions})
	httpx.JSON(w, http.StatusCreated, role)
}

func (a *App) updateRole(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in roleInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := in.check(); err != nil {
		httpx.Err(w, err)
		return
	}
	ctx := r.Context()
	old, err := a.st.RoleByID(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	role, err := a.st.UpdateRole(ctx, id, in.Name, in.Description, in.Permissions)
	if err != nil {
		storeErr(w, err)
		return
	}
	if n, err := a.st.CountEnabledAdmins(ctx); err == nil && n == 0 {
		_, _ = a.st.UpdateRole(ctx, id, old.Name, old.Description, old.Permissions)
		httpx.Error(w, http.StatusConflict, "last_admin", "the change would leave no enabled administrator")
		return
	}
	a.audit(ctx, p, "role.update", role.Name, map[string]any{"permissions": role.Permissions})
	httpx.JSON(w, http.StatusOK, role)
}

func (a *App) deleteRole(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	role, err := a.st.RoleByID(ctx, id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if role.Users > 0 {
		httpx.Error(w, http.StatusConflict, "role_in_use", "the role is assigned to users")
		return
	}
	if err := a.st.DeleteRole(ctx, id); err != nil {
		storeErr(w, err)
		return
	}
	a.audit(ctx, p, "role.delete", role.Name, nil)
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- LDAP / AD

const settingLDAP = "ldap"

type ldapSettings struct {
	directory.Config
	DefaultRoleID int64 `json:"default_role_id"`
}

func (a *App) ldapSettings(ctx context.Context) (ldapSettings, error) {
	var ls ldapSettings
	_, err := a.st.Setting(ctx, settingLDAP, &ls)
	return ls, err
}

type ldapView struct {
	ldapSettings
	BindPasswordSet bool              `json:"bind_password_set"`
	GroupRoles      []store.GroupRole `json:"group_roles"`
}

func (a *App) getLDAP(w http.ResponseWriter, r *http.Request, p *Principal) {
	ctx := r.Context()
	ls, err := a.ldapSettings(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	groups, err := a.st.GroupRoles(ctx)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	set := ls.BindPasswordRef != ""
	ls.BindPasswordRef = ""
	if ls.Kind == "" {
		ls.Config = directory.Defaults(directory.KindAD)
	}
	httpx.JSON(w, http.StatusOK, ldapView{ldapSettings: ls, BindPasswordSet: set, GroupRoles: groups})
}

type ldapInput struct {
	directory.Config
	BindPassword  *string           `json:"bind_password"` // nil = keep
	DefaultRoleID int64             `json:"default_role_id"`
	GroupRoles    []store.GroupRole `json:"group_roles"`
}

func (a *App) ldapFromInput(ctx context.Context, in ldapInput) (ldapSettings, string, error) {
	old, err := a.ldapSettings(ctx)
	if err != nil {
		return ldapSettings{}, "", err
	}
	bind := ""
	if in.BindPassword != nil {
		bind = *in.BindPassword
	} else if old.BindPasswordRef != "" {
		if bind, err = a.secret(old.BindPasswordRef); err != nil {
			return ldapSettings{}, "", err
		}
	}
	ls := ldapSettings{Config: in.Config, DefaultRoleID: in.DefaultRoleID}
	ls.BindPasswordRef = ""
	if ls.Enabled || ls.URL != "" {
		cfg, err := ls.Config.Normalize()
		if err != nil {
			return ldapSettings{}, "", httpx.BadRequest("ldap_invalid", err.Error())
		}
		cfg.Enabled = ls.Enabled
		ls.Config = cfg
	}
	return ls, bind, nil
}

func (a *App) putLDAP(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in ldapInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	ls, bind, err := a.ldapFromInput(ctx, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if ls.DefaultRoleID != 0 {
		if _, err := a.st.RoleByID(ctx, ls.DefaultRoleID); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_role", "no such default role")
			return
		}
	}
	for i, g := range in.GroupRoles {
		if !directory.ValidDN(g.GroupDN) {
			httpx.Error(w, http.StatusBadRequest, "invalid_group", "group DN is invalid: "+g.GroupDN)
			return
		}
		in.GroupRoles[i].GroupDN = directory.NormalizeDN(g.GroupDN)
	}
	if ls.Enabled && bind == "" {
		httpx.Error(w, http.StatusBadRequest, "ldap_invalid", "the service account password is required")
		return
	}
	if bind != "" {
		if ls.BindPasswordRef, err = a.putSecret(ctx, directory.SecretPath, directory.SecretKey, bind); err != nil {
			httpx.Error(w, http.StatusBadGateway, "openbao_write_failed", err.Error())
			return
		}
	} else {
		a.deleteSecret(ctx, directory.SecretPath)
	}
	if err := a.st.SetGroupRoles(ctx, in.GroupRoles); err != nil {
		storeErr(w, err)
		return
	}
	if err := a.st.PutSetting(ctx, settingLDAP, ls); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(ctx, p, "settings.ldap", ls.URL, map[string]any{"enabled": ls.Enabled, "groups": len(in.GroupRoles)})
	a.getLDAP(w, r, p)
}

func (a *App) testLDAP(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		ldapInput
		TestUsername string `json:"test_username"`
		TestPassword string `json:"test_password"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ls, bind, err := a.ldapFromInput(r.Context(), in.ldapInput)
	if err != nil {
		var he *httpx.HTTPError
		if errors.As(err, &he) {
			httpx.JSON(w, http.StatusOK, directory.TestResult{Error: he.Msg})
			return
		}
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, directory.Test(ls.Config, bind, in.TestUsername, in.TestPassword))
}
