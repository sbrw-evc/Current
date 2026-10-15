package app

import (
	"net/http"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
)

// ---- users: read-only records synchronized from SPA (spa.go). Creating
// people, passwords, roles and enabling or disabling them is done in SPA.

func (a *App) listUsers(w http.ResponseWriter, r *http.Request, p *Principal) {
	users, err := a.st.ListUsers(r.Context())
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"results": users})
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
	a.audit(r.Context(), p, "role.create", role.Name, map[string]any{"ident": role.Ident, "permissions": role.Permissions})
	a.rolesChanged(r.Context())
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
	a.audit(ctx, p, "role.update", role.Name, map[string]any{"ident": role.Ident, "permissions": role.Permissions})
	a.rolesChanged(ctx)
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
	a.audit(ctx, p, "role.delete", role.Name, map[string]string{"ident": role.Ident})
	a.rolesChanged(ctx)
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}
