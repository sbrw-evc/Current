package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/auth"
	"github.com/sbrw-evc/network/app/backend/internal/directory"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/schema"
	"github.com/sbrw-evc/network/app/backend/internal/setup"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// userView is the user as /api/auth/me and /api/auth/login return it.
type userView struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	Source      string   `json:"source"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// PasskeysEnabled shows the passkeys of the profile; the password fields
	// the expiry of a local password.
	PasskeysEnabled   bool       `json:"passkeys_enabled"`
	PasswordExpired   bool       `json:"password_expired"`
	PasswordWarning   bool       `json:"password_expiry_warning"`
	PasswordExpiresAt *time.Time `json:"password_expires_at,omitempty"`
}

func (a *App) viewOf(ctx context.Context, u store.User, perms access.Set) userView {
	v := userView{ID: u.ID, Username: u.Username, Name: u.Name, Email: u.Email, Source: u.Source, Role: u.Role, Permissions: perms.List()}
	ps, _ := a.passkeyConfig(ctx)
	v.PasskeysEnabled = ps.Enabled
	if exp, ok := a.passwordExpiry(ctx, u); ok {
		now := time.Now()
		v.PasswordExpiresAt = &exp
		v.PasswordExpired = !now.Before(exp)
		v.PasswordWarning = !now.Before(exp.AddDate(0, 0, -a.policy(ctx).WarnDays))
	}
	return v
}

// passwordExpiry is when the password of a local user expires under the policy.
func (a *App) passwordExpiry(ctx context.Context, u store.User) (time.Time, bool) {
	if u.Source != store.SourceLocal || u.PasswordChangedAt == nil {
		return time.Time{}, false
	}
	p := a.policy(ctx)
	if p.MaxAgeDays <= 0 {
		return time.Time{}, false
	}
	return u.PasswordChangedAt.AddDate(0, 0, p.MaxAgeDays), true
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	remote := httpx.ClientIP(r, a.opt.TrustedProxies)
	username := strings.TrimSpace(in.Username)
	keys := []string{"user:" + strings.ToLower(username), "ip:" + remote}
	// An explicit policy (set here or by Umbrella Identity) decides the lockout
	// of the account; without one the built-in limits stay.
	var stored auth.PasswordPolicy
	if found, _ := a.st.Setting(ctx, setup.SettingPasswordPolicy, &stored); found && stored.LockoutAttempts > 0 {
		pol := stored.Normalize()
		a.limiter.Tune(pol.LockoutAttempts, time.Duration(pol.LockoutMinutes)*time.Minute)
	}
	if locked, left := a.limiter.Locked(keys...); locked {
		w.Header().Set("Retry-After", fmt.Sprint(int(left.Seconds())+1))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed sign-ins, try again later")
		return
	}
	u, err := a.authenticate(ctx, username, in.Password)
	if err != nil {
		var se *signInError
		if !errors.As(err, &se) {
			slog.Error("sign-in failed", "user", username, "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "sign_in_unavailable", "sign-in is not available: "+err.Error())
			return
		}
		if se.count {
			a.limiter.Fail(keys...)
		}
		_ = a.st.Audit(ctx, username, "auth.login_failed", "", remote, map[string]string{"reason": se.code})
		httpx.Error(w, se.status, se.code, se.msg)
		return
	}
	a.limiter.Reset(keys[0])
	ss, err := a.sessions.Create(ctx, w, u.ID, remote)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	_ = a.st.TouchLogin(ctx, u.ID)
	list, err := a.st.Permissions(ctx, u.ID)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	_ = a.st.Audit(ctx, u.Username, "auth.login", "", remote, map[string]string{"source": u.Source})
	httpx.JSON(w, http.StatusOK, map[string]any{"user": a.viewOf(ctx, u, access.NewSet(list)), "csrf": ss.CSRF})
}

type signInError struct {
	status int
	code   string
	msg    string
	count  bool // counts toward the lockout
}

func (e *signInError) Error() string { return e.msg }

var errInvalid = &signInError{status: http.StatusUnauthorized, code: "invalid_credentials", msg: "wrong user name or password", count: true}

// authenticate checks a local password, or the directory for directory
// users and unknown names when LDAP is on.
func (a *App) authenticate(ctx context.Context, username, password string) (store.User, error) {
	if username == "" || password == "" || len(password) > 1024 {
		return store.User{}, errInvalid
	}
	u, err := a.st.UserByUsername(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	if err == nil && u.Source == store.SourceLocal {
		ok, err := a.passwords.Verify(u.PasswordRef, password)
		if err != nil {
			return store.User{}, err
		}
		if !ok {
			return store.User{}, errInvalid
		}
		if u.Disabled {
			return store.User{}, &signInError{status: http.StatusForbidden, code: "user_disabled", msg: "the account is disabled"}
		}
		return u, nil
	}
	ls, err := a.ldapSettings(ctx)
	if err != nil {
		return store.User{}, err
	}
	if !ls.Enabled {
		auth.CheckPassword("", password) // same timing as a wrong password
		return store.User{}, errInvalid
	}
	bind, err := a.secret(ls.BindPasswordRef)
	if err != nil {
		return store.User{}, fmt.Errorf("LDAP service account password: %w", err)
	}
	id, err := directory.Authenticate(ls.Config, bind, username, password)
	switch {
	case errors.Is(err, directory.ErrInvalidCredentials), errors.Is(err, directory.ErrUserNotFound), errors.Is(err, directory.ErrAmbiguousUser):
		return store.User{}, errInvalid
	case err != nil:
		return store.User{}, fmt.Errorf("LDAP: %w", err)
	}
	roleID, err := a.directoryRole(ctx, ls, id.Groups)
	if err != nil {
		return store.User{}, err
	}
	if roleID == 0 {
		return store.User{}, &signInError{status: http.StatusForbidden, code: "no_role",
			msg: "your directory groups give no role in Flow; ask an administrator"}
	}
	u, err = a.st.UpsertDirectoryUser(ctx, id.Username, id.Name, id.Email, roleID)
	if errors.Is(err, store.ErrConflict) {
		return store.User{}, errInvalid // a local user with this name exists
	}
	if err != nil {
		return store.User{}, err
	}
	if u.Disabled {
		return store.User{}, &signInError{status: http.StatusForbidden, code: "user_disabled", msg: "the account is disabled"}
	}
	return u, nil
}

// directoryRole maps groups to a role: the first group mapping that matches,
// else the default role (0 = no access).
func (a *App) directoryRole(ctx context.Context, ls ldapSettings, groups []string) (int64, error) {
	mappings, err := a.st.GroupRoles(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range mappings {
		if slices.Contains(groups, directory.NormalizeDN(m.GroupDN)) {
			return m.RoleID, nil
		}
	}
	return ls.DefaultRoleID, nil
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	// No CSRF check: signing out is harmless, and the cookie is SameSite=Lax.
	if err := a.sessions.Delete(r.Context(), w, r); err != nil {
		slog.Warn("session not deleted", "err", err)
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, p *Principal) {
	httpx.JSON(w, http.StatusOK, map[string]any{"user": a.viewOf(r.Context(), p.User, p.Perms), "csrf": p.Session.CSRF})
}

func (a *App) changeOwnPassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if p.User.Source != store.SourceLocal {
		httpx.Error(w, http.StatusConflict, "directory_user", "the password of a directory user is changed in the directory")
		return
	}
	if ok, err := a.passwords.Verify(p.User.PasswordRef, in.Current); err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "openbao_unavailable", "the password store is not available")
		return
	} else if !ok {
		httpx.Error(w, http.StatusForbidden, "invalid_credentials", "the current password is wrong")
		return
	}
	if err := a.replacePassword(r.Context(), p.User, in.New, p.Session.ID, true); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "auth.password_change", p.User.Username, nil)
	httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// policy returns the password policy (settings key password_policy).
func (a *App) policy(ctx context.Context) auth.PasswordPolicy {
	p := auth.DefaultPolicy
	if _, err := a.st.Setting(ctx, setup.SettingPasswordPolicy, &p); err != nil {
		slog.Warn("password policy not read", "err", err)
	}
	return p.Normalize()
}

// checkPassword validates a new password against the policy.
func (a *App) checkPassword(ctx context.Context, password, username string) error {
	return a.policy(ctx).Validate(password, username)
}

// setPassword stores the hash of a new password (an administrator sets it:
// the history is kept but not checked) and ends the user's other sessions.
func (a *App) setPassword(ctx context.Context, u store.User, password, keepSession string) error {
	return a.replacePassword(ctx, u, password, keepSession, false)
}

// replacePassword stores the hash of a new password in OpenBao, the reference
// in PostgreSQL, remembers the previous one for the history (checked when the
// user changes their own password) and ends the user's other sessions.
func (a *App) replacePassword(ctx context.Context, u store.User, password, keepSession string, checkHistory bool) error {
	if err := a.checkPassword(ctx, password, u.Username); err != nil {
		return err
	}
	pol := a.policy(ctx)
	ref, err := a.passwords.Replace(ctx, u.ID, u.PasswordRef, password, pol.HistoryCount, checkHistory)
	if errors.Is(err, auth.ErrReused) {
		return &auth.PolicyError{Violations: []string{auth.ViolationHistory}}
	}
	if err != nil {
		return &httpx.HTTPError{Status: http.StatusServiceUnavailable, Code: "openbao_unavailable", Err: err}
	}
	if err := a.st.SetPasswordRef(ctx, u.ID, ref); err != nil {
		return err
	}
	return a.sessions.DeleteUser(ctx, u.ID, keepSession)
}

func (a *App) catalog(w http.ResponseWriter, r *http.Request, p *Principal) {
	httpx.JSON(w, http.StatusOK, map[string]any{"groups": access.Groups(), "pages": access.Pages()})
}

type columnView struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Dimension bool   `json:"dimension"`
	Rollup    bool   `json:"rollup"`
	Reverse   string `json:"reverse,omitempty"`
	Metric    bool   `json:"metric"`
}

func (a *App) schema(w http.ResponseWriter, r *http.Request, p *Principal) {
	cols := make([]columnView, 0, len(schema.Columns))
	for _, c := range schema.Columns {
		cols = append(cols, columnView{Name: c.Name, Kind: string(c.Kind), Dimension: c.Dimension, Rollup: c.Rollup, Reverse: c.Reverse, Metric: c.Metric})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"columns": cols})
}
