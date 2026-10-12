package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/httpx"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

// Moving the secrets to another OpenBao (Settings → OpenBao), as in Umbrella
// Monitoring: check the target, copy every secret of the current mount
// there, point the openbao:// references of PostgreSQL and flow.json to the
// new mount, write flow.json and switch the running OpenBao client in place,
// so every component follows without a restart. The source is left intact.

func (a *App) openbaoMigrateRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	h("POST /api/settings/openbao/probe", a.guard(perms(access.OpenBaoMigrate), a.probeOpenBao))
	h("POST /api/settings/openbao/migrate", a.guard(perms(access.OpenBaoMigrate), a.migrateOpenBao))
}

// openbaoMoves serializes moves per App (one at a time).
var openbaoMoves sync.Map // *App → *sync.Mutex

func (a *App) openbaoMoveLock() *sync.Mutex {
	m, _ := openbaoMoves.LoadOrStore(a, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// openbaoTarget is the target connection as the console sends it. File
// paths cannot be set through the API; without credentials, a target on the
// same server reuses the current ones.
type openbaoTarget struct {
	Addr       string `json:"addr"`
	Mount      string `json:"mount"`
	Namespace  string `json:"namespace,omitempty"`
	Auth       string `json:"auth"`
	Token      string `json:"token,omitempty"`
	RoleID     string `json:"role_id,omitempty"`
	SecretID   string `json:"secret_id,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
	SkipVerify bool   `json:"skip_verify,omitempty"`
}

func (in openbaoTarget) config(current config.OpenBao) (config.OpenBao, error) {
	o := config.OpenBao{Addr: in.Addr, Mount: in.Mount, Namespace: in.Namespace, Auth: in.Auth, Token: in.Token,
		RoleID: in.RoleID, SecretID: in.SecretID, CACert: in.CACert, SkipVerify: in.SkipVerify}
	noCreds := strings.TrimSpace(in.Token) == "" && strings.TrimSpace(in.RoleID) == "" && strings.TrimSpace(in.SecretID) == ""
	if noCreds && strings.TrimRight(strings.TrimSpace(in.Addr), "/") == strings.TrimRight(current.Addr, "/") {
		o.Auth, o.Token, o.TokenFile = current.Auth, current.Token, current.TokenFile
		o.RoleID, o.SecretID, o.RoleIDFile, o.SecretIDFile, o.AppRolePath = current.RoleID, current.SecretID, current.RoleIDFile, current.SecretIDFile, current.AppRolePath
		if o.CACert == "" {
			o.CACert = current.CACert
		}
	}
	o, err := o.Normalize()
	if err != nil {
		return o, httpx.BadRequest("openbao_invalid", err.Error())
	}
	return o, nil
}

func sameStore(x, y config.OpenBao) bool {
	return strings.EqualFold(strings.TrimRight(x.Addr, "/"), strings.TrimRight(y.Addr, "/")) && x.Mount == y.Mount && x.Namespace == y.Namespace
}

// openbaoProbe is the check of a target.
type openbaoProbe struct {
	secrets.Check
	KV2Error string `json:"kv2_error,omitempty"`
	Secrets  int    `json:"secrets"` // already in the target mount
	Same     bool   `json:"same,omitempty"`
}

// currentOpenBao is the connection of flow.json as the App knows it.
func (a *App) currentOpenBao() config.OpenBao {
	return a.config().OpenBao
}

func (a *App) probeTarget(ctx context.Context, o config.OpenBao) (*secrets.Client, openbaoProbe) {
	var rep openbaoProbe
	c, err := o.Client()
	if err != nil {
		rep.Error = err.Error()
		return nil, rep
	}
	rep.Check = c.Verify(ctx)
	if !rep.OK {
		return nil, rep
	}
	if err := c.CheckKV2(ctx); err != nil {
		rep.OK, rep.KV2Error, rep.Error = false, err.Error(), err.Error()
		return nil, rep
	}
	existing, err := c.List(ctx)
	if err != nil {
		rep.OK, rep.Error = false, err.Error()
		return nil, rep
	}
	rep.Secrets = len(existing)
	return c, rep
}

func (a *App) probeOpenBao(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in openbaoTarget
	if !httpx.Decode(w, r, &in) {
		return
	}
	cur := a.currentOpenBao()
	o, err := in.config(cur)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, rep := a.probeTarget(ctx, o)
	rep.Same = sameStore(o, cur)
	httpx.JSON(w, http.StatusOK, rep)
}

type openbaoMoved struct {
	Addr   string `json:"addr"`
	Mount  string `json:"mount"`
	Copied int    `json:"copied"`
	Refs   int64  `json:"refs"` // references rewritten in PostgreSQL and flow.json
}

func (a *App) migrateOpenBao(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Target    openbaoTarget `json:"target"`
		Overwrite bool          `json:"overwrite"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if a.opt.DataDir == "" {
		notImplemented(w, "moving the secrets to another OpenBao")
		return
	}
	lock := a.openbaoMoveLock()
	if !lock.TryLock() {
		httpx.Error(w, http.StatusConflict, "openbao_migration_running", "another move is running")
		return
	}
	defer lock.Unlock()
	cur := a.config().OpenBao
	target, err := in.Target.config(cur)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	if sameStore(target, cur) {
		httpx.Error(w, http.StatusBadRequest, "openbao_same_store", "the target is the current OpenBao mount")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()
	dst, probe := a.probeTarget(ctx, target)
	if dst == nil {
		httpx.Error(w, http.StatusBadRequest, "openbao_unavailable", probe.Error)
		return
	}
	if probe.Secrets > 0 && !in.Overwrite {
		httpx.Error(w, http.StatusConflict, "openbao_target_not_empty",
			fmt.Sprintf("the mount %s already has %d secrets; confirm overwriting them", target.Mount, probe.Secrets))
		return
	}
	res, err := a.moveSecrets(ctx, cur, target, dst, probe.Secrets == 0)
	if err != nil {
		a.audit(ctx, p, "settings.openbao.migrate_failed", target.Addr+"/"+target.Mount, map[string]string{"error": err.Error()})
		slog.Error("openbao migration failed", "to", target.Addr, "mount", target.Mount, "err", err)
		httpx.Error(w, http.StatusBadGateway, "openbao_migration_failed", err.Error())
		return
	}
	a.audit(ctx, p, "settings.openbao.migrate", target.Addr+"/"+target.Mount, map[string]any{
		"from": cur.Addr + "/" + cur.Mount, "copied": res.Copied, "refs": res.Refs})
	slog.Info("openbao migrated", "from", cur.Addr, "to", target.Addr, "mount", target.Mount, "copied", res.Copied, "refs", res.Refs)
	httpx.JSON(w, http.StatusOK, res)
}

// moveSecrets copies, rewrites the references and switches. Called with the
// move lock held. On failure nothing is switched, and secrets copied to an
// empty target are removed again.
func (a *App) moveSecrets(ctx context.Context, cur, target config.OpenBao, dst *secrets.Client, cleanup bool) (res openbaoMoved, err error) {
	res = openbaoMoved{Addr: target.Addr, Mount: target.Mount}
	copied, err := a.deps.Vault.CopyTo(ctx, dst)
	res.Copied = len(copied)
	defer func() {
		if err == nil || !cleanup {
			return
		}
		for _, path := range copied {
			if derr := dst.Delete(context.WithoutCancel(ctx), path); derr != nil {
				slog.Warn("copied secret not removed from the target OpenBao", "path", path, "err", derr)
			}
		}
	}()
	if err != nil {
		return res, err
	}
	file, found, err := config.Read(a.opt.DataDir)
	if err != nil {
		return res, fmt.Errorf("read %s: %w", config.FileName, err)
	}
	if !found {
		file = a.config()
	}
	from, to := cur.Mount, target.Mount
	next, fileRefs, err := moveFileRefs(file, from, to)
	if err != nil {
		return res, err
	}
	next.OpenBao = target
	err = pgx.BeginFunc(ctx, a.st.Pool(), func(tx pgx.Tx) error {
		n, err := moveDatabaseRefs(ctx, tx, from, to)
		if err != nil {
			return fmt.Errorf("rewrite the secret references in PostgreSQL: %w", err)
		}
		res.Refs = n + fileRefs
		if err := config.Write(a.opt.DataDir, next); err != nil {
			return fmt.Errorf("write %s: %w", config.FileName, err)
		}
		return nil
	})
	if err != nil {
		if found {
			if werr := config.Write(a.opt.DataDir, file); werr != nil {
				slog.Error("flow.json not restored after a failed OpenBao move", "err", werr)
			}
		}
		return res, err
	}
	// The switch: every holder of the client follows at once.
	if err := a.deps.Vault.Reconfigure(dst.Config()); err != nil {
		return res, err // not expected: the same settings built dst
	}
	a.setConfig(next)
	return res, nil
}

// moveFileRefs rewrites the openbao:// references of flow.json to the new mount.
func moveFileRefs(f config.File, from, to string) (config.File, int64, error) {
	if from == to {
		return f, 0, nil
	}
	b, err := json.Marshal(f)
	if err != nil {
		return f, 0, err
	}
	old := `"` + secrets.Scheme + from + `/`
	n := strings.Count(string(b), old)
	if n == 0 {
		return f, 0, nil
	}
	var out config.File
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(b), old, `"`+secrets.Scheme+to+`/`)), &out); err != nil {
		return f, 0, err
	}
	return out, int64(n), nil
}

// moveDatabaseRefs rewrites openbao://<from>/… to openbao://<to>/… in every
// text and jsonb column of the Flow schema, so references kept by any package
// (users, settings, Inventory DB, LDAP, Umbrella, Entra ID…) follow.
func moveDatabaseRefs(ctx context.Context, tx pgx.Tx, from, to string) (int64, error) {
	if from == to {
		return 0, nil
	}
	if strings.ContainsAny(from+to, `'"\`) {
		return 0, errors.New("invalid mount name")
	}
	rows, err := tx.Query(ctx, `SELECT c.table_name, c.column_name, c.data_type FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE'
			AND c.data_type IN ('text', 'character varying', 'jsonb') AND c.table_name NOT IN ('goose_db_version', 'audit_log')
		ORDER BY 1, 2`)
	if err != nil {
		return 0, err
	}
	type col struct{ table, column, kind string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column, &c.kind); err != nil {
			rows.Close()
			return 0, err
		}
		cols = append(cols, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	oldRef, newRef := secrets.Scheme+from+"/", secrets.Scheme+to+"/"
	var total int64
	for _, c := range cols {
		t, k := pgx.Identifier{c.table}.Sanitize(), pgx.Identifier{c.column}.Sanitize()
		var q string
		var args []any
		if c.kind == "jsonb" {
			q = fmt.Sprintf(`UPDATE %s SET %s = replace(%s::text, $1, $2)::jsonb WHERE strpos(%s::text, $1) > 0`, t, k, k, k)
			args = []any{`"` + oldRef, `"` + newRef}
		} else {
			q = fmt.Sprintf(`UPDATE %s SET %s = replace(%s, $1, $2) WHERE strpos(%s, $1) > 0`, t, k, k, k)
			args = []any{oldRef, newRef}
		}
		tag, err := tx.Exec(ctx, q, args...)
		if err != nil {
			return 0, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
