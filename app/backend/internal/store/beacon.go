package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- dependency discovery runs (table dependency_runs, docs/integrations.md §3.3)

// Dependency run triggers.
const (
	DependencyTriggerSchedule = "schedule"
	DependencyTriggerManual   = "manual"
)

// DependencyRun is one discovery run. Proposals is the JSON array of the
// proposals it built (the preview); Params the thresholds it ran with.
type DependencyRun struct {
	ID         int64           `json:"id"`
	Trigger    string          `json:"trigger"`
	Actor      string          `json:"actor"`
	DryRun     bool            `json:"dry_run"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	OK         *bool           `json:"ok"`
	Error      string          `json:"error"`
	Pairs      int             `json:"pairs"`
	Sent       int             `json:"sent"`
	Accepted   int             `json:"accepted"`
	Updated    int             `json:"updated"`
	Ignored    int             `json:"ignored"`
	Params     json.RawMessage `json:"params"`
	Proposals  json.RawMessage `json:"proposals,omitempty"`
}

// DependencyRunResult is what a finished run records.
type DependencyRunResult struct {
	OK        bool
	Error     string
	Pairs     int
	Sent      int
	Accepted  int
	Updated   int
	Ignored   int
	Proposals any // JSON array
}

// keepDependencyRuns: older runs are deleted when a new one starts.
const keepDependencyRuns = 50

// StartDependencyRun records a run that starts now. scheduleDay (scheduled
// runs only) is unique: a second claim of the same day answers ErrConflict,
// so concurrent api processes run the daily job once.
func (s *Store) StartDependencyRun(ctx context.Context, trigger, actor string, dryRun bool, scheduleDay *time.Time, params any) (int64, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return 0, err
	}
	var day any
	if scheduleDay != nil {
		day = scheduleDay.UTC().Format("2006-01-02")
	}
	var id int64
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO dependency_runs (trigger, actor, dry_run, schedule_day, params)
			VALUES ($1, $2, $3, $4::date, $5) RETURNING id`, trigger, actor, dryRun, day, raw).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM dependency_runs WHERE id IN (
			SELECT id FROM dependency_runs ORDER BY started_at DESC, id DESC OFFSET $1)`, keepDependencyRuns)
		return err
	})
	return id, pgErr(err)
}

// FinishDependencyRun records the result of a run.
func (s *Store) FinishDependencyRun(ctx context.Context, id int64, r DependencyRunResult) error {
	props := r.Proposals
	if props == nil {
		props = []any{}
	}
	raw, err := json.Marshal(props)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE dependency_runs SET finished_at = now(), ok = $2, error = $3, pairs = $4, sent = $5,
		accepted = $6, updated = $7, ignored = $8, proposals = $9 WHERE id = $1`,
		id, r.OK, r.Error, r.Pairs, r.Sent, r.Accepted, r.Updated, r.Ignored, raw)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

const depRunCols = `id, trigger, actor, dry_run, started_at, finished_at, ok, error, pairs, sent, accepted, updated, ignored, params`

func scanDependencyRun(row pgx.Row, withProposals bool) (DependencyRun, error) {
	var r DependencyRun
	var params, props []byte
	dest := []any{&r.ID, &r.Trigger, &r.Actor, &r.DryRun, &r.StartedAt, &r.FinishedAt, &r.OK, &r.Error, &r.Pairs, &r.Sent,
		&r.Accepted, &r.Updated, &r.Ignored, &params}
	if withProposals {
		dest = append(dest, &props)
	}
	if err := row.Scan(dest...); err != nil {
		return r, pgErr(err)
	}
	r.Params = params
	if withProposals {
		r.Proposals = props
	}
	return r, nil
}

// LatestDependencyRun returns the newest run with its proposals
// (ErrNotFound when there is none). finishedOnly skips a run in progress.
func (s *Store) LatestDependencyRun(ctx context.Context, finishedOnly bool) (DependencyRun, error) {
	where := ""
	if finishedOnly {
		where = "WHERE finished_at IS NOT NULL"
	}
	return scanDependencyRun(s.pool.QueryRow(ctx, `SELECT `+depRunCols+`, proposals FROM dependency_runs `+where+`
		ORDER BY started_at DESC, id DESC LIMIT 1`), true)
}

// DependencyRuns lists the latest runs without their proposals.
func (s *Store) DependencyRuns(ctx context.Context, limit int) ([]DependencyRun, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `SELECT `+depRunCols+` FROM dependency_runs ORDER BY started_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DependencyRun{}
	for rows.Next() {
		r, err := scanDependencyRun(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScheduledDependencyRunOn reports whether the daily run of day was claimed.
func (s *Store) ScheduledDependencyRunOn(ctx context.Context, day time.Time) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM dependency_runs WHERE schedule_day = $1::date`, day.UTC().Format("2006-01-02")).Scan(&n)
	return n > 0, err
}
