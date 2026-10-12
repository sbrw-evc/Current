-- +goose Up

-- Dependency discovery runs (docs/integrations.md §3.3): the daily job and the
-- runs started from the API. schedule_day is set for scheduled runs only and is
-- unique, so that several api processes run the daily job once.
CREATE TABLE dependency_runs (
    id           bigserial PRIMARY KEY,
    trigger      text NOT NULL,              -- schedule | manual
    actor        text NOT NULL DEFAULT '',
    dry_run      boolean NOT NULL DEFAULT false,
    schedule_day date UNIQUE,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    ok           boolean,
    error        text NOT NULL DEFAULT '',
    pairs        integer NOT NULL DEFAULT 0,
    sent         integer NOT NULL DEFAULT 0,
    accepted     integer NOT NULL DEFAULT 0,
    updated      integer NOT NULL DEFAULT 0,
    ignored      integer NOT NULL DEFAULT 0,
    params       jsonb NOT NULL DEFAULT '{}',
    proposals    jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX dependency_runs_started ON dependency_runs (started_at DESC);

-- +goose Down
DROP TABLE dependency_runs;
