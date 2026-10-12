-- +goose Up

-- Detection rules (internal/detector.Rule as JSON), in display order. No row at
-- all means "the built-in default set"; a stored empty set is kept as the
-- settings key detector_rules_set (see store.SetDetectorRules).
CREATE TABLE detector_rules (
    id         text PRIMARY KEY,
    position   integer NOT NULL DEFAULT 0,
    rule       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The detector's persisted state: alert states and undelivered events
-- (internal/detector.Snapshot as JSON), a single row.
CREATE TABLE detector_state (
    id         integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    state      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE detector_state;
DROP TABLE detector_rules;
