package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// settingDetectorRulesSet marks that the rules were saved at least once, so an
// empty table means "no rules" rather than "the defaults".
const settingDetectorRulesSet = "detector_rules_set"

// DetectorRule is one stored rule: its id and its JSON (internal/detector.Rule).
type DetectorRule struct {
	ID   string
	Rule json.RawMessage
}

// DetectorRules returns the stored rules in order. found is false when they
// were never saved (the detector then uses its default set). updated is the
// time of the last change.
func (s *Store) DetectorRules(ctx context.Context) (rules []DetectorRule, found bool, updated time.Time, err error) {
	var mark struct {
		At time.Time `json:"at"`
	}
	if found, err = s.Setting(ctx, settingDetectorRulesSet, &mark); err != nil || !found {
		return nil, found, time.Time{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, rule FROM detector_rules ORDER BY position, id`)
	if err != nil {
		return nil, true, mark.At, err
	}
	defer rows.Close()
	for rows.Next() {
		var r DetectorRule
		var raw []byte
		if err := rows.Scan(&r.ID, &raw); err != nil {
			return nil, true, mark.At, err
		}
		r.Rule = raw
		rules = append(rules, r)
	}
	return rules, true, mark.At, rows.Err()
}

// SetDetectorRules replaces every rule in one transaction.
func (s *Store) SetDetectorRules(ctx context.Context, rules []DetectorRule) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM detector_rules`); err != nil {
			return err
		}
		for i, r := range rules {
			if _, err := tx.Exec(ctx, `INSERT INTO detector_rules (id, position, rule) VALUES ($1, $2, $3)`,
				r.ID, i, []byte(r.Rule)); err != nil {
				return err
			}
		}
		mark, _ := json.Marshal(map[string]time.Time{"at": time.Now().UTC()})
		_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, settingDetectorRulesSet, mark)
		return err
	})
}

// DetectorState returns the persisted detector snapshot (nil when none).
func (s *Store) DetectorState(ctx context.Context) ([]byte, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT state FROM detector_state WHERE id = 1`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return raw, err
}

// SetDetectorState stores the detector snapshot.
func (s *Store) SetDetectorState(ctx context.Context, state []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO detector_state (id, state) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET state = excluded.state, updated_at = now()`, state)
	return err
}
