package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// Alert states of one (rule, group).
const (
	StatePending   = "pending"   // condition true, waiting for `for`
	StateFiring    = "firing"    // event sent
	StateResolving = "resolving" // firing, condition false, waiting for the hysteresis
)

// AlertState is the persisted state of one (rule, group key).
type AlertState struct {
	RuleID string    `json:"rule_id"`
	Key    string    `json:"key"`
	State  string    `json:"state"`
	Since  time.Time `json:"since"`                // condition first true (starts_at)
	Clear  time.Time `json:"clear_since,omitzero"` // condition false since (resolving)
	Sent   time.Time `json:"last_sent,omitzero"`   // last firing event
	Value  float64   `json:"value"`                // last value
	Event  *Event    `json:"event,omitempty"`      // firing event (resolved reuses id, title, CI…)
	Group  string    `json:"group,omitempty"`      // human-readable group
	Seen   time.Time `json:"last_evaluated,omitzero"`
}

// action is what a state transition asks to send.
type action int

const (
	actNone action = iota
	actFire
	actResolve
)

// advance applies one evaluation to a state. st is nil when there is no
// state yet; the returned state is nil when it is gone. breach is the
// condition to enter (pending → firing); hold the condition to stay firing.
func advance(st *AlertState, breach, hold bool, now time.Time, forD, hysteresis time.Duration) (*AlertState, action) {
	if st == nil {
		if !breach {
			return nil, actNone
		}
		st = &AlertState{State: StatePending, Since: now}
		if forD <= 0 {
			st.State = StateFiring
			return st, actFire
		}
		return st, actNone
	}
	switch st.State {
	case StatePending:
		if !breach {
			return nil, actNone
		}
		if now.Sub(st.Since) >= forD {
			st.State = StateFiring
			return st, actFire
		}
		return st, actNone
	default: // firing, resolving
		if hold {
			st.State, st.Clear = StateFiring, time.Time{}
			return st, actNone
		}
		if st.Clear.IsZero() {
			st.State, st.Clear = StateResolving, now
		}
		if now.Sub(st.Clear) >= hysteresis {
			return nil, actResolve
		}
		return st, actNone
	}
}

// eventID is stable for one occurrence of an alert: firing and resolved
// share it, and a restart does not change it.
func eventID(ruleID, key string, since time.Time) string {
	h := sha256.Sum256([]byte(ruleID + "\x00" + key + "\x00" + since.UTC().Format(time.RFC3339Nano)))
	return "flow-" + hex.EncodeToString(h[:10])
}

// Snapshot is what the detector persists: alert states and undelivered
// events, so a restart neither repeats nor loses events.
type Snapshot struct {
	Version int          `json:"version"`
	SavedAt time.Time    `json:"saved_at"`
	Alerts  []AlertState `json:"alerts"`
	Outbox  []Event      `json:"outbox,omitempty"`
}

// StateStore persists the snapshot (the platform may keep it in PostgreSQL;
// MemoryStore keeps it in memory).
type StateStore interface {
	Load(ctx context.Context) (*Snapshot, error) // nil, nil when empty
	Save(ctx context.Context, s *Snapshot) error
}

// MarshalSnapshot encodes a snapshot as JSON.
func MarshalSnapshot(s *Snapshot) ([]byte, error) { return json.Marshal(s) }

// UnmarshalSnapshot decodes a snapshot; empty input gives nil.
func UnmarshalSnapshot(b []byte) (*Snapshot, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// MemoryStore is an in-memory StateStore holding the JSON snapshot.
type MemoryStore struct {
	mu   sync.Mutex
	data []byte
}

func (m *MemoryStore) Load(context.Context) (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return UnmarshalSnapshot(m.data)
}

func (m *MemoryStore) Save(_ context.Context, s *Snapshot) error {
	b, err := MarshalSnapshot(s)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.data = b
	m.mu.Unlock()
	return nil
}

// Bytes returns the last saved JSON snapshot.
func (m *MemoryStore) Bytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.data...)
}

// SetBytes replaces the snapshot (e.g. read back from disk).
func (m *MemoryStore) SetBytes(b []byte) {
	m.mu.Lock()
	m.data = append([]byte(nil), b...)
	m.mu.Unlock()
}
