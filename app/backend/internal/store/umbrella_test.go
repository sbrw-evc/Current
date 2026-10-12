package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/store/storetest"
)

func TestDependencyRuns(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	if _, err := st.LatestDependencyRun(ctx, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	id, err := st.StartDependencyRun(ctx, store.DependencyTriggerSchedule, "", false, &day, map[string]int{"min_flows": 100})
	if err != nil {
		t.Fatal(err)
	}
	// The daily run is claimed once.
	if _, err := st.StartDependencyRun(ctx, store.DependencyTriggerSchedule, "", false, &day, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second claim: %v", err)
	}
	if done, err := st.ScheduledDependencyRunOn(ctx, day.Add(5*time.Hour)); err != nil || !done {
		t.Fatal(done, err)
	}
	// In progress: not a finished run yet.
	if _, err := st.LatestDependencyRun(ctx, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := st.FinishDependencyRun(ctx, id, store.DependencyRunResult{OK: true, Pairs: 3, Sent: 2, Accepted: 1, Updated: 1,
		Proposals: []map[string]string{{"key": "a"}, {"key": "b"}}}); err != nil {
		t.Fatal(err)
	}
	r, err := st.LatestDependencyRun(ctx, true)
	if err != nil || r.ID != id || r.OK == nil || !*r.OK || r.Sent != 2 || r.FinishedAt == nil || string(r.Params) != `{"min_flows": 100}` {
		t.Fatalf("%+v %v (params %s)", r, err, r.Params)
	}
	if len(r.Proposals) == 0 || string(r.Proposals)[0] != '[' {
		t.Fatalf("proposals %s", r.Proposals)
	}
	for i := 0; i < 55; i++ {
		if _, err := st.StartDependencyRun(ctx, store.DependencyTriggerManual, "admin", true, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := st.DependencyRuns(ctx, 100)
	if err != nil || len(runs) != 50 {
		t.Fatalf("kept %d runs: %v", len(runs), err)
	}
	if err := st.FinishDependencyRun(ctx, 1<<40, store.DependencyRunResult{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}
