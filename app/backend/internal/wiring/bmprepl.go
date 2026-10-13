package wiring

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sbrw-evc/network/app/backend/internal/bmp"
)

// BMP replication over NATS JetStream: every enricher process publishes its
// BMP sessions to the stream FLOW_BMP (one subject per session,
// flow.bmp.<router>.<session>) and replays the sessions of the others from
// it, so that each replica enriches with the routes of every router whatever
// process holds its session. Old records of a session are purged when it
// publishes a snapshot; sessions of a dead process are purged once they
// expire.

const (
	bmpStream        = "FLOW_BMP"
	bmpSubjectPrefix = "flow.bmp."
	bmpStreamBytes   = 4 << 30
	// bmpExpiry drops a remote router after this long without records (the
	// session sends a heartbeat every bmp.HeartbeatInterval).
	bmpExpiry = 5 * bmp.HeartbeatInterval

	hdrKind     = "Flow-Bmp-Kind"
	hdrInstance = "Flow-Bmp-Instance"
	hdrRouter   = "Flow-Bmp-Router"
	hdrSession  = "Flow-Bmp-Session"
)

// bmpReplication is the JetStream transport (bmp.Replicator) and consumer.
type bmpReplication struct {
	js       jetstream.JetStream
	instance string
	log      *slog.Logger

	mu       sync.Mutex
	lastErr  string
	caughtUp bool
}

func newBMPReplication(js jetstream.JetStream, log *slog.Logger) *bmpReplication {
	return &bmpReplication{js: js, instance: bmpNewInstance(), log: log}
}

func bmpNewInstance() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func bmpSubject(router netip.Addr, session string) string {
	a := router.As16()
	return bmpSubjectPrefix + hex.EncodeToString(a[:]) + "." + session
}

func (r *bmpReplication) setErr(err error) {
	r.mu.Lock()
	if err != nil {
		r.lastErr = err.Error()
	} else {
		r.lastErr = ""
	}
	r.mu.Unlock()
}

func (r *bmpReplication) ensureStream(ctx context.Context) error {
	_, err := r.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        bmpStream,
		Description: "Umbrella Flow: BMP sessions shared between enricher replicas",
		Subjects:    []string{bmpSubjectPrefix + ">"},
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardOld,
		MaxBytes:    bmpStreamBytes,
		Storage:     jetstream.FileStorage,
	})
	if err != nil {
		if _, gerr := r.js.Stream(ctx, bmpStream); gerr == nil {
			return nil
		}
		return fmt.Errorf("BMP replication: stream %s: %w", bmpStream, err)
	}
	return nil
}

func (r *bmpReplication) publish(ctx context.Context, rec bmp.Record) (uint64, error) {
	m := nats.NewMsg(bmpSubject(rec.Router, rec.Session))
	m.Header.Set(hdrKind, strconv.Itoa(int(rec.Kind)))
	m.Header.Set(hdrInstance, r.instance)
	m.Header.Set(hdrRouter, rec.Router.String())
	m.Header.Set(hdrSession, rec.Session)
	m.Data = rec.Data
	ack, err := r.js.PublishMsg(ctx, m)
	if err != nil {
		r.setErr(err)
		return 0, err
	}
	return ack.Sequence, nil
}

// Publish implements bmp.Replicator.
func (r *bmpReplication) Publish(ctx context.Context, rec bmp.Record) error {
	_, err := r.publish(ctx, rec)
	return err
}

// Replace implements bmp.Replicator: the snapshot, then a purge of the
// session's records older than its first message.
func (r *bmpReplication) Replace(ctx context.Context, kind byte, router netip.Addr, session string, chunks [][]byte) error {
	rec := bmp.Record{Kind: kind, Router: router, Session: session}
	seq, err := r.publish(ctx, rec)
	if err != nil {
		return err
	}
	for _, c := range chunks {
		rec.Kind, rec.Data = bmp.RecSnapshot, c
		if _, err := r.publish(ctx, rec); err != nil {
			return err
		}
	}
	rec.Kind, rec.Data = bmp.RecSnapshotEnd, nil
	if _, err := r.publish(ctx, rec); err != nil {
		return err
	}
	return r.purge(ctx, bmpSubject(router, session), seq)
}

// purge drops the messages of subject before seq (all of them when 0).
func (r *bmpReplication) purge(ctx context.Context, subject string, seq uint64) error {
	st, err := r.js.Stream(ctx, bmpStream)
	if err != nil {
		return err
	}
	opts := []jetstream.StreamPurgeOpt{jetstream.WithPurgeSubject(subject)}
	if seq > 0 {
		opts = append(opts, jetstream.WithPurgeSequence(seq))
	}
	return st.Purge(ctx, opts...)
}

func parseBMPRecord(m jetstream.Msg) (bmp.Record, string, bool) {
	h := m.Headers()
	kind, err := strconv.Atoi(h.Get(hdrKind))
	if err != nil || kind <= 0 || kind > 255 {
		return bmp.Record{}, "", false
	}
	router, err := netip.ParseAddr(h.Get(hdrRouter))
	if err != nil || h.Get(hdrSession) == "" {
		return bmp.Record{}, "", false
	}
	rec := bmp.Record{Kind: byte(kind), Router: router, Session: h.Get(hdrSession), Data: m.Data(), Time: time.Now()}
	if md, err := m.Metadata(); err == nil {
		rec.Time = md.Timestamp
	}
	return rec, h.Get(hdrInstance), true
}

// run replays the records of the other processes into replica until ctx
// ends, and expires the routers of dead processes.
func (r *bmpReplication) run(ctx context.Context, replica *bmp.Replica) {
	for ctx.Err() == nil {
		err := r.consume(ctx, replica)
		if ctx.Err() != nil {
			return
		}
		r.setErr(err)
		r.log.Warn("BMP replication interrupted", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *bmpReplication) consume(ctx context.Context, replica *bmp.Replica) error {
	if err := r.ensureStream(ctx); err != nil {
		return err
	}
	cons, err := r.js.OrderedConsumer(ctx, bmpStream, jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{bmpSubjectPrefix + ">"},
		DeliverPolicy:  jetstream.DeliverAllPolicy,
	})
	if err != nil {
		return err
	}
	// Every replay starts from scratch: forget what an earlier one built.
	replica.Clear()
	r.mu.Lock()
	r.caughtUp = false
	r.mu.Unlock()
	if info, err := cons.Info(ctx); err == nil && info.NumPending == 0 {
		r.markCaughtUp()
	}
	it, err := cons.Messages()
	if err != nil {
		return err
	}
	defer it.Stop()
	go func() {
		<-ctx.Done()
		it.Stop()
	}()
	expire := time.NewTicker(bmp.HeartbeatInterval)
	defer expire.Stop()
	msgs := make(chan jetstream.Msg)
	errc := make(chan error, 1)
	go func() {
		for {
			m, err := it.Next()
			if err != nil {
				errc <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			if errors.Is(err, jetstream.ErrMsgIteratorClosed) && ctx.Err() != nil {
				return nil
			}
			return err
		case m := <-msgs:
			rec, inst, ok := parseBMPRecord(m)
			if ok && inst != r.instance {
				replica.ApplyRecord(rec)
			}
			if md, err := m.Metadata(); err == nil && md.NumPending == 0 {
				r.markCaughtUp()
			}
		case now := <-expire.C:
			r.mu.Lock()
			ready := r.caughtUp
			r.mu.Unlock()
			if !ready {
				continue // an old heartbeat is not a dead session yet
			}
			for _, dead := range replica.Expire(now, bmpExpiry) {
				r.log.Info("BMP replication: router expired", "router", dead.Router)
				pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_ = r.purge(pctx, bmpSubject(dead.Router, dead.Session), 0)
				cancel()
			}
		}
	}
}

func (r *bmpReplication) markCaughtUp() {
	r.mu.Lock()
	if !r.caughtUp {
		r.caughtUp, r.lastErr = true, ""
	}
	r.mu.Unlock()
}

// status is the replication part of the BMP status.
func (r *bmpReplication) status(replica *bmp.Replica) map[string]any {
	r.mu.Lock()
	out := map[string]any{"enabled": true, "caught_up": r.caughtUp}
	if r.lastErr != "" {
		out["error"] = r.lastErr
	}
	r.mu.Unlock()
	if replica != nil {
		out["routers"] = replica.Routers()
	} else {
		out["routers"] = []bmp.ReplicaRouter{}
	}
	return out
}
