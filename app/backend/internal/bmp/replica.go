package bmp

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Replication shares the BMP sessions of one enricher with the others (HA,
// several enricher replicas behind one flow bus): the receiving process
// publishes the raw BMP messages of each session as records, every other
// process replays them into its own RIB with the same decoder. A session's
// records are compacted from time to time into a snapshot of its current
// state (Peer Up messages and synthesized Route Monitoring), so that a
// process starting later rebuilds the routes from a bounded history.

// Record kinds.
const (
	// RecStart: a session began; replicas drop older routes of the router.
	RecStart byte = 1 + iota
	// RecMessages: raw BMP messages (common header included) of the session.
	RecMessages
	// RecCompact begins a snapshot replacing the older records of the
	// session; replicas that followed the session skip it.
	RecCompact
	// RecResync begins a snapshot after records were lost; every replica
	// rebuilds the routes of the router from it.
	RecResync
	// RecSnapshot carries BMP messages of the snapshot begun by RecCompact
	// or RecResync.
	RecSnapshot
	// RecSnapshotEnd ends the snapshot; live messages follow.
	RecSnapshotEnd
	// RecHeartbeat: the session is alive.
	RecHeartbeat
	// RecEnd: the session closed; replicas drop the routes of the router.
	RecEnd
)

// Record is one replication message of a session.
type Record struct {
	Kind    byte
	Router  netip.Addr
	Session string
	Data    []byte    // BMP messages for RecMessages and RecSnapshot
	Time    time.Time // publication time, set by the transport on receipt
}

// Replicator publishes the records of the local sessions (NATS JetStream in
// wiring). Calls for one session come from one goroutine, except
// heartbeats.
type Replicator interface {
	Publish(ctx context.Context, r Record) error
	// Replace publishes a snapshot (RecCompact or RecResync, then the
	// chunks as RecSnapshot, then RecSnapshotEnd) and drops the records of
	// the session published before it.
	Replace(ctx context.Context, kind byte, router netip.Addr, session string, chunks [][]byte) error
}

// replicaRouter is the replayed session of one remote router.
type replicaRouter struct {
	session  string
	st       *sessionState
	last     time.Time
	skipping bool // in a compaction snapshot the replica already follows
}

// Replica replays the records of sessions held by other processes into the
// RIB. Routers with a session in this process are left to it: a router
// should send BMP to one station (or one load-balanced address).
type Replica struct {
	srv *Server

	mu      sync.Mutex
	routers map[netip.Addr]*replicaRouter
	local   map[netip.Addr]int
}

// NewReplica returns a replica decoding with the policy of srv (which needs
// not listen) into its RIB. Pass it as Config.Replica of the listening
// server so that local sessions take precedence.
func NewReplica(srv *Server) *Replica {
	return &Replica{srv: srv, routers: map[netip.Addr]*replicaRouter{}, local: map[netip.Addr]int{}}
}

// Apply sets the policy and allowed routers, as Server.Apply.
func (r *Replica) Apply(st Settings) error { return r.srv.Apply(st) }

func (r *Replica) localStart(router netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.local[router]++
	if _, ok := r.routers[router]; ok {
		delete(r.routers, router)
		r.srv.rib.RemoveRouter(router)
	}
}

func (r *Replica) localEnd(router netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.local[router]--; r.local[router] <= 0 {
		delete(r.local, router)
	}
}

func (r *Replica) reset(rec Record) *replicaRouter {
	if _, ok := r.routers[rec.Router]; ok {
		r.srv.rib.RemoveRouter(rec.Router)
	}
	rr := &replicaRouter{session: rec.Session, last: rec.Time,
		st: &sessionState{router: rec.Router, caps: map[PeerKey]*sessionCaps{}}}
	r.routers[rec.Router] = rr
	return rr
}

// ApplyRecord replays one record of another process.
func (r *Replica) ApplyRecord(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.local[rec.Router] > 0 {
		return
	}
	r.srv.m.replicated.WithLabelValues("in").Inc()
	rr := r.routers[rec.Router]
	cur := rr != nil && rr.session == rec.Session
	switch rec.Kind {
	case RecStart:
		r.reset(rec)
		return
	case RecCompact:
		if cur {
			rr.skipping, rr.last = true, rec.Time
			return
		}
		r.reset(rec)
		return
	case RecResync:
		r.reset(rec)
		return
	}
	if !cur {
		// A session whose beginning this replica did not see (it started
		// before a compaction this replica has not reached yet), or an
		// older one: nothing to apply.
		return
	}
	rr.last = rec.Time
	switch rec.Kind {
	case RecMessages, RecSnapshot:
		if !rr.skipping {
			r.feed(rr, rec.Data)
		}
	case RecSnapshotEnd:
		rr.skipping = false
	case RecEnd:
		delete(r.routers, rec.Router)
		r.srv.rib.RemoveRouter(rec.Router)
	}
}

// feed decodes concatenated BMP messages.
func (r *Replica) feed(rr *replicaRouter, b []byte) {
	for len(b) >= commonHeaderLen {
		typ, l, err := parseCommonHeader(b)
		if err != nil || l > len(b) {
			r.srv.m.errors.WithLabelValues("replication").Inc()
			return
		}
		if _, err := r.srv.handle(rr.st, typ, b[commonHeaderLen:l]); err != nil {
			r.srv.m.errors.WithLabelValues("decode").Inc()
		}
		b = b[l:]
	}
}

// Expire drops the routers whose session sent nothing for ttl (the process
// holding it died) and returns those sessions.
func (r *Replica) Expire(now time.Time, ttl time.Duration) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Record
	for a, rr := range r.routers {
		if now.Sub(rr.last) > ttl {
			delete(r.routers, a)
			r.srv.rib.RemoveRouter(a)
			out = append(out, Record{Router: a, Session: rr.session})
		}
	}
	return out
}

// Clear drops every replayed router (replication stopped).
func (r *Replica) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for a := range r.routers {
		r.srv.rib.RemoveRouter(a)
	}
	clear(r.routers)
}

// ReplicaRouter describes a router replayed from another process.
type ReplicaRouter struct {
	Router     netip.Addr `json:"router"`
	PeersUp    int        `json:"peers_up"`
	LastRecord time.Time  `json:"last_record"`
}

// Routers lists the replayed routers.
func (r *Replica) Routers() []ReplicaRouter {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ReplicaRouter, 0, len(r.routers))
	for a, rr := range r.routers {
		out = append(out, ReplicaRouter{Router: a, PeersUp: len(rr.st.caps), LastRecord: rr.last})
	}
	return out
}
