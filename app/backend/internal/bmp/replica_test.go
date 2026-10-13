package bmp

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// memLog is an in-memory replication transport: one ordered log with
// per-session purges, as the JetStream stream in wiring.
type memLog struct {
	mu   sync.Mutex
	recs []Record
	fail bool
}

func (l *memLog) Publish(_ context.Context, r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return io.ErrClosedPipe
	}
	r.Data = slices.Clone(r.Data)
	r.Time = time.Now()
	l.recs = append(l.recs, r)
	return nil
}

func (l *memLog) Replace(ctx context.Context, kind byte, router netip.Addr, session string, chunks [][]byte) error {
	l.mu.Lock()
	if l.fail {
		l.mu.Unlock()
		return io.ErrClosedPipe
	}
	// Drop the older records of the session (the purge); positions stay,
	// as JetStream sequences do.
	for i := range l.recs {
		if l.recs[i].Session == session {
			l.recs[i] = Record{}
		}
	}
	l.mu.Unlock()
	_ = l.Publish(ctx, Record{Kind: kind, Router: router, Session: session})
	for _, c := range chunks {
		_ = l.Publish(ctx, Record{Kind: RecSnapshot, Router: router, Session: session, Data: c})
	}
	return l.Publish(ctx, Record{Kind: RecSnapshotEnd, Router: router, Session: session})
}

func (l *memLog) replay(r *Replica, from int) int {
	l.mu.Lock()
	recs := slices.Clone(l.recs[from:])
	l.mu.Unlock()
	for _, rec := range recs {
		if rec.Kind != 0 {
			r.ApplyRecord(rec)
		}
	}
	return from + len(recs)
}

func newReplica() (*Replica, *RIB) {
	rib := NewRIB()
	return NewReplica(NewServer(Config{}, rib)), rib
}

// session runs a local session fed through a pipe.
func runSession(t *testing.T, s *Server) (*io.PipeWriter, chan struct{}) {
	t.Helper()
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.serve(pr, &session{info: Session{Router: router}})
	}()
	return pw, done
}

func routeOf(rib *RIB, rd uint64, a string) (Route, bool) {
	return rib.LookupRD(rd, netip.MustParseAddr(a))
}

func TestReplication(t *testing.T) {
	log := &memLog{}
	src := NewRIB()
	s := NewServer(Config{Replicator: log}, src)
	peer := netip.MustParseAddr("198.51.100.2")
	red := mustRD(t, "65000:1")
	w, done := runSession(t, s)
	write := func(ms ...[]byte) {
		t.Helper()
		if _, err := w.Write(concat(ms...)); err != nil {
			t.Fatal(err)
		}
	}
	// ADD-PATH on IPv4 unicast: the snapshot must encode path ids too.
	write(bmpMsg(MsgInitiation, concat([]byte{0, 2, 0, 3}, []byte("rt1"))),
		peerUp(peerHdr(peerGlobal, 0, peer, 64500),
			openMsg(65000, capAS4(65000), capAddPath(afiIPv4, safiUnicast, 1)),
			openMsg(64500, capAS4(64500), capAddPath(afiIPv4, safiUnicast, 2))))
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64500, 15169), attr(0x40, attrNextHop, []byte{198, 51, 100, 2}),
		attr(0xc0, attrLargeCommunities, []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2}))
	nl := concat([]byte{0, 0, 0, 1}, nlri("8.8.8.0/24"), []byte{0, 0, 0, 2}, nlri("8.0.0.0/9"))
	write(bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, attrs, nl))))
	// A VPN route without next hop.
	mp := concat(binary.BigEndian.AppendUint16(nil, afiIPv4), []byte{safiVPN, 8}, make([]byte, 8), []byte{0}, vpnNLRI(red, "10.1.0.0/16", false))
	vattrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64600), attr(0x80, attrMPReach, mp))
	write(bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, vattrs, nil))))

	// A replica following from the start sees the same routes.
	b, ribB := newReplica()
	wait := func(cond func() bool) {
		t.Helper()
		for i := 0; i < 300 && !cond(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !cond() {
			t.Fatal("timeout")
		}
	}
	pos := 0
	wait(func() bool {
		pos = log.replay(b, pos)
		_, ok := routeOf(ribB, red, "10.1.0.1")
		return ok
	})
	check := func(rib *RIB, name string) {
		t.Helper()
		r, ok := routeOf(rib, 0, "8.8.8.8")
		if !ok || r.Prefix.String() != "8.8.8.0/24" || !slices.Equal(r.ASPath, []uint32{64500, 15169}) || r.NextHop != peer ||
			!slices.Equal(r.LargeText, []string{"65000:1:2"}) || !r.Peer.Post || r.Peer.Router != router {
			t.Fatalf("%s: 8.8.8.8 → %+v %v", name, r, ok)
		}
		if r, ok := routeOf(rib, red, "10.1.0.1"); !ok || r.NextHop.IsValid() || r.OriginAS() != 64600 {
			t.Fatalf("%s: VPN → %+v %v", name, r, ok)
		}
		if st := rib.Stats(); st.Routes != 3 || st.Peers != 1 {
			t.Fatalf("%s: stats %+v", name, st)
		}
	}
	check(ribB, "follower")

	// Compaction: the history is replaced by a snapshot. The follower skips
	// it; a new replica rebuilds the same state from it.
	pubs := func() *publisher {
		s.pubMu.Lock()
		defer s.pubMu.Unlock()
		for p := range s.pubs {
			return p
		}
		return nil
	}
	p := pubs()
	if p == nil {
		t.Fatal("no publisher")
	}
	p.compact.Store(true)
	write(bmpMsg(MsgStatistics, make([]byte, perPeerHeaderLen+4)))
	wait(func() bool {
		log.mu.Lock()
		defer log.mu.Unlock()
		return log.recs[len(log.recs)-1].Kind == RecSnapshotEnd
	})
	log.mu.Lock()
	first := slices.IndexFunc(log.recs, func(r Record) bool { return r.Kind != 0 })
	if log.recs[first].Kind != RecCompact {
		t.Fatalf("first record after compaction: %d", log.recs[first].Kind)
	}
	log.mu.Unlock()
	pos = log.replay(b, pos)
	check(ribB, "follower after compaction")
	c, ribC := newReplica()
	posC := log.replay(c, 0)
	check(ribC, "replica from snapshot")

	// Live messages after the snapshot reach both (ADD-PATH caps restored
	// from the Peer Up in the snapshot).
	write(bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(concat([]byte{0, 0, 0, 1}, nlri("8.8.8.0/24")), nil, nil))))
	wait(func() bool {
		pos = log.replay(b, pos)
		r, _ := routeOf(ribB, 0, "8.8.8.8")
		return r.Prefix.String() == "8.0.0.0/9"
	})
	log.replay(c, posC)
	if r, _ := routeOf(ribC, 0, "8.8.8.8"); r.Prefix.String() != "8.0.0.0/9" {
		t.Fatalf("replica C after withdraw: %v", r.Prefix)
	}

	// Lost records: the next flush sends a resync that every replica applies.
	log.mu.Lock()
	log.fail = true
	log.mu.Unlock()
	write(bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, flagL, peer, 64500), updateMsg(nil, attrs, concat([]byte{0, 0, 0, 3}, nlri("9.9.9.0/24"))))))
	wait(func() bool { _, ok := routeOf(src, 0, "9.9.9.9"); return ok })
	log.mu.Lock()
	log.fail = false
	log.mu.Unlock()
	write(bmpMsg(MsgStatistics, make([]byte, perPeerHeaderLen+4)))
	wait(func() bool {
		pos = log.replay(b, pos)
		_, ok := routeOf(ribB, 0, "9.9.9.9")
		return ok
	})

	// A local session of the router takes precedence: replica records of
	// that router are ignored and its replayed routes dropped.
	b.localStart(router)
	if _, ok := routeOf(ribB, 0, "9.9.9.9"); ok {
		t.Fatal("replayed routes kept during a local session")
	}
	b.localEnd(router)

	// Session end: routes go away on the replicas.
	_ = w.Close()
	<-done
	pos = log.replay(c, 0)
	if _, ok := routeOf(ribC, 0, "9.9.9.9"); ok || ribC.Stats().Peers != 0 {
		t.Fatalf("replica after session end: %+v", ribC.Stats())
	}
}

func TestReplicaExpire(t *testing.T) {
	r, rib := newReplica()
	old := time.Now().Add(-time.Hour)
	peer := netip.MustParseAddr("198.51.100.2")
	attrs := concat(attr(0x40, attrOrigin, []byte{0}), asPath4(64500), attr(0x40, attrNextHop, []byte{198, 51, 100, 2}))
	r.ApplyRecord(Record{Kind: RecStart, Router: router, Session: "a", Time: old})
	r.ApplyRecord(Record{Kind: RecMessages, Router: router, Session: "a", Time: old,
		Data: bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, peer, 64500), updateMsg(nil, attrs, nlri("1.1.1.0/24"))))})
	// Records of an unknown session are ignored.
	r.ApplyRecord(Record{Kind: RecMessages, Router: router, Session: "b", Time: old,
		Data: bmpMsg(MsgRouteMonitoring, concat(peerHdr(peerGlobal, 0, peer, 64500), updateMsg(nil, attrs, nlri("2.2.2.0/24"))))})
	if _, ok := routeOf(rib, 0, "1.1.1.1"); !ok {
		t.Fatal("no replayed route")
	}
	if _, ok := routeOf(rib, 0, "2.2.2.2"); ok {
		t.Fatal("route of an unknown session")
	}
	if rs := r.Routers(); len(rs) != 1 {
		t.Fatalf("routers %+v", rs)
	}
	exp := r.Expire(time.Now(), 3*HeartbeatInterval)
	if len(exp) != 1 || exp[0].Session != "a" {
		t.Fatalf("expired %+v", exp)
	}
	if _, ok := routeOf(rib, 0, "1.1.1.1"); ok {
		t.Fatal("route after expiry")
	}
}
