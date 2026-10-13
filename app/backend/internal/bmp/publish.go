package bmp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

const (
	publishBatch    = 256 << 10 // bytes of BMP messages per record
	publishTimeout  = 30 * time.Second
	resyncInterval  = 10 * time.Second // between snapshot attempts after a failure
	compactMinBytes = 64 << 20         // history allowed before the first compaction
	// HeartbeatInterval is how often a session is announced alive; replicas
	// expire a router after a few missed heartbeats.
	HeartbeatInterval = 30 * time.Second
)

// publisher replicates one local session.
type publisher struct {
	s       *Server
	st      *sessionState
	id      string
	batch   []byte
	since   int  // bytes published since the last snapshot
	snap    int  // size of the last snapshot
	dirty   bool // records were lost: the next flush sends a resync
	lastTry time.Time
	// compact requests a compaction at the next flush (tests).
	compact atomic.Bool
}

func newSessionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) startPublisher(st *sessionState) *publisher {
	if s.cfg.Replicator == nil {
		return nil
	}
	p := &publisher{s: s, st: st, id: newSessionID()}
	if err := p.publish(Record{Kind: RecStart}); err != nil {
		p.dirty = true
	}
	s.pubMu.Lock()
	s.pubs[p] = struct{}{}
	s.pubMu.Unlock()
	return p
}

func (p *publisher) publish(r Record) error {
	r.Router, r.Session = p.st.router, p.id
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	err := p.s.cfg.Replicator.Publish(ctx, r)
	if err != nil {
		p.s.m.errors.WithLabelValues("replication").Inc()
		p.s.log.Debug("BMP replication record not published", "router", p.st.router, "err", err)
		return err
	}
	p.s.m.replicated.WithLabelValues("out").Inc()
	return nil
}

// add queues a message (common header + body) and keeps what a snapshot
// needs: the Initiation and Peer Up messages.
func (p *publisher) add(typ byte, hdr, body []byte) {
	start := len(p.batch)
	p.batch = append(p.batch, hdr...)
	p.batch = append(p.batch, body...)
	switch typ {
	case MsgInitiation:
		p.st.init = append([]byte(nil), p.batch[start:]...)
	case MsgPeerUp, MsgPeerDown:
		h, _, err := parsePeerHeader(body)
		if err != nil {
			return
		}
		k := h.key(p.st.router)
		k.Post = false
		if typ == MsgPeerUp {
			p.st.peerUps[k] = append([]byte(nil), p.batch[start:]...)
		} else {
			delete(p.st.peerUps, k)
		}
	}
}

// flush publishes the queued messages, a resync snapshot after lost
// records, or a compaction once the history outgrows the state.
func (p *publisher) flush() {
	if p.dirty {
		p.batch = p.batch[:0]
		if time.Since(p.lastTry) < resyncInterval {
			return
		}
		p.lastTry = time.Now()
		p.replace(RecResync)
		return
	}
	if len(p.batch) == 0 {
		return
	}
	if err := p.publish(Record{Kind: RecMessages, Data: p.batch}); err != nil {
		p.dirty = true
	}
	p.since += len(p.batch)
	p.batch = p.batch[:0]
	if !p.dirty && (p.since > compactMinBytes+2*p.snap || p.compact.Swap(false)) {
		p.replace(RecCompact)
	}
}

func (p *publisher) replace(kind byte) {
	chunks := p.s.snapshot(p.st)
	ctx, cancel := context.WithTimeout(context.Background(), 4*publishTimeout)
	defer cancel()
	if err := p.s.cfg.Replicator.Replace(ctx, kind, p.st.router, p.id, chunks); err != nil {
		p.s.m.errors.WithLabelValues("replication").Inc()
		p.s.log.Warn("BMP replication snapshot not published", "router", p.st.router, "err", err)
		p.dirty = true
		return
	}
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	p.s.m.replicated.WithLabelValues("out").Add(float64(len(chunks) + 2))
	p.dirty, p.since, p.snap = false, 0, n
}

func (p *publisher) end() {
	p.s.pubMu.Lock()
	delete(p.s.pubs, p)
	p.s.pubMu.Unlock()
	_ = p.publish(Record{Kind: RecEnd})
}

// heartbeats announces the local sessions alive until ctx ends.
func (s *Server) heartbeats(ctx context.Context) {
	t := time.NewTicker(HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.pubMu.Lock()
		ps := make([]*publisher, 0, len(s.pubs))
		for p := range s.pubs {
			ps = append(ps, p)
		}
		s.pubMu.Unlock()
		for _, p := range ps {
			_ = p.publish(Record{Kind: RecHeartbeat})
		}
	}
}

// pubSet is the set of replicated local sessions.
type pubSet struct {
	pubMu sync.Mutex
	pubs  map[*publisher]struct{}
}
