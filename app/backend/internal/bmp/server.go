// Package bmp is a BGP Monitoring Protocol receiver (RFC 7854): routers
// connect over TCP and stream the Adj-RIB-In of their BGP peers (route
// monitoring with BGP UPDATEs, peer up / down). The routes are kept in a
// compact longest-prefix-match table (RIB) with AS path, communities, large
// communities and next hop, which the enricher uses to fill DstASPath,
// DstCommunities, DstLargeCommunities and, as the "routing" AS provider,
// SrcAS / DstAS.
//
// The BGP decoder is written from the RFCs (4271, 4760, 6793, 7911, 1997,
// 8092, 9069, 4364, 4659, 8671, 8277, 7432, 9136): unicast, labeled unicast
// and L3VPN IPv4 / IPv6 and the IP routes of EVPN; other address families
// are skipped.
//
// With several enricher processes, sessions are replicated (replica.go):
// each process replays the sessions of the others into its own RIB.
package bmp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Policies select which Adj-RIB-In is used.
const (
	PolicyPreferPost = "prefer-post" // both, post-policy routes win (default)
	PolicyPost       = "post"        // post-policy (and Loc-RIB) only
	PolicyPre        = "pre"         // pre-policy only
)

// DefaultListen is the BMP port of Flow (10179/tcp); routers usually allow
// any port.
const DefaultListen = ":10179"

// DefaultMaxMessage bounds one BMP message (BGP extended messages are 64 KiB).
const DefaultMaxMessage = 1 << 20

// Settings are the BMP settings (PostgreSQL settings key "bmp").
type Settings struct {
	Enabled bool   `json:"enabled"`
	Policy  string `json:"policy"`
	// Routers are the addresses / CIDRs allowed to connect; empty = any.
	Routers []string `json:"routers"`
	// ASProviders is the AS provider order of the enricher while BMP is
	// enabled (default routing, flow, geoip).
	ASProviders []string `json:"as_providers"`
}

// DefaultASProviders is the AS order applied while BMP is enabled.
var DefaultASProviders = []string{"routing", "flow", "geoip"}

// Normalize fills defaults and validates.
func (s Settings) Normalize() (Settings, error) {
	switch s.Policy {
	case "":
		s.Policy = PolicyPreferPost
	case PolicyPreferPost, PolicyPost, PolicyPre:
	default:
		return s, fmt.Errorf("policy must be %s, %s or %s", PolicyPreferPost, PolicyPost, PolicyPre)
	}
	if s.Routers == nil {
		s.Routers = []string{}
	}
	if _, err := ParseRouters(s.Routers); err != nil {
		return s, err
	}
	if len(s.ASProviders) == 0 {
		s.ASProviders = slices.Clone(DefaultASProviders)
	}
	seen := map[string]bool{}
	for _, p := range s.ASProviders {
		switch p {
		case "routing", "flow", "flow-except-private", "geoip":
		default:
			return s, fmt.Errorf("unknown AS provider %q", p)
		}
		if seen[p] {
			return s, fmt.Errorf("AS provider %q is listed twice", p)
		}
		seen[p] = true
	}
	return s, nil
}

// ParseRouters parses addresses and prefixes.
func ParseRouters(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("router %q is not an address or prefix", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Metrics of the receiver and the RIB; create them once per process.
type Metrics struct {
	messages   *prometheus.CounterVec
	errors     *prometheus.CounterVec
	skipped    *prometheus.CounterVec
	replicated *prometheus.CounterVec
	sessions   prometheus.Gauge
}

// NewMetrics registers the BMP metrics (reg may be nil).
func NewMetrics(reg prometheus.Registerer, rib *RIB) (*Metrics, error) {
	m := &Metrics{
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "bmp", Name: "messages_total",
			Help: "BMP messages received by type."}, []string{"type"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "bmp", Name: "errors_total",
			Help: "BMP decoding errors and rejected connections."}, []string{"kind"}),
		skipped: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "bmp", Name: "skipped_total",
			Help: "Route Monitoring messages not added to the RIB: Adj-RIB-Out, or excluded by the policy setting."}, []string{"reason"}),
		replicated: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "flow", Subsystem: "bmp", Name: "replication_records_total",
			Help: "Replication records published for local sessions (out) and replayed from other processes (in)."}, []string{"direction"}),
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "flow", Subsystem: "bmp", Name: "sessions",
			Help: "Connected BMP routers."}),
	}
	if reg == nil {
		return m, nil
	}
	stat := func(name, help string, f func(Stats) float64) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "flow", Subsystem: "bmp", Name: name, Help: help},
			func() float64 { return f(rib.Stats()) })
	}
	cs := []prometheus.Collector{m.messages, m.errors, m.skipped, m.replicated, m.sessions,
		stat("prefixes_v4", "IPv4 prefixes in the RIB.", func(s Stats) float64 { return float64(s.PrefixesV4) }),
		stat("prefixes_v6", "IPv6 prefixes in the RIB.", func(s Stats) float64 { return float64(s.PrefixesV6) }),
		stat("routes", "Routes in the RIB (prefixes × peers).", func(s Stats) float64 { return float64(s.Routes) }),
		stat("vpn_prefixes", "L3VPN prefixes in the RIB (all route distinguishers).", func(s Stats) float64 { return float64(s.VPNPrefixes) }),
		stat("vrfs", "Route distinguishers with routes in the RIB.", func(s Stats) float64 { return float64(s.VRFs) }),
		stat("peers", "BGP peers with an Adj-RIB-In.", func(s Stats) float64 { return float64(s.Peers) }),
		stat("attribute_sets", "Distinct interned path attribute sets.", func(s Stats) float64 { return float64(s.AttrSets) }),
		stat("rib_bytes", "Estimated memory held by the RIB.", func(s Stats) float64 { return float64(s.Bytes) }),
	}
	for _, c := range cs {
		if err := reg.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) {
				return nil, err
			}
		}
	}
	return m, nil
}

// Config of the receiver.
type Config struct {
	Listen     string // default DefaultListen
	MaxMessage int    // default DefaultMaxMessage
	Logger     *slog.Logger
	Metrics    *Metrics // nil: not counted
	// Replicator publishes the local sessions for the other processes;
	// nil: no replication.
	Replicator Replicator
	// Replica replays the sessions of other processes into the same RIB;
	// local sessions of a router take precedence over it.
	Replica *Replica
}

type options struct {
	policy  string
	routers []netip.Prefix
}

// Session describes a connected router for the status API.
type Session struct {
	Router    netip.Addr `json:"router"`
	SysName   string     `json:"sys_name,omitempty"`
	SysDescr  string     `json:"sys_descr,omitempty"`
	Since     time.Time  `json:"since"`
	PeersUp   int        `json:"peers_up"`
	Messages  uint64     `json:"messages"`
	Errors    uint64     `json:"errors"`
	LastError string     `json:"last_error,omitempty"`
}

type session struct {
	mu   sync.Mutex
	info Session
	conn net.Conn
}

// Server accepts BMP sessions and feeds the RIB.
type Server struct {
	cfg  Config
	rib  *RIB
	log  *slog.Logger
	m    *Metrics
	opts atomic.Pointer[options]

	ln       net.Listener
	mu       sync.Mutex
	sessions map[*session]struct{}
	wg       sync.WaitGroup
	pubSet
}

// NewServer returns a server feeding rib; Listen binds it.
func NewServer(cfg Config, rib *RIB) *Server {
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.MaxMessage <= 0 {
		cfg.MaxMessage = DefaultMaxMessage
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	m := cfg.Metrics
	if m == nil {
		m, _ = NewMetrics(nil, rib)
	}
	s := &Server{cfg: cfg, rib: rib, log: log.With("component", "bmp"), m: m, sessions: map[*session]struct{}{},
		pubSet: pubSet{pubs: map[*publisher]struct{}{}}}
	s.opts.Store(&options{policy: PolicyPreferPost})
	return s
}

// Apply sets the policy and the allowed routers (from Settings).
func (s *Server) Apply(st Settings) error {
	st, err := st.Normalize()
	if err != nil {
		return err
	}
	rs, _ := ParseRouters(st.Routers)
	s.opts.Store(&options{policy: st.Policy, routers: rs})
	return nil
}

// Listen binds the TCP listener.
func (s *Server) Listen() error {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(context.Background(), "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("bmp: listen %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	return nil
}

// Addr is the bound address (nil before Listen).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Run accepts sessions until ctx ends, then closes them; the routes of a
// closed session are removed.
func (s *Server) Run(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	if s.cfg.Replicator != nil {
		go s.heartbeats(ctx)
	}
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
		s.mu.Lock()
		for ss := range s.sessions {
			_ = ss.conn.Close()
		}
		s.mu.Unlock()
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			s.log.Warn("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		router := addrOf(c.RemoteAddr())
		if !s.allowed(router) {
			s.m.errors.WithLabelValues("rejected").Inc()
			s.log.Warn("BMP connection from a router not in the allowed list", "router", router)
			_ = c.Close()
			continue
		}
		ss := &session{conn: c, info: Session{Router: router, Since: time.Now()}}
		s.mu.Lock()
		s.sessions[ss] = struct{}{}
		s.mu.Unlock()
		s.m.sessions.Inc()
		s.wg.Go(func() {
			if s.cfg.Replica != nil {
				s.cfg.Replica.localStart(router)
				defer s.cfg.Replica.localEnd(router)
			}
			defer func() {
				_ = c.Close()
				s.mu.Lock()
				delete(s.sessions, ss)
				s.mu.Unlock()
				s.m.sessions.Dec()
				n := s.rib.RemoveRouter(router)
				s.log.Info("BMP session closed", "router", router, "peers_removed", n)
			}()
			s.log.Info("BMP session opened", "router", router)
			if err := s.serve(c, ss); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Warn("BMP session ended", "router", router, "err", err)
			}
		})
	}
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(ta.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *Server) allowed(a netip.Addr) bool {
	o := s.opts.Load()
	if len(o.routers) == 0 {
		return true
	}
	for _, p := range o.routers {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Sessions lists the connected routers.
func (s *Server) Sessions() []Session {
	s.mu.Lock()
	out := make([]Session, 0, len(s.sessions))
	for ss := range s.sessions {
		ss.mu.Lock()
		out = append(out, ss.info)
		ss.mu.Unlock()
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b Session) int { return a.Router.Compare(b.Router) })
	return out
}

// serve reads the messages of one session.
func (s *Server) serve(r io.Reader, ss *session) error {
	br := bufio.NewReaderSize(r, 64<<10)
	st := &sessionState{router: ss.info.Router, caps: map[PeerKey]*sessionCaps{}, peerUps: map[PeerKey][]byte{}}
	pub := s.startPublisher(st)
	if pub != nil {
		defer pub.end()
	}
	hdr := make([]byte, commonHeaderLen)
	buf := make([]byte, 0, 4096)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return err
		}
		typ, length, err := parseCommonHeader(hdr)
		if err != nil {
			s.m.errors.WithLabelValues("framing").Inc()
			return err
		}
		if length > s.cfg.MaxMessage {
			s.m.errors.WithLabelValues("framing").Inc()
			return fmt.Errorf("BMP message of %d bytes exceeds the limit of %d", length, s.cfg.MaxMessage)
		}
		if cap(buf) < length-commonHeaderLen {
			buf = make([]byte, length-commonHeaderLen)
		}
		body := buf[:length-commonHeaderLen]
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
		s.m.messages.WithLabelValues(msgName(typ)).Inc()
		done, err := s.handle(st, typ, body)
		if pub != nil {
			pub.add(typ, hdr, body)
			// Publish when the next read would wait (or the batch is
			// large), so that replicas lag by one round trip at most.
			if br.Buffered() == 0 || len(pub.batch) >= publishBatch || done {
				pub.flush()
			}
		}
		ss.mu.Lock()
		ss.info.Messages++
		ss.info.PeersUp = len(st.caps)
		if st.sysName != "" {
			ss.info.SysName, ss.info.SysDescr = st.sysName, st.sysDescr
		}
		if err != nil {
			ss.info.Errors++
			ss.info.LastError = err.Error()
		}
		ss.mu.Unlock()
		if err != nil {
			s.m.errors.WithLabelValues("decode").Inc()
			s.log.Debug("BMP message not decoded", "router", st.router, "type", msgName(typ), "err", err)
		}
		if done {
			return nil
		}
	}
}

// sessionState is the decoding state of one router connection.
type sessionState struct {
	router            netip.Addr
	caps              map[PeerKey]*sessionCaps // by peer (Post false)
	sysName, sysDescr string
	// Raw Initiation and Peer Up messages for replication snapshots
	// (local sessions with a Replicator only).
	init    []byte
	peerUps map[PeerKey][]byte
}

// handle processes one message body; done ends the session (Termination).
func (s *Server) handle(st *sessionState, typ byte, body []byte) (done bool, err error) {
	switch typ {
	case MsgInitiation:
		tlv := parseTLVs(body)
		st.sysName, st.sysDescr = tlv[2], tlv[1]
		return false, nil
	case MsgTermination:
		return true, nil
	case MsgStatistics, MsgRouteMirroring:
		return false, nil
	}
	h, rest, err := parsePeerHeader(body)
	if err != nil {
		return false, err
	}
	k := h.key(st.router)
	base := k
	base.Post = false
	switch typ {
	case MsgPeerUp:
		caps, err := parsePeerUp(rest)
		if err != nil {
			st.caps[base] = &sessionCaps{}
			return false, err
		}
		st.caps[base] = caps
	case MsgPeerDown:
		delete(st.caps, base)
		s.rib.RemovePeer(k)
	case MsgRouteMonitoring:
		// Adj-RIB-Out describes what the router sends, not where traffic
		// goes; mixing it with Adj-RIB-In would invent paths.
		if h.out() {
			s.m.skipped.WithLabelValues("adj_rib_out").Inc()
			return false, nil
		}
		o := s.opts.Load()
		if (o.policy == PolicyPost && !h.post()) || (o.policy == PolicyPre && h.post()) {
			s.m.skipped.WithLabelValues("policy").Inc()
			return false, nil
		}
		bt, ub, _, err := bgpMessage(rest)
		if err != nil {
			return false, err
		}
		if bt != bgpUpdate {
			return false, fmt.Errorf("route monitoring carries BGP message type %d", bt)
		}
		u, err := parseUpdate(ub, h.as4(), st.caps[base])
		if err != nil {
			return false, err
		}
		s.rib.apply(k, h.rd, u)
	}
	return false, nil
}
