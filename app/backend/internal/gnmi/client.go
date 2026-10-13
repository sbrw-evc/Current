package gnmi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// query is one Get of the poll; only the first one must succeed (the others
// read optional leaves a device may not support).
type query struct {
	path     *gpb.Path
	required bool
}

func elem(name string, kv ...string) *gpb.PathElem {
	e := &gpb.PathElem{Name: name}
	if len(kv) == 2 {
		e.Key = map[string]string{kv[0]: kv[1]}
	}
	return e
}

// ifPath is /interfaces/interface[name=*]/<rest>.
func ifPath(rest ...string) *gpb.Path {
	p := &gpb.Path{Elem: []*gpb.PathElem{elem("interfaces"), elem("interface", "name", "*")}}
	for _, r := range rest {
		p.Elem = append(p.Elem, elem(r))
	}
	return p
}

// subPath is /interfaces/interface[name=*]/subinterfaces/subinterface[index=*]/state/<leaf>.
func subPath(leaf string) *gpb.Path {
	p := ifPath("subinterfaces")
	p.Elem = append(p.Elem, elem("subinterface", "index", "*"), elem("state"), elem(leaf))
	return p
}

var queries = []query{
	{ifPath("state", "ifindex"), true},
	{ifPath("state", "description"), false},
	{ifPath("ethernet", "state", "port-speed"), false},
	{ifPath("ethernet", "state", "negotiated-port-speed"), false},
	{ifPath("aggregation", "state", "lag-speed"), false},
	{subPath("ifindex"), false},
	{subPath("description"), false},
}

// Get reads the interfaces of a device once (the settings test).
func Get(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings) (map[uint32]Interface, error) {
	if s.TimeoutSeconds == 0 {
		s, _ = s.Normalize()
	}
	if p.Port == 0 {
		p.Port = DefaultPort
	}
	return getGNMI(ctx, a.Unmap(), p, c, s)
}

// dial builds the gRPC connection of a profile (no I/O until the first RPC).
func dial(a netip.Addr, p Profile, c Credentials) (*grpc.ClientConn, error) {
	tc := insecure.NewCredentials()
	if p.TLS {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: p.SkipVerify, ServerName: p.ServerName}
		if cfg.ServerName == "" {
			cfg.ServerName = a.String()
		}
		if strings.TrimSpace(c.CA) != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(c.CA)) {
				return nil, fmt.Errorf("profile %q: the CA certificate is not valid PEM", p.Name)
			}
			cfg.RootCAs = pool
		}
		if c.Cert != "" || c.Key != "" {
			cert, err := tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
			if err != nil {
				return nil, fmt.Errorf("profile %q: client certificate: %w", p.Name, err)
			}
			cfg.Certificates = []tls.Certificate{cert}
		}
		tc = credentials.NewTLS(cfg)
	}
	port := p.Port
	if port == 0 {
		port = DefaultPort
	}
	target := "passthrough:///" + net.JoinHostPort(a.String(), strconv.Itoa(int(port)))
	return grpc.NewClient(target, grpc.WithTransportCredentials(tc),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)))
}

// withAuth adds the username / password metadata of a profile.
func withAuth(ctx context.Context, p Profile, c Credentials) context.Context {
	if p.Username != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "username", p.Username, "password", c.Password)
	}
	return ctx
}

func encoding(p Profile) gpb.Encoding {
	if p.Encoding == EncodingJSON {
		return gpb.Encoding_JSON
	}
	return gpb.Encoding_JSON_IETF
}

func getGNMI(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings) (map[uint32]Interface, error) {
	conn, err := dial(a, p, c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cl := gpb.NewGNMIClient(conn)
	ctx = withAuth(ctx, p, c)
	enc := encoding(p)
	d := newDecoder()
	for i, q := range queries {
		resp, err := get(ctx, cl, q.path, enc, s)
		// A device without JSON_IETF support is asked again with JSON.
		if err != nil && i == 0 && enc == gpb.Encoding_JSON_IETF && encodingRejected(err) {
			enc = gpb.Encoding_JSON
			resp, err = get(ctx, cl, q.path, enc, s)
		}
		if err != nil {
			if q.required {
				return nil, grpcError(err)
			}
			continue
		}
		for _, n := range resp.GetNotification() {
			d.notification(n)
		}
	}
	ifs := d.interfaces()
	if len(ifs) == 0 {
		return nil, errors.New("the device returned no interfaces with an ifindex")
	}
	return ifs, nil
}

// ErrSubscribeUnsupported: the device refused the Subscribe RPC or its
// subscription list; the poller reads it with Get instead.
var ErrSubscribeUnsupported = errors.New("the device does not support gNMI Subscribe for these paths")

// subscribeGNMI keeps a Subscribe stream (STREAM mode, TARGET_DEFINED
// subscriptions of the polled leaves) open until ctx ends or the stream
// fails. update receives the whole interface table once the device has sent
// its initial state (sync_response), then after every batch of changes.
func subscribeGNMI(ctx context.Context, a netip.Addr, p Profile, c Credentials, s Settings, update func(map[uint32]Interface)) error {
	conn, err := dial(a, p, c)
	if err != nil {
		return err
	}
	defer conn.Close()
	cl := gpb.NewGNMIClient(conn)
	ctx = withAuth(ctx, p, c)
	enc := encoding(p)
	for {
		err := subscribeOnce(ctx, cl, enc, s, update)
		// A device without JSON_IETF support is asked again with JSON.
		if errors.Is(err, errEncoding) && enc == gpb.Encoding_JSON_IETF {
			enc = gpb.Encoding_JSON
			continue
		}
		if errors.Is(err, errEncoding) {
			return fmt.Errorf("%w (%v)", ErrSubscribeUnsupported, errors.Unwrap(err))
		}
		return err
	}
}

// errEncoding wraps a rejection of the subscription before any data.
var errEncoding = errors.New("subscription rejected")

func subscribeOnce(ctx context.Context, cl gpb.GNMIClient, enc gpb.Encoding, s Settings, update func(map[uint32]Interface)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := cl.Subscribe(ctx)
	if err != nil {
		return grpcError(err)
	}
	list := &gpb.SubscriptionList{Mode: gpb.SubscriptionList_STREAM, Encoding: enc}
	for _, q := range queries {
		list.Subscription = append(list.Subscription, &gpb.Subscription{Path: q.path, Mode: gpb.SubscriptionMode_TARGET_DEFINED})
	}
	if err := st.Send(&gpb.SubscribeRequest{Request: &gpb.SubscribeRequest_Subscribe{Subscribe: list}}); err != nil {
		return grpcError(err)
	}
	type recv struct {
		r   *gpb.SubscribeResponse
		err error
	}
	ch := make(chan recv, 64)
	go func() {
		for {
			r, err := st.Recv()
			select {
			case ch <- recv{r, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	d := newDecoder()
	synced, got := false, false
	// A device that never sends sync_response is taken as synced after a while.
	syncWait := time.NewTimer(3 * s.timeout())
	defer syncWait.Stop()
	publish := func() error {
		ifs := d.interfaces()
		if len(ifs) == 0 {
			return errors.New("the device returned no interfaces with an ifindex")
		}
		update(ifs)
		return nil
	}
	handle := func(x recv) (bool, error) {
		if x.err != nil {
			if errors.Is(x.err, io.EOF) {
				return false, errors.New("the device closed the subscription")
			}
			if !got {
				switch status.Code(x.err) {
				case codes.Unimplemented:
					return false, fmt.Errorf("%w: %w", ErrSubscribeUnsupported, grpcError(x.err))
				case codes.InvalidArgument:
					return false, fmt.Errorf("%w: %w", errEncoding, grpcError(x.err))
				}
			}
			return false, grpcError(x.err)
		}
		got = true
		switch r := x.r.GetResponse().(type) {
		case *gpb.SubscribeResponse_Update:
			d.notification(r.Update)
			return synced, nil
		case *gpb.SubscribeResponse_SyncResponse:
			synced = true
			return true, nil
		}
		return false, nil
	}
	for {
		var changed bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncWait.C:
			if !synced {
				synced, changed = true, true
			}
		case x := <-ch:
			c, err := handle(x)
			if err != nil {
				return err
			}
			changed = c
			// Coalesce what is already queued into one table update.
			for drained := false; !drained; {
				select {
				case x := <-ch:
					c, err := handle(x)
					if err != nil {
						return err
					}
					changed = changed || c
				default:
					drained = true
				}
			}
		}
		if changed && synced {
			if err := publish(); err != nil {
				return err
			}
		}
	}
}

func get(ctx context.Context, cl gpb.GNMIClient, path *gpb.Path, enc gpb.Encoding, s Settings) (*gpb.GetResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	return cl.Get(ctx, &gpb.GetRequest{Path: []*gpb.Path{path}, Encoding: enc})
}

func encodingRejected(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.Unimplemented:
		return true
	}
	return false
}

// grpcError shortens a gRPC status error to "<code>: <message>".
func grpcError(err error) error {
	if st, ok := status.FromError(err); ok {
		return fmt.Errorf("%s: %s", st.Code(), st.Message())
	}
	return err
}

// ---- decoding

// rowKey is an interface (sub = -1) or one of its subinterfaces.
type rowKey struct {
	name string
	sub  int64
}

type row struct {
	ifindex                     uint32
	hasIndex                    bool
	descr                       string
	portSpeed, negSpeed, lagMbs uint64
}

// decoder collects the leaves of Get notifications, whether a device sends
// one typed value per leaf or JSON blobs of whole containers.
type decoder struct{ rows map[rowKey]*row }

func newDecoder() *decoder { return &decoder{rows: map[rowKey]*row{}} }

func (d *decoder) notification(n *gpb.Notification) {
	for _, p := range n.GetDelete() {
		d.remove(append(append([]*gpb.PathElem{}, n.GetPrefix().GetElem()...), p.GetElem()...))
	}
	for _, u := range n.GetUpdate() {
		elems := append(append([]*gpb.PathElem{}, n.GetPrefix().GetElem()...), u.GetPath().GetElem()...)
		v, err := typedValue(u.GetVal())
		if err != nil {
			continue
		}
		d.walk(elems, v)
	}
}

func typedValue(tv *gpb.TypedValue) (any, error) {
	decode := func(b []byte) (any, error) {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var v any
		err := dec.Decode(&v)
		return v, err
	}
	switch v := tv.GetValue().(type) {
	case *gpb.TypedValue_JsonIetfVal:
		return decode(v.JsonIetfVal)
	case *gpb.TypedValue_JsonVal:
		return decode(v.JsonVal)
	case *gpb.TypedValue_UintVal:
		return v.UintVal, nil
	case *gpb.TypedValue_IntVal:
		return v.IntVal, nil
	case *gpb.TypedValue_StringVal:
		return v.StringVal, nil
	case *gpb.TypedValue_AsciiVal:
		return v.AsciiVal, nil
	}
	return nil, errors.New("unsupported value type")
}

// local strips the YANG module prefix of a JSON_IETF member or identity.
func local(s string) string {
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// listKeys are the keys of the lists walked in JSON blobs.
var listKeys = map[string]string{"interface": "name", "subinterface": "index"}

func (d *decoder) walk(elems []*gpb.PathElem, v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			k = local(k)
			if key, ok := listKeys[k]; ok {
				if arr, ok := c.([]any); ok {
					for _, e := range arr {
						m, ok := e.(map[string]any)
						if !ok {
							continue
						}
						kv := scalarText(m[key])
						if kv == "" {
							continue
						}
						d.walk(appendElem(elems, elem(k, key, kv)), m)
					}
					continue
				}
			}
			// A leaf sent as {"module:leaf": value} under its own path.
			if len(elems) > 0 && local(elems[len(elems)-1].GetName()) == k && len(elems[len(elems)-1].GetKey()) == 0 {
				d.walk(elems, c)
				continue
			}
			d.walk(appendElem(elems, elem(k)), c)
		}
	case []any: // leaf-lists: none of the leaves read
	default:
		d.leaf(elems, x)
	}
}

func appendElem(elems []*gpb.PathElem, e *gpb.PathElem) []*gpb.PathElem {
	return append(append(make([]*gpb.PathElem, 0, len(elems)+1), elems...), e)
}

// locate splits a full path into its interface row and the path below it;
// ok is false for paths outside one named interface.
func locate(elems []*gpb.PathElem) (key rowKey, rest []string, ok bool) {
	key = rowKey{sub: -1}
	i := -1
	for j, e := range elems {
		if local(e.GetName()) == "interface" && e.GetKey()["name"] != "" {
			key.name, i = e.GetKey()["name"], j
		}
	}
	if i < 0 || key.name == "*" {
		return key, nil, false
	}
	rest = make([]string, 0, len(elems)-i)
	for j := i + 1; j < len(elems); j++ {
		n := local(elems[j].GetName())
		if n == "subinterface" {
			idx, err := strconv.ParseInt(elems[j].GetKey()["index"], 10, 64)
			if err != nil || idx < 0 {
				return key, nil, false
			}
			key.sub, rest = idx, rest[:0]
			continue
		}
		rest = append(rest, n)
	}
	return key, rest, true
}

// leaf records a scalar at a full path (nil clears it).
func (d *decoder) leaf(elems []*gpb.PathElem, v any) {
	key, rest, ok := locate(elems)
	if !ok {
		return
	}
	r := d.rows[key]
	if r == nil {
		if v == nil {
			return
		}
		r = &row{}
		d.rows[key] = r
	}
	switch strings.Join(rest, "/") {
	case "state/ifindex":
		r.hasIndex = false
		if n, ok := scalarUint(v); ok && n > 0 && n <= 0xffffffff {
			r.ifindex, r.hasIndex = uint32(n), true
		}
	case "state/description":
		r.descr = scalarText(v)
	case "ethernet/state/port-speed":
		r.portSpeed = SpeedBits(scalarText(v))
	case "ethernet/state/negotiated-port-speed":
		r.negSpeed = SpeedBits(scalarText(v))
	case "aggregation/state/lag-speed":
		r.lagMbs, _ = scalarUint(v)
	}
}

// leafPaths are the leaves read below an interface or subinterface row.
var leafPaths = [][]string{
	{"state", "ifindex"}, {"state", "description"}, {"ethernet", "state", "port-speed"},
	{"ethernet", "state", "negotiated-port-speed"}, {"aggregation", "state", "lag-speed"},
}

// remove applies a Subscribe delete: a whole interface (with its
// subinterfaces), a subinterface, or the leaves below a container.
func (d *decoder) remove(elems []*gpb.PathElem) {
	key, rest, ok := locate(elems)
	if !ok {
		// The whole interface list (or more) is gone.
		if len(elems) <= 2 && (len(elems) == 0 || local(elems[0].GetName()) == "interfaces") {
			clear(d.rows)
		}
		return
	}
	if len(rest) == 1 && rest[0] == "subinterfaces" && key.sub < 0 {
		for k := range d.rows {
			if k.name == key.name && k.sub >= 0 {
				delete(d.rows, k)
			}
		}
		return
	}
	if len(rest) == 0 {
		for k := range d.rows {
			if k.name == key.name && (key.sub < 0 || k.sub == key.sub) {
				delete(d.rows, k)
			}
		}
		return
	}
	base := elems[:len(elems)-len(rest)]
	for _, lp := range leafPaths {
		if len(lp) >= len(rest) && slices.Equal(lp[:len(rest)], rest) {
			full := append([]*gpb.PathElem{}, base...)
			for _, n := range lp {
				full = append(full, elem(n))
			}
			d.leaf(full, nil)
		}
	}
}

// interfaces returns the decoded interfaces by ifindex; a subinterface is
// named "<interface>.<index>" and takes the speed of its interface.
func (d *decoder) interfaces() map[uint32]Interface {
	speed := func(r *row) uint64 {
		switch {
		case r.negSpeed > 0:
			return r.negSpeed
		case r.portSpeed > 0:
			return r.portSpeed
		}
		return r.lagMbs * 1_000_000
	}
	out := map[uint32]Interface{}
	for k, r := range d.rows {
		if !r.hasIndex {
			continue
		}
		it := Interface{Name: k.name, Descr: r.descr}
		if k.sub >= 0 {
			it.Name = k.name + "." + strconv.FormatInt(k.sub, 10)
			if parent := d.rows[rowKey{name: k.name, sub: -1}]; parent != nil {
				it.Speed = speed(parent)
			}
			// Several devices give subinterface 0 the ifindex of its interface: keep the interface.
			if _, dup := out[r.ifindex]; dup {
				continue
			}
		} else {
			it.Speed = speed(r)
		}
		out[r.ifindex] = it
	}
	return out
}

func scalarText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case uint64:
		return strconv.FormatUint(x, 10)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return ""
}

// scalarUint reads a number (JSON_IETF sends 64-bit integers as strings).
func scalarUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		return uint64(x), x >= 0
	case json.Number, string:
		n, err := strconv.ParseUint(scalarText(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

var speedRe = regexp.MustCompile(`^SPEED_(\d+(?:\.\d+)?)(MB|GB|TB)$`)

// SpeedBits maps an OpenConfig ETHERNET_SPEED identity (SPEED_10MB …
// SPEED_800GB, with or without its module prefix) to bits per second;
// SPEED_UNKNOWN and unknown names give 0.
func SpeedBits(identity string) uint64 {
	m := speedRe.FindStringSubmatch(local(strings.TrimSpace(identity)))
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	mult := map[string]float64{"MB": 1e6, "GB": 1e9, "TB": 1e12}[m[2]]
	return uint64(f*mult + 0.5)
}
