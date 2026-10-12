// Package collector receives NetFlow v5/v9, IPFIX and sFlow v5 datagrams over
// UDP, decodes them into flow.Flow records and hands batches to a flow.Sink.
//
// Besides flows it learns, per exporter, sampling rates (packet headers,
// sampler option data) and interface names / descriptions / speeds (option
// data, sFlow counter samples), and keeps a small registry of exporters.
package collector

import (
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config configures a Collector. Zero values are replaced by defaults (see
// withDefaults); an empty listen address disables that listener.
type Config struct {
	// NetFlowListen is the UDP address for NetFlow v5/v9 and IPFIX
	// (auto-detected per datagram), e.g. ":2055". Empty disables it.
	NetFlowListen string
	// SFlowListen is the UDP address for sFlow v5, e.g. ":6343". Empty
	// disables it.
	SFlowListen string
	// Sockets is the number of SO_REUSEPORT sockets per listener, each with
	// its own reader goroutine (Linux only; elsewhere it is forced to 1).
	Sockets int
	// ReadBuffer is the requested SO_RCVBUF size in bytes.
	ReadBuffer int
	// Workers is the number of decoding goroutines shared by all listeners.
	// Datagrams of one exporter always go to the same worker, so templates
	// and options are applied in arrival order.
	Workers int
	// QueueSize is the number of datagrams buffered per worker; datagrams
	// beyond it are dropped and counted.
	QueueSize int

	// DefaultSamplingRate is used when an exporter does not report a rate.
	DefaultSamplingRate uint64
	// SamplingOverrides force the sampling rate of exporters in a prefix
	// (longest prefix wins), whatever they report; an override naming an
	// interface (IfIndex or IfName) applies to the flows of that interface
	// only and wins over the exporter-wide ones.
	SamplingOverrides []SamplingOverride

	// BatchSize is the maximum number of flows handed to the sink at once.
	BatchSize int
	// FlushInterval bounds how long a decoded flow waits for its batch.
	FlushInterval time.Duration
	// ShutdownTimeout bounds the final flush to the sink on shutdown.
	ShutdownTimeout time.Duration
	// InterfaceTTL is how long learned interface names are kept without
	// being refreshed by the exporter.
	InterfaceTTL time.Duration
}

// SamplingOverride forces the sampling rate for exporters within Prefix.
// With IfIndex (≠ 0) or IfName set it applies only to flows whose input
// interface (else output interface) is that one; IfName is matched against
// the interface names the collector learns from the exporter (option data,
// sFlow counters), case-insensitively.
type SamplingOverride struct {
	Prefix  netip.Prefix
	IfIndex uint32
	IfName  string
	Rate    uint64
}

// perInterface reports whether the override names an interface.
func (o SamplingOverride) perInterface() bool { return o.IfIndex != 0 || o.IfName != "" }

// String formats the override in the ParseSamplingOverrides syntax.
func (o SamplingOverride) String() string {
	s := o.Prefix.String()
	if o.Prefix.IsSingleIP() {
		s = o.Prefix.Addr().String()
	}
	switch {
	case o.IfIndex != 0:
		s += "@" + strconv.FormatUint(uint64(o.IfIndex), 10)
	case o.IfName != "":
		s += "@" + o.IfName
	}
	return s + "=" + strconv.FormatUint(o.Rate, 10)
}

// DefaultConfig returns a configuration listening on the standard ports.
func DefaultConfig() Config {
	return Config{NetFlowListen: ":2055", SFlowListen: ":6343"}.withDefaults()
}

func (c Config) withDefaults() Config {
	if c.Sockets <= 0 {
		c.Sockets = 1
	}
	if c.ReadBuffer <= 0 {
		c.ReadBuffer = 8 << 20
	}
	if c.Workers <= 0 {
		c.Workers = runtime.GOMAXPROCS(0)
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 4096
	}
	if c.DefaultSamplingRate == 0 {
		c.DefaultSamplingRate = 1
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 2000
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 500 * time.Millisecond
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 5 * time.Second
	}
	if c.InterfaceTTL <= 0 {
		c.InterfaceTTL = 24 * time.Hour
	}
	// longest prefix first, so the first match wins
	ov := append([]SamplingOverride(nil), c.SamplingOverrides...)
	sort.SliceStable(ov, func(i, j int) bool { return ov[i].Prefix.Bits() > ov[j].Prefix.Bits() })
	c.SamplingOverrides = ov
	return c
}

// ParseSamplingOverrides parses "CIDR[@interface]=rate" items separated by
// commas, semicolons or spaces, e.g.
// "192.0.2.0/24=1000,2001:db8::/32=512,192.0.2.1@17=4000,192.0.2.1@Hu0/0/0/1=8000".
// A bare address is taken as a host prefix; the interface is an ifIndex
// (digits) or an interface name.
func ParseSamplingOverrides(s string) ([]SamplingOverride, error) {
	var out []SamplingOverride
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\t' }) {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("sampling override %q: want CIDR[@interface]=rate", item)
		}
		var o SamplingOverride
		if a, itf, found := strings.Cut(k, "@"); found {
			k = a
			if itf == "" {
				return nil, fmt.Errorf("sampling override %q: empty interface after @", item)
			}
			if n, err := strconv.ParseUint(itf, 10, 32); err == nil {
				if n == 0 {
					return nil, fmt.Errorf("sampling override %q: ifIndex 0", item)
				}
				o.IfIndex = uint32(n)
			} else {
				o.IfName = itf
			}
		}
		var p netip.Prefix
		var err error
		if strings.Contains(k, "/") {
			p, err = netip.ParsePrefix(k)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(k)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if err != nil {
			return nil, fmt.Errorf("sampling override %q: %w", item, err)
		}
		rate, err := strconv.ParseUint(v, 10, 64)
		if err != nil || rate == 0 {
			return nil, fmt.Errorf("sampling override %q: bad rate", item)
		}
		o.Prefix, o.Rate = p.Masked(), rate
		out = append(out, o)
	}
	return out, nil
}

// overrideFor returns the forced exporter-wide sampling rate for an
// exporter, or 0.
func (c *Config) overrideFor(a netip.Addr) uint64 {
	for _, o := range c.SamplingOverrides {
		if !o.perInterface() && o.Prefix.Contains(a) {
			return o.Rate
		}
	}
	return 0
}

// ifOverrides are the per-interface rates of one exporter.
type ifOverrides struct {
	byIndex map[uint32]uint64
	byName  map[string]uint64 // lower-case interface name
}

// ifOverridesFor collects the per-interface overrides that apply to an
// exporter (nil when none). Overrides are sorted longest prefix first, so the
// first one seen for an interface wins.
func (c *Config) ifOverridesFor(a netip.Addr) *ifOverrides {
	var out *ifOverrides
	for _, o := range c.SamplingOverrides {
		if !o.perInterface() || !o.Prefix.Contains(a) {
			continue
		}
		if out == nil {
			out = &ifOverrides{byIndex: map[uint32]uint64{}, byName: map[string]uint64{}}
		}
		if o.IfIndex != 0 {
			if _, ok := out.byIndex[o.IfIndex]; !ok {
				out.byIndex[o.IfIndex] = o.Rate
			}
		} else {
			n := strings.ToLower(o.IfName)
			if _, ok := out.byName[n]; !ok {
				out.byName[n] = o.Rate
			}
		}
	}
	return out
}
