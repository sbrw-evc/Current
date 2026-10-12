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
	// (longest prefix wins), whatever they report.
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
type SamplingOverride struct {
	Prefix netip.Prefix
	Rate   uint64
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

// ParseSamplingOverrides parses "CIDR=rate" pairs separated by commas or
// spaces, e.g. "192.0.2.0/24=1000,2001:db8::/32=512". A bare address is
// taken as a host prefix.
func ParseSamplingOverrides(s string) ([]SamplingOverride, error) {
	var out []SamplingOverride
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("sampling override %q: want CIDR=rate", item)
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
		out = append(out, SamplingOverride{Prefix: p.Masked(), Rate: rate})
	}
	return out, nil
}

// overrideFor returns the forced sampling rate for an exporter, or 0.
func (c *Config) overrideFor(a netip.Addr) uint64 {
	for _, o := range c.SamplingOverrides {
		if o.Prefix.Contains(a) {
			return o.Rate
		}
	}
	return 0
}
