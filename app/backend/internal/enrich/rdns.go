package enrich

import (
	"net/netip"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// PTRSource gives reverse DNS names without blocking: "" while the name is
// not resolved yet (or there is none). *rdns.Resolver implements it.
type PTRSource interface {
	Lookup(addr netip.Addr) string
}

// enrichPTR fills SrcHostPTR / DstHostPTR for addresses without an
// Ledger host name.
func (e *Enricher) enrichPTR(f *flow.Flow, src, dst netip.Addr) {
	p := e.cfg.PTR
	if p == nil {
		return
	}
	if src.IsValid() && f.SrcHost == "" {
		f.SrcHostPTR = p.Lookup(src)
	}
	if dst.IsValid() && f.DstHost == "" {
		f.DstHostPTR = p.Lookup(dst)
	}
}
