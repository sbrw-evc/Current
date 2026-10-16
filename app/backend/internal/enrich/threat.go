package enrich

import (
	"net/netip"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// ThreatSource names the threat list holding an address ("" when none).
// *threat.Updater implements it.
type ThreatSource interface {
	Lookup(addr netip.Addr) string
}

// enrichThreat fills SrcThreat / DstThreat.
func (e *Enricher) enrichThreat(f *flow.Flow, src, dst netip.Addr) {
	t := e.cfg.Threats
	if t == nil {
		return
	}
	if src.IsValid() {
		f.SrcThreat = t.Lookup(src)
	}
	if dst.IsValid() {
		f.DstThreat = t.Lookup(dst)
	}
}
