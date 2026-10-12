package enrich

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// ASRouting is the AS provider taking the origin AS of the BGP route (BMP).
const ASRouting = "routing"

// RouteInfo is the BGP route covering an address. Slices are shared with
// the routing table and must not be modified.
type RouteInfo struct {
	OriginAS         uint32
	ASPath           []uint32
	Communities      []uint32
	LargeCommunities []string // "a:b:c"
	NextHop          netip.Addr
}

// RoutingSource looks up routes; the BMP RIB implements it (via wiring).
type RoutingSource interface {
	LookupRoute(addr netip.Addr) (RouteInfo, bool)
}

// route looks up the route of a (source or destination) address.
func (e *Enricher) route(a netip.Addr, n *netInfo) {
	if e.cfg.Routing == nil {
		return
	}
	n.rt, n.rtOK = e.cfg.Routing.LookupRoute(a)
}

// applyDstRoute fills the BGP columns of the destination and the next hop
// when the exporter did not report one.
func (e *Enricher) applyDstRoute(f *flow.Flow, n *netInfo) {
	if !n.rtOK {
		return
	}
	f.DstASPath, f.DstCommunities, f.DstLargeCommunities = n.rt.ASPath, n.rt.Communities, n.rt.LargeCommunities
	if (!f.NextHop.IsValid() || f.NextHop.Unmap().IsUnspecified()) && n.rt.NextHop.IsValid() {
		f.NextHop = n.rt.NextHop
	}
}

// ValidASProvider reports a known AS provider name.
func ValidASProvider(p string) bool {
	switch p {
	case ASFlow, ASFlowExceptPrivate, ASGeoIP, ASRouting:
		return true
	}
	return false
}

// SetASProviders replaces the AS provider order at run time (e.g. "routing"
// first while BMP is enabled); nil restores Config.ASProviders.
func (e *Enricher) SetASProviders(order []string) error {
	if order == nil {
		e.asDyn.Store(nil)
		return nil
	}
	if len(order) == 0 {
		return errors.New("enrich: empty AS provider list")
	}
	for _, p := range order {
		if !ValidASProvider(p) {
			return errors.New("enrich: unknown AS provider " + strconv.Quote(p))
		}
	}
	o := slices.Clone(order)
	e.asDyn.Store(&o)
	return nil
}
