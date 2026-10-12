package enrich

import "net/netip"

// IfNameChain combines interface sources in priority order (the collector's
// option data first, then SNMP): the first source that knows the interface
// gives its name, and missing description and speed are taken from the next
// ones. Nil sources are skipped; nil is returned when none is left.
func IfNameChain(srcs ...IfNameSource) IfNameSource {
	var out ifNameChain
	for _, s := range srcs {
		if s != nil {
			out = append(out, s)
		}
	}
	switch len(out) {
	case 0:
		return nil
	case 1:
		return out[0]
	}
	return out
}

type ifNameChain []IfNameSource

func (c ifNameChain) Lookup(exporter netip.Addr, ifIndex uint32) (name, descr string, speed uint64, ok bool) {
	for _, s := range c {
		n, d, sp, found := s.Lookup(exporter, ifIndex)
		if !found {
			continue
		}
		if !ok {
			name, descr, speed, ok = n, d, sp, true
		} else {
			if name == "" {
				name = n
			}
			if descr == "" {
				descr = d
			}
			if speed == 0 {
				speed = sp
			}
		}
		if name != "" && descr != "" && speed != 0 {
			break
		}
	}
	return name, descr, speed, ok
}
