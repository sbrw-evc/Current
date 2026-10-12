package inventory

import "net/netip"

// trie is a binary trie for longest-prefix match, one per address family.
type trie[V any] struct {
	v4, v6 *trieNode[V]
	n      int
}

type trieNode[V any] struct {
	child [2]*trieNode[V]
	val   V
	set   bool
}

func bitAt(b []byte, i int) int { return int(b[i>>3]>>(7-uint(i&7))) & 1 }

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

// insert stores v at p; keep decides whether an existing value is replaced
// (return true to replace).
func (t *trie[V]) insert(p netip.Prefix, v V, replace func(old V) bool) {
	p = p.Masked()
	a := p.Addr().Unmap()
	root := &t.v6
	if a.Is4() {
		root = &t.v4
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(a, max(p.Bits()-96, 0))
		}
	}
	if *root == nil {
		*root = &trieNode[V]{}
	}
	n := *root
	b := addrBytes(a)
	for i := 0; i < p.Bits(); i++ {
		bit := bitAt(b, i)
		if n.child[bit] == nil {
			n.child[bit] = &trieNode[V]{}
		}
		n = n.child[bit]
	}
	if n.set && !replace(n.val) {
		return
	}
	if !n.set {
		t.n++
	}
	n.val, n.set = v, true
}

// lookup returns the value of the longest prefix containing a.
func (t *trie[V]) lookup(a netip.Addr) (v V, ok bool) {
	a = a.Unmap()
	n := t.v6
	bits := 128
	if a.Is4() {
		n, bits = t.v4, 32
	}
	if n == nil {
		return v, false
	}
	var b []byte
	if a.Is4() {
		x := a.As4()
		b = x[:]
	} else {
		x := a.As16()
		b = x[:]
	}
	for i := 0; ; i++ {
		if n.set {
			v, ok = n.val, true
		}
		if i == bits {
			return
		}
		n = n.child[bitAt(b, i)]
		if n == nil {
			return
		}
	}
}
