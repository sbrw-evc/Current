package threat

import (
	"net/netip"
)

// Trie is an immutable longest-prefix-match table of prefixes to list
// indexes, one binary trie per address family. Build it with a Builder;
// lookups are safe for concurrent use.
type Trie struct {
	v4, v6 *node
	n      int
}

type node struct {
	child [2]*node
	list  int16 // -1: no prefix ends here
}

func newNode() *node { return &node{list: -1} }

// Builder collects prefixes.
type Builder struct{ t *Trie }

// NewBuilder returns an empty builder.
func NewBuilder() *Builder { return &Builder{t: &Trie{v4: newNode(), v6: newNode()}} }

// Insert adds p for list index list. When the same prefix is inserted by
// several lists, the lowest index wins (configuration order).
func (b *Builder) Insert(p netip.Prefix, list int) {
	p = p.Masked()
	a := p.Addr()
	root, bits := b.t.v6, p.Bits()
	if a.Is4() {
		root = b.t.v4
	}
	raw := a.AsSlice()
	n := root
	for i := range bits {
		bit := raw[i/8] >> (7 - i%8) & 1
		if n.child[bit] == nil {
			n.child[bit] = newNode()
		}
		n = n.child[bit]
	}
	if n.list < 0 {
		b.t.n++
		n.list = int16(list)
	} else if int16(list) < n.list {
		n.list = int16(list)
	}
}

// Trie returns the built trie; the builder must not be used afterwards.
func (b *Builder) Trie() *Trie { return b.t }

// Len is the number of distinct prefixes.
func (t *Trie) Len() int {
	if t == nil {
		return 0
	}
	return t.n
}

// Lookup returns the list index of the longest prefix containing a, or -1.
// IPv4-mapped IPv6 addresses are looked up as IPv4.
func (t *Trie) Lookup(a netip.Addr) int {
	if t == nil || !a.IsValid() {
		return -1
	}
	a = a.Unmap()
	n := t.v6
	if a.Is4() {
		n = t.v4
	}
	raw := a.AsSlice()
	best := int16(-1)
	for i := 0; n != nil; i++ {
		if n.list >= 0 {
			best = n.list
		}
		if i == len(raw)*8 {
			break
		}
		n = n.child[raw[i/8]>>(7-i%8)&1]
	}
	return int(best)
}
