// Package geoiptest writes small MMDB files for tests (no external
// dependency): an IPv6 search tree with 32-bit records and a data section
// supporting strings, unsigned integers, maps and arrays.
package geoiptest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"
)

// Network is one prefix and its record.
type Network struct {
	Prefix netip.Prefix
	Data   map[string]any // values: string, uint16, uint32, uint64, int, map[string]any, []any, []string
}

type node struct {
	child [2]rec
}

type rec struct {
	node *node
	data int // -1 empty, else index into datas
}

// Write writes an MMDB file with the given database_type. Later networks
// override earlier ones where they overlap (insert less specific first).
func Write(path, dbType string, nets []Network) error {
	b, err := Build(dbType, nets)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Build returns the MMDB bytes.
func Build(dbType string, nets []Network) ([]byte, error) {
	root := &node{child: [2]rec{{data: -1}, {data: -1}}}
	var datas [][]byte
	for _, n := range nets {
		p := n.Prefix.Masked()
		var bits [16]byte
		plen := p.Bits()
		if p.Addr().Is4() {
			a4 := p.Addr().As4()
			copy(bits[12:], a4[:])
			plen += 96
		} else {
			bits = p.Addr().As16()
		}
		if plen == 0 {
			return nil, fmt.Errorf("geoiptest: /0 is not supported")
		}
		var buf bytes.Buffer
		if err := encode(&buf, n.Data); err != nil {
			return nil, err
		}
		datas = append(datas, buf.Bytes())
		idx := len(datas) - 1
		cur := root
		for i := 0; i < plen; i++ {
			bit := int(bits[i>>3]>>(7-uint(i&7))) & 1
			if i == plen-1 {
				cur.child[bit] = rec{data: idx}
				break
			}
			r := cur.child[bit]
			if r.node == nil {
				nn := &node{child: [2]rec{{data: r.data}, {data: r.data}}}
				cur.child[bit] = rec{node: nn, data: -1}
				r = cur.child[bit]
			}
			cur = r.node
		}
	}
	// Number nodes breadth-first.
	var order []*node
	index := map[*node]uint32{}
	queue := []*node{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		index[n] = uint32(len(order))
		order = append(order, n)
		for _, c := range n.child {
			if c.node != nil {
				queue = append(queue, c.node)
			}
		}
	}
	nodeCount := uint32(len(order))
	// Data section with offsets.
	var data bytes.Buffer
	offsets := make([]uint32, len(datas))
	for i, d := range datas {
		offsets[i] = uint32(data.Len())
		data.Write(d)
	}
	var out bytes.Buffer
	for _, n := range order {
		for _, c := range n.child {
			var v uint32
			switch {
			case c.node != nil:
				v = index[c.node]
			case c.data < 0:
				v = nodeCount
			default:
				v = nodeCount + 16 + offsets[c.data]
			}
			binary.Write(&out, binary.BigEndian, v)
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	meta := map[string]any{
		"node_count":                  nodeCount,
		"record_size":                 uint16(32),
		"ip_version":                  uint16(6),
		"database_type":               dbType,
		"languages":                   []string{"en"},
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 uint64(time.Now().Unix()),
		"description":                 map[string]any{"en": "test database"},
	}
	if err := encode(&out, meta); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func ctrl(w *bytes.Buffer, typ int, size int) {
	var first byte
	ext := typ > 7
	if !ext {
		first = byte(typ << 5)
	}
	var extra []byte
	switch {
	case size < 29:
		first |= byte(size)
	case size < 29+256:
		first |= 29
		extra = []byte{byte(size - 29)}
	case size < 285+65536:
		first |= 30
		s := size - 285
		extra = []byte{byte(s >> 8), byte(s)}
	default:
		first |= 31
		s := size - 65821
		extra = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}
	w.WriteByte(first)
	if ext {
		w.WriteByte(byte(typ - 7))
	}
	w.Write(extra)
}

func uintBytes(v uint64) []byte {
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	return b
}

func encode(w *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case string:
		ctrl(w, 2, len(x))
		w.WriteString(x)
	case uint16:
		b := uintBytes(uint64(x))
		ctrl(w, 5, len(b))
		w.Write(b)
	case uint32:
		b := uintBytes(uint64(x))
		ctrl(w, 6, len(b))
		w.Write(b)
	case int:
		b := uintBytes(uint64(x))
		ctrl(w, 6, len(b))
		w.Write(b)
	case uint64:
		b := uintBytes(x)
		ctrl(w, 9, len(b))
		w.Write(b)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ctrl(w, 7, len(x))
		for _, k := range keys {
			encode(w, k)
			if err := encode(w, x[k]); err != nil {
				return err
			}
		}
	case []string:
		ctrl(w, 11, len(x))
		for _, s := range x {
			encode(w, s)
		}
	case []any:
		ctrl(w, 11, len(x))
		for _, e := range x {
			if err := encode(w, e); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("geoiptest: unsupported type %T", v)
	}
	return nil
}
