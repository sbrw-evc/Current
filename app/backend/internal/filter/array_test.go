package filter

import "testing"

func TestArrayColumns(t *testing.T) {
	cases := []struct{ in, sql string }{
		{"DstASPath = AS15169", "has(DstASPath, 15169)"},
		{"DstASPath != 64500", "NOT has(DstASPath, 64500)"},
		{"DstCommunities = 65000:100", "has(DstCommunities, 4259840100)"},
		{"DstCommunities IN (65000:100, 1)", "hasAny(DstCommunities, [4259840100, 1])"},
		{"DstLargeCommunities NOT IN ('65000:1:2')", "NOT hasAny(DstLargeCommunities, ['65000:1:2'])"},
		{"DstASPath = 15169 AND SrcAS = 1", "(has(DstASPath, 15169) AND SrcAS = 1)"},
	}
	for _, c := range cases {
		r, err := Compile(c.in)
		if err != nil {
			t.Errorf("Compile(%q): %v", c.in, err)
			continue
		}
		if r.SQL != c.sql {
			t.Errorf("Compile(%q).SQL = %s, want %s", c.in, r.SQL, c.sql)
		}
		if _, err := Compile(r.Normalized); err != nil {
			t.Errorf("normalized %q: %v", r.Normalized, err)
		}
	}
	for _, in := range []string{"DstASPath > 1", "DstASPath = 'x'", "DstCommunities = 70000:1", "DstLargeCommunities LIKE 'a%'"} {
		if _, err := Compile(in); err == nil {
			t.Errorf("Compile(%q) accepted", in)
		}
	}
}
