package filter

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
)

func TestCompileValid(t *testing.T) {
	cases := []struct {
		in, sql, rev, norm string
		cols               []string
	}{
		{"", "1", "1", "", []string{}},
		{"  /* only */ -- comments\n\t", "1", "1", "", []string{}},
		{"SrcAS = 65000", "SrcAS = 65000", "DstAS = 65000", "SrcAS = 65000", []string{"SrcAS"}},
		{"srcas = as65000", "SrcAS = 65000", "DstAS = 65000", "SrcAS = 65000", []string{"SrcAS"}},
		{"DstAS != AS4200000000", "DstAS != 4200000000", "SrcAS != 4200000000", "DstAS != 4200000000", []string{"DstAS"}},
		{"Proto = tcp", "Proto = 6", "Proto = 6", "Proto = 6", []string{"Proto"}},
		{"Proto IN (udp, ICMPv6, 132)", "Proto IN (17, 58, 132)", "Proto IN (17, 58, 132)", "Proto IN (17, 58, 132)", []string{"Proto"}},
		{"EType = ipv6", "EType = 34525", "EType = 34525", "EType = 34525", []string{"EType"}},
		{"EType = 0x0800", "EType = 2048", "EType = 2048", "EType = 2048", []string{"EType"}},
		{"SrcPort = 0080", "SrcPort = 80", "DstPort = 80", "SrcPort = 80", []string{"SrcPort"}},
		{"Bytes >= 18446744073709551615", "Bytes >= 18446744073709551615", "Bytes >= 18446744073709551615", "Bytes >= 18446744073709551615", []string{"Bytes"}},
		{"Packets < 10 AND Packets > 1", "(Packets < 10 AND Packets > 1)", "(Packets < 10 AND Packets > 1)", "Packets < 10 AND Packets > 1", []string{"Packets"}},
		{"InIfBoundary = external", "InIfBoundary = 'external'", "OutIfBoundary = 'external'", "InIfBoundary = 'external'", []string{"InIfBoundary"}},
		{`ExporterName = "edge-1"`, "ExporterName = 'edge-1'", "ExporterName = 'edge-1'", "ExporterName = 'edge-1'", []string{"ExporterName"}},
		{`App LIKE 'http%'`, "like(App, 'http%')", "like(App, 'http%')", "App LIKE 'http%'", []string{"App"}},
		{`App unlike 'x'`, "notLike(App, 'x')", "notLike(App, 'x')", "App UNLIKE 'x'", []string{"App"}},
		{`App NOT LIKE 'x'`, "notLike(App, 'x')", "notLike(App, 'x')", "App UNLIKE 'x'", []string{"App"}},
		{`SrcCountry ILIKE 'r%'`, "ilike(SrcCountry, 'r%')", "ilike(DstCountry, 'r%')", "SrcCountry ILIKE 'r%'", []string{"SrcCountry"}},
		{`SrcCountry IUNLIKE 'r%'`, "notILike(SrcCountry, 'r%')", "notILike(DstCountry, 'r%')", "SrcCountry IUNLIKE 'r%'", []string{"SrcCountry"}},
		{`SrcCountry NOT ILIKE 'r%'`, "notILike(SrcCountry, 'r%')", "notILike(DstCountry, 'r%')", "SrcCountry IUNLIKE 'r%'", []string{"SrcCountry"}},
		{`DstCountry IN ('RU', "DE")`, "DstCountry IN ('RU', 'DE')", "SrcCountry IN ('RU', 'DE')", "DstCountry IN ('RU', 'DE')", []string{"DstCountry"}},
		{`DstCountry NOTIN (RU)`, "DstCountry NOT IN ('RU')", "SrcCountry NOT IN ('RU')", "DstCountry NOTIN ('RU')", []string{"DstCountry"}},
		{`DstCountry not in (RU)`, "DstCountry NOT IN ('RU')", "SrcCountry NOT IN ('RU')", "DstCountry NOTIN ('RU')", []string{"DstCountry"}},
		{"SrcAddr = 192.0.2.1", "SrcAddr = toIPv6('::ffff:192.0.2.1')", "DstAddr = toIPv6('::ffff:192.0.2.1')", "SrcAddr = 192.0.2.1", []string{"SrcAddr"}},
		{"SrcAddr = ::ffff:192.0.2.1", "SrcAddr = toIPv6('::ffff:192.0.2.1')", "DstAddr = toIPv6('::ffff:192.0.2.1')", "SrcAddr = 192.0.2.1", []string{"SrcAddr"}},
		{"DstAddr != 2001:DB8::1", "DstAddr != toIPv6('2001:db8::1')", "SrcAddr != toIPv6('2001:db8::1')", "DstAddr != 2001:db8::1", []string{"DstAddr"}},
		{"ExporterAddress IN (10.0.0.1, '::1')", "ExporterAddress IN (toIPv6('::ffff:10.0.0.1'), toIPv6('::1'))", "ExporterAddress IN (toIPv6('::ffff:10.0.0.1'), toIPv6('::1'))", "ExporterAddress IN (10.0.0.1, ::1)", []string{"ExporterAddress"}},
		{"SrcAddr << 10.0.0.0/8",
			"(SrcAddr BETWEEN toIPv6('::ffff:10.0.0.0') AND toIPv6('::ffff:10.255.255.255'))",
			"(DstAddr BETWEEN toIPv6('::ffff:10.0.0.0') AND toIPv6('::ffff:10.255.255.255'))",
			"SrcAddr << 10.0.0.0/8", []string{"SrcAddr"}},
		{"SrcAddr << 192.168.1.77/24",
			"(SrcAddr BETWEEN toIPv6('::ffff:192.168.1.0') AND toIPv6('::ffff:192.168.1.255'))",
			"(DstAddr BETWEEN toIPv6('::ffff:192.168.1.0') AND toIPv6('::ffff:192.168.1.255'))",
			"SrcAddr << 192.168.1.0/24", []string{"SrcAddr"}},
		{"NextHop << 2001:db8:a::/48",
			"(NextHop BETWEEN toIPv6('2001:db8:a::') AND toIPv6('2001:db8:a:ffff:ffff:ffff:ffff:ffff'))",
			"(NextHop BETWEEN toIPv6('2001:db8:a::') AND toIPv6('2001:db8:a:ffff:ffff:ffff:ffff:ffff'))",
			"NextHop << 2001:db8:a::/48", []string{"NextHop"}},
		{"SrcAddr << 0.0.0.0/0",
			"(SrcAddr BETWEEN toIPv6('::ffff:0.0.0.0') AND toIPv6('::ffff:255.255.255.255'))",
			"(DstAddr BETWEEN toIPv6('::ffff:0.0.0.0') AND toIPv6('::ffff:255.255.255.255'))",
			"SrcAddr << 0.0.0.0/0", []string{"SrcAddr"}},
		{"SrcAddr << 198.51.100.7/32",
			"(SrcAddr BETWEEN toIPv6('::ffff:198.51.100.7') AND toIPv6('::ffff:198.51.100.7'))",
			"(DstAddr BETWEEN toIPv6('::ffff:198.51.100.7') AND toIPv6('::ffff:198.51.100.7'))",
			"SrcAddr << 198.51.100.7/32", []string{"SrcAddr"}},
		{"SrcNetPrefix = 10.1.0.0/16", "SrcNetPrefix = '10.1.0.0/16'", "DstNetPrefix = '10.1.0.0/16'", "SrcNetPrefix = 10.1.0.0/16", []string{"SrcNetPrefix"}},
		{"DstNetPrefix IN ('2001:db8::/32', 10.0.0.0/8)", "DstNetPrefix IN ('2001:db8::/32', '10.0.0.0/8')", "SrcNetPrefix IN ('2001:db8::/32', '10.0.0.0/8')", "DstNetPrefix IN (2001:db8::/32, 10.0.0.0/8)", []string{"DstNetPrefix"}},
		{"TimeReceived >= '2024-01-31 12:00:00'", "TimeReceived >= toDateTime('2024-01-31 12:00:00', 'UTC')", "TimeReceived >= toDateTime('2024-01-31 12:00:00', 'UTC')", "TimeReceived >= '2024-01-31 12:00:00'", []string{"TimeReceived"}},
		{"TimeReceived < '2024-01-31T15:00:00+03:00'", "TimeReceived < toDateTime('2024-01-31 12:00:00', 'UTC')", "TimeReceived < toDateTime('2024-01-31 12:00:00', 'UTC')", "TimeReceived < '2024-01-31 12:00:00'", []string{"TimeReceived"}},
		// Precedence: NOT > AND > OR.
		{"SrcAS = 1 OR SrcAS = 2 AND DstAS = 3",
			"(SrcAS = 1 OR (SrcAS = 2 AND DstAS = 3))",
			"(DstAS = 1 OR (DstAS = 2 AND SrcAS = 3))",
			"SrcAS = 1 OR SrcAS = 2 AND DstAS = 3", []string{"SrcAS", "DstAS"}},
		{"(SrcAS = 1 OR SrcAS = 2) AND DstAS = 3",
			"((SrcAS = 1 OR SrcAS = 2) AND DstAS = 3)",
			"((DstAS = 1 OR DstAS = 2) AND SrcAS = 3)",
			"(SrcAS = 1 OR SrcAS = 2) AND DstAS = 3", []string{"SrcAS", "DstAS"}},
		{"NOT SrcAS = 1 AND ! DstAS = 2",
			"(NOT (SrcAS = 1) AND NOT (DstAS = 2))",
			"(NOT (DstAS = 1) AND NOT (SrcAS = 2))",
			"NOT SrcAS = 1 AND NOT DstAS = 2", []string{"SrcAS", "DstAS"}},
		{"not (SrcAS = 1 || SrcAS = 2)",
			"NOT (SrcAS = 1 OR SrcAS = 2)",
			"NOT (DstAS = 1 OR DstAS = 2)",
			"NOT (SrcAS = 1 OR SrcAS = 2)", []string{"SrcAS"}},
		{"NOT NOT SrcPort = 1", "NOT (NOT (SrcPort = 1))", "NOT (NOT (DstPort = 1))", "NOT NOT SrcPort = 1", []string{"SrcPort"}},
		{"((SrcPort = 1))", "SrcPort = 1", "DstPort = 1", "SrcPort = 1", []string{"SrcPort"}},
		{"SrcPort=1&&DstPort==2||Proto=udp",
			"((SrcPort = 1 AND DstPort = 2) OR Proto = 17)",
			"((DstPort = 1 AND SrcPort = 2) OR Proto = 17)",
			"SrcPort = 1 AND DstPort = 2 OR Proto = 17", []string{"SrcPort", "DstPort", "Proto"}},
		{"SrcPort = 1 AND (DstPort = 2 AND Proto = 6)",
			"(SrcPort = 1 AND DstPort = 2 AND Proto = 6)",
			"(DstPort = 1 AND SrcPort = 2 AND Proto = 6)",
			"SrcPort = 1 AND DstPort = 2 AND Proto = 6", []string{"SrcPort", "DstPort", "Proto"}},
		{"SrcPort <> 1", "SrcPort != 1", "DstPort != 1", "SrcPort != 1", []string{"SrcPort"}},
		{"-- leading comment\nSrcAS = 1 /* inline */ AND\n  DstAS = 2 -- trailing",
			"(SrcAS = 1 AND DstAS = 2)", "(DstAS = 1 AND SrcAS = 2)",
			"SrcAS = 1 AND DstAS = 2", []string{"SrcAS", "DstAS"}},
		{"SrcAddr << 10.0.0.0/8/* no space */", "(SrcAddr BETWEEN toIPv6('::ffff:10.0.0.0') AND toIPv6('::ffff:10.255.255.255'))",
			"(DstAddr BETWEEN toIPv6('::ffff:10.0.0.0') AND toIPv6('::ffff:10.255.255.255'))", "SrcAddr << 10.0.0.0/8", []string{"SrcAddr"}},
		// Keywords as substrings of bare values / column names.
		{"App = android", "App = 'android'", "App = 'android'", "App = 'android'", []string{"App"}},
		// Direction-less columns are kept in the reverse SQL.
		{"ExporterName = r1 AND InIfIndex = 3", "(ExporterName = 'r1' AND InIfIndex = 3)", "(ExporterName = 'r1' AND InIfIndex = 3)", "ExporterName = 'r1' AND InIfIndex = 3", []string{"ExporterName", "InIfIndex"}},
		// Strings with escapes.
		{`App = 'it\'s' OR App = "say \"hi\"\n"`, `(App = 'it\'s' OR App = 'say "hi"\x0a')`, `(App = 'it\'s' OR App = 'say "hi"\x0a')`, `App = 'it\'s' OR App = 'say "hi"\n'`, []string{"App"}},
		{`SrcCity = 'Москва'`, `SrcCity = 'Москва'`, `DstCity = 'Москва'`, `SrcCity = 'Москва'`, []string{"SrcCity"}},
	}
	for _, c := range cases {
		r, err := Compile(c.in)
		if err != nil {
			t.Errorf("Compile(%q): unexpected error %v", c.in, err)
			continue
		}
		if r.SQL != c.sql {
			t.Errorf("Compile(%q).SQL\n got %s\nwant %s", c.in, r.SQL, c.sql)
		}
		if r.ReverseSQL != c.rev {
			t.Errorf("Compile(%q).ReverseSQL\n got %s\nwant %s", c.in, r.ReverseSQL, c.rev)
		}
		if r.Normalized != c.norm {
			t.Errorf("Compile(%q).Normalized\n got %s\nwant %s", c.in, r.Normalized, c.norm)
		}
		if !slices.Equal(r.Columns, c.cols) || r.Columns == nil {
			t.Errorf("Compile(%q).Columns = %v, want %v", c.in, r.Columns, c.cols)
		}
		// The normalized form compiles to the same SQL.
		r2, err := Compile(r.Normalized)
		if err != nil || r2.SQL != r.SQL || r2.ReverseSQL != r.ReverseSQL || r2.Normalized != r.Normalized {
			t.Errorf("Compile(Normalized %q) = %+v, %v; want same as %+v", r.Normalized, r2, err, r)
		}
	}
}

type wantErr struct {
	line, col, off int
	msg            string // substring
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		in   string
		errs []wantErr
	}{
		{"Foo = 1", []wantErr{{1, 1, 0, `unknown column "Foo"`}}},
		{"SrcASS = 1", []wantErr{{1, 1, 0, "did you mean SrcAS?"}}},
		{"SrcAS", []wantErr{{1, 6, 5, "expected operator after SrcAS, got end of filter"}}},
		{"SrcAS 1", []wantErr{{1, 7, 6, `expected operator after SrcAS, got "1"`}}},
		{"SrcAS =", []wantErr{{1, 8, 7, "expected a number, got end of filter"}}},
		{"SrcAS = AND", []wantErr{{1, 9, 8, `expected a number, got "AND"`}}},
		{"SrcAS = foo", []wantErr{{1, 9, 8, "SrcAS expects a number or AS<number>"}}},
		{"SrcAS = '1'", []wantErr{{1, 9, 8, "expects a number, not a string"}}},
		{"SrcAS = -1", []wantErr{{1, 9, 8, "unexpected character '-'"}}},
		{"SrcAS = 1.5", []wantErr{{1, 9, 8, "SrcAS expects a number"}}},
		{"SrcAS = 4294967296", []wantErr{{1, 9, 8, "out of range for SrcAS (UInt32, max 4294967295)"}}},
		{"SrcPort = 65536", []wantErr{{1, 11, 10, "max 65535"}}},
		{"Proto = 256", []wantErr{{1, 9, 8, "max 255"}}},
		{"Proto = tcpp", []wantErr{{1, 9, 8, "protocol name"}}},
		{"SrcPort = tcp", []wantErr{{1, 11, 10, "SrcPort expects a number"}}},
		{"SrcPort = AS1", []wantErr{{1, 11, 10, "SrcPort expects a number"}}},
		{"Bytes = 18446744073709551616", []wantErr{{1, 9, 8, "out of range"}}},
		{"SrcPort = 0x", []wantErr{{1, 11, 10, "expects a number"}}},
		{"SrcAS LIKE 'x'", []wantErr{{1, 7, 6, "operator LIKE is not valid for SrcAS (uint)"}}},
		{"App < 'x'", []wantErr{{1, 5, 4, "operator < is not valid for App (string)"}}},
		{"App << 'x'", []wantErr{{1, 5, 4, "operator << is not valid"}}},
		{"SrcAddr > 1.2.3.4", []wantErr{{1, 9, 8, "operator > is not valid for SrcAddr (ip)"}}},
		{"SrcAddr LIKE '1.%'", []wantErr{{1, 9, 8, "not valid"}}},
		{"SrcAddr = 1.2.3", []wantErr{{1, 11, 10, "expects an IP address"}}},
		{"SrcAddr = 10.0.0.0/8", []wantErr{{1, 11, 10, "use SrcAddr << 10.0.0.0/8"}}},
		{"SrcAddr << 10.0.0.1", []wantErr{{1, 12, 11, "expects a prefix"}}},
		{"SrcAddr << 10.0.0.0/33", []wantErr{{1, 12, 11, "expects a prefix"}}},
		{"SrcAddr = fe80::1%eth0", []wantErr{{1, 18, 17, "unexpected character '%'"}}},
		{"SrcNetPrefix = 10.0.0.1", []wantErr{{1, 16, 15, "expects a prefix"}}},
		{"SrcNetPrefix << 10.0.0.0/8", []wantErr{{1, 14, 13, "not valid for SrcNetPrefix (prefix)"}}},
		{"TimeReceived > 'yesterday'", []wantErr{{1, 16, 15, "expects a time"}}},
		{"TimeReceived IN ('2024-01-01')", []wantErr{{1, 14, 13, "operator IN is not valid"}}},
		{"App = 'unterminated", []wantErr{{1, 7, 6, "unterminated string"}}},
		{`App = 'bad \q escape'`, []wantErr{{1, 12, 11, `unknown escape sequence \q`}}},
		{"App = x /* open", []wantErr{{1, 9, 8, "unterminated comment"}}},
		{"App = x & y", []wantErr{{1, 9, 8, `did you mean "&&"?`}}},
		{"App = x | y", []wantErr{{1, 9, 8, `did you mean "||"?`}}},
		{"App = x AND", []wantErr{{1, 12, 11, "expected column name, NOT or '(', got end of filter"}}},
		{"App = x OR OR App = y", []wantErr{{1, 12, 11, `expected column name, NOT or '(', got "OR"`}}},
		{"App = x App = y", []wantErr{{1, 9, 8, `unexpected "App", expected AND, OR or end of filter`}}},
		{"(App = x", []wantErr{{1, 9, 8, "expected ')' to close '('"}}},
		{"App = x)", []wantErr{{1, 8, 7, "unmatched ')'"}}},
		{"()", []wantErr{{1, 2, 1, "expected column name"}}},
		{"App IN 'x'", []wantErr{{1, 8, 7, "expected '(' after IN"}}},
		{"App IN ()", []wantErr{{1, 9, 8, "expected a quoted string, got ')'"}}},
		{"App IN (a b)", []wantErr{{1, 11, 10, "expected ',' or ')' in IN list"}}},
		{"App IN (a,)", []wantErr{{1, 11, 10, "expected a quoted string"}}},
		{"App = 'é' AND É = 1", []wantErr{{1, 15, 15, "unexpected character 'É'"}}},
		{"SrcAS = 1\n  AND\n    Foo = 2", []wantErr{{3, 5, 20, `unknown column "Foo"`}}},
		{"SrcAS = 1 AND -- c\n /* x\n y */ DstAS = x", []wantErr{{3, 15, 39, "DstAS expects a number"}}},
		// Several errors in one go.
		{"Foo = 1 AND SrcPort = 70000 OR App > 1", []wantErr{
			{1, 1, 0, `unknown column "Foo"`},
			{1, 23, 22, "out of range"},
			{1, 36, 35, "operator > is not valid for App"},
		}},
		{"App = 'x\nSrcAS = $", []wantErr{{1, 7, 6, "unterminated string"}}},
		{"SrcAS = $ AND DstAS = %", []wantErr{{1, 9, 8, "unexpected character '$'"}, {1, 23, 22, "unexpected character '%'"}}},
		{"SrcAS = 99999999999 AND (", []wantErr{{1, 9, 8, "out of range"}, {1, 26, 25, "expected column name"}}},
		{"SrcAS = \xff", []wantErr{{1, 9, 8, "invalid UTF-8"}}},
	}
	for _, c := range cases {
		_, err := Compile(c.in)
		fe, ok := err.(*Error)
		if !ok {
			t.Errorf("Compile(%q): error %v (%T), want *Error", c.in, err, err)
			continue
		}
		_, errs := Validate(c.in)
		if len(errs) != len(c.errs) {
			t.Errorf("Validate(%q): %d errors %v, want %d", c.in, len(errs), errs, len(c.errs))
			continue
		}
		if fe != errs[0] && *fe != *errs[0] {
			t.Errorf("Compile(%q) error %+v differs from first Validate error %+v", c.in, fe, errs[0])
		}
		for i, w := range c.errs {
			g := errs[i]
			if g.Line != w.line || g.Column != w.col || g.Offset != w.off || !strings.Contains(g.Message, w.msg) {
				t.Errorf("Validate(%q) error %d = %d:%d@%d %q, want %d:%d@%d containing %q",
					c.in, i, g.Line, g.Column, g.Offset, g.Message, w.line, w.col, w.off, w.msg)
			}
		}
	}
}

func TestNestingLimit(t *testing.T) {
	deep := strings.Repeat("(", 200) + "SrcAS = 1" + strings.Repeat(")", 200)
	if _, err := Compile(deep); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Errorf("deep parens: %v", err)
	}
	nots := strings.Repeat("NOT ", 200) + "SrcAS = 1"
	if _, err := Compile(nots); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Errorf("deep NOT: %v", err)
	}
	ok := strings.Repeat("(", 30) + "SrcAS = 1" + strings.Repeat(")", 30)
	if _, err := Compile(ok); err != nil {
		t.Errorf("30 levels: %v", err)
	}
	// Long flat chains are fine.
	chain := strings.Repeat("SrcAS = 1 AND ", 2000) + "SrcAS = 2"
	if _, err := Compile(chain); err != nil {
		t.Errorf("long chain: %v", err)
	}
}

// splitSQL separates a generated SQL expression into its skeleton (string
// literals replaced by ?) and the decoded literals, following ClickHouse's
// escaping rules for single-quoted strings.
func splitSQL(t *testing.T, sql string) (string, []string) {
	t.Helper()
	var skel strings.Builder
	var lits []string
	for i := 0; i < len(sql); i++ {
		if sql[i] != '\'' {
			skel.WriteByte(sql[i])
			continue
		}
		var lit strings.Builder
		i++
		for ; ; i++ {
			if i >= len(sql) {
				t.Fatalf("unterminated literal in %q", sql)
			}
			c := sql[i]
			if c == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' { // '' is also an escaped quote
					t.Fatalf("doubled quote in %q", sql)
				}
				break
			}
			if c == '\\' {
				i++
				switch e := sql[i]; e {
				case '\\', '\'':
					lit.WriteByte(e)
				case 'x':
					n, err := strconv.ParseUint(sql[i+1:i+3], 16, 8)
					if err != nil {
						t.Fatalf("bad \\x in %q", sql)
					}
					lit.WriteByte(byte(n))
					i += 2
				default:
					t.Fatalf("unexpected escape \\%c in %q", e, sql)
				}
				continue
			}
			lit.WriteByte(c)
		}
		skel.WriteString("?")
		lits = append(lits, lit.String())
	}
	return skel.String(), lits
}

// safeSkeleton: outside literals, only schema columns, a fixed set of
// keywords/functions, numbers and punctuation may appear.
var skeletonToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[0-9]+|\?|!=|<=|>=|[=<>(),]|\s+`)

var allowedWords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range []string{"AND", "OR", "NOT", "IN", "BETWEEN", "like", "notLike", "ilike", "notILike", "toIPv6", "toDateTime"} {
		m[w] = true
	}
	for _, c := range schema.Columns {
		m[c.Name] = true
	}
	return m
}()

func checkSkeleton(t *testing.T, skel string) {
	t.Helper()
	rest := skel
	for rest != "" {
		loc := skeletonToken.FindStringIndex(rest)
		if loc == nil || loc[0] != 0 {
			t.Fatalf("unexpected text in SQL skeleton %q at %q", skel, rest)
		}
		tok := rest[:loc[1]]
		if c := tok[0]; (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_') && !allowedWords[tok] {
			t.Fatalf("unexpected word %q in SQL skeleton %q", tok, skel)
		}
		rest = rest[loc[1]:]
	}
}

func TestInjection(t *testing.T) {
	payloads := []string{
		`x' OR 1=1 --`,
		`x\' OR 1=1 --`,
		`x\\' OR 1=1 --`,
		`'; DROP TABLE flows; --`,
		`\`,
		`\\`,
		`'`,
		`''`,
		"a\x00b",
		"new\nline\r\t",
		"\x1b[31m\x7f",
		`%' OR '1'='1`,
		`") OR ("1"="1`,
		`/* */ -- `,
		"ok  ünï",
	}
	quote := func(p string, q byte) string {
		var b strings.Builder
		b.WriteByte(q)
		for i := 0; i < len(p); i++ {
			switch c := p[i]; {
			case c == q || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c == 0:
				b.WriteString(`\0`)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte(q)
		return b.String()
	}
	for _, p := range payloads {
		for _, q := range []byte{'\'', '"'} {
			for _, tmpl := range []string{"App = %s", "SrcCountry LIKE %s", "InIfName IN (a, %s)", "NOT DstHost IUNLIKE %s"} {
				in := strings.Replace(tmpl, "%s", quote(p, q), 1)
				r, err := Compile(in)
				if err != nil {
					t.Errorf("Compile(%q): %v", in, err)
					continue
				}
				for _, sql := range []string{r.SQL, r.ReverseSQL} {
					skel, lits := splitSQL(t, sql)
					checkSkeleton(t, skel)
					if !slices.Contains(lits, p) {
						t.Errorf("Compile(%q).SQL = %s: literals %q do not round-trip payload %q", in, sql, lits, p)
					}
				}
				r2, err := Compile(r.Normalized)
				if err != nil || r2.SQL != r.SQL {
					t.Errorf("normalized %q does not round-trip: %v", r.Normalized, err)
				}
			}
		}
	}
	// Injection through column names or bare words is rejected.
	for _, in := range []string{
		"App = x; DROP TABLE flows",
		"App = x) OR (1=1",
		"App = x OR 1 = 1",
		"SrcAS = 1 OR sleep(3)",
		"App = `x`",
		"App IN (x) UNION SELECT 1",
	} {
		if _, err := Compile(in); err == nil {
			t.Errorf("Compile(%q) succeeded, want error", in)
		}
	}
}

func TestErrorType(t *testing.T) {
	_, err := Compile("Nope = 1")
	var fe *Error
	if !errors.As(err, &fe) || fe.Message == "" || err.Error() != fe.Message {
		t.Fatalf("got %v", err)
	}
}

func TestCompleteColumns(t *testing.T) {
	got := CompleteColumns("srcA")
	var labels []string
	for _, c := range got {
		labels = append(labels, c.Label)
		if c.Quoted || c.Detail == "" {
			t.Errorf("bad completion %+v", c)
		}
	}
	if !slices.Equal(labels, []string{"SrcAddr", "SrcAS"}) {
		t.Errorf("CompleteColumns(srcA) = %v", labels)
	}
	if n := len(CompleteColumns("")); n != len(schema.Columns) {
		t.Errorf("CompleteColumns(\"\") = %d columns, want %d", n, len(schema.Columns))
	}
	if got := CompleteColumns("zzz"); got == nil || len(got) != 0 {
		t.Errorf("CompleteColumns(zzz) = %#v, want empty non-nil", got)
	}
	b, _ := json.Marshal(Completion{Label: "a", Detail: "b", Quoted: true})
	if string(b) != `{"label":"a","detail":"b","quoted":true}` {
		t.Errorf("JSON = %s", b)
	}
}

func TestCompleteOperators(t *testing.T) {
	labels := func(cs []Completion) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Label)
			if c.Detail == "" {
				t.Errorf("no detail for %q", c.Label)
			}
		}
		return out
	}
	for col, want := range map[string][]string{
		"srcaddr":      {"=", "!=", "<<", "IN", "NOTIN"},
		"App":          {"=", "!=", "IN", "NOTIN", "LIKE", "UNLIKE", "ILIKE", "IUNLIKE"},
		"SrcAS":        {"=", "!=", "<", "<=", ">", ">=", "IN", "NOTIN"},
		"SrcNetPrefix": {"=", "!=", "IN", "NOTIN"},
	} {
		if got := labels(CompleteOperators(col)); !slices.Equal(got, want) {
			t.Errorf("CompleteOperators(%s) = %v, want %v", col, got, want)
		}
	}
	if got := CompleteOperators("Nope"); got != nil {
		t.Errorf("unknown column: %v", got)
	}
	// Every offered operator compiles for a sample value.
	sample := map[schema.Kind]string{
		schema.KindString: "'x'", schema.KindIP: "10.0.0.1", schema.KindPrefix: "10.0.0.0/8",
		schema.KindUint: "1", schema.KindTime: "'2024-01-01 00:00:00'",
		schema.KindUintArray: "1", schema.KindStringArray: "'x'",
	}
	for _, c := range schema.Columns {
		for _, op := range CompleteOperators(c.Name) {
			v := sample[c.Kind]
			if op.Label == "<<" {
				v = "10.0.0.0/8"
			}
			if op.Label == "IN" || op.Label == "NOTIN" {
				v = "(" + v + ")"
			}
			if _, err := Compile(c.Name + " " + op.Label + " " + v); err != nil {
				t.Errorf("%s %s %s: %v", c.Name, op.Label, v, err)
			}
		}
	}
}

func TestValueColumnKind(t *testing.T) {
	if k, ok := ValueColumnKind("dstaddr"); !ok || k != schema.KindIP {
		t.Errorf("dstaddr: %v %v", k, ok)
	}
	if _, ok := ValueColumnKind("Nope"); ok {
		t.Error("Nope should be unknown")
	}
	if n, ok := CanonicalColumn("inifboundary"); !ok || n != "InIfBoundary" {
		t.Errorf("CanonicalColumn = %q %v", n, ok)
	}
}

func TestStaticValues(t *testing.T) {
	got := StaticValues("proto", "ic")
	if len(got) != 2 || got[0].Label != "icmp" || got[1].Label != "icmpv6" || got[0].Detail != "1" {
		t.Errorf("Proto ic: %+v", got)
	}
	if got := StaticValues("EType", ""); len(got) != len(etypes) {
		t.Errorf("EType: %+v", got)
	}
	got = StaticValues("OutIfBoundary", "ex")
	if len(got) != 1 || got[0].Label != "external" || !got[0].Quoted {
		t.Errorf("boundary: %+v", got)
	}
	if got := StaticValues("SrcAS", ""); len(got) != 0 {
		t.Errorf("SrcAS: %+v", got)
	}
	// Every static value compiles.
	for _, col := range []string{"Proto", "EType", "InIfBoundary"} {
		for _, v := range StaticValues(col, "") {
			if _, err := Compile(col + " = " + v.Label); err != nil {
				t.Errorf("%s = %s: %v", col, v.Label, err)
			}
		}
	}
}

func TestPrefixRange(t *testing.T) {
	// Semantics of <<: every address in the prefix is within [lo, hi], and
	// the neighbours just outside are not.
	cases := []struct{ p, lo, hi string }{
		{"10.0.0.0/8", "::ffff:10.0.0.0", "::ffff:10.255.255.255"},
		{"172.16.0.0/12", "::ffff:172.16.0.0", "::ffff:172.31.255.255"},
		{"2001:db8::/127", "2001:db8::", "2001:db8::1"},
		{"::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::ffff:10.0.0.0/104", "::ffff:10.0.0.0", "::ffff:10.255.255.255"},
	}
	for _, c := range cases {
		r, err := Compile("SrcAddr << " + c.p)
		if err != nil {
			t.Fatal(err)
		}
		want := "(SrcAddr BETWEEN toIPv6('" + c.lo + "') AND toIPv6('" + c.hi + "'))"
		if r.SQL != want {
			t.Errorf("%s: %s, want %s", c.p, r.SQL, want)
		}
	}
}

func FuzzCompile(f *testing.F) {
	for _, s := range []string{
		"", "SrcAS = AS65000 AND (Proto = tcp OR NOT InIfBoundary = external)",
		"SrcAddr << 10.0.0.0/8 || DstAddr IN (::1, 1.2.3.4)", `App LIKE 'x\'%' -- c`,
		"/* x */ SrcPort NOTIN (1, 2)", "TimeReceived > '2024-01-01'", "((((", "App = 'é",
		"SrcNetPrefix = 2001:db8::/32", "EType = 0x86dd", "!App=x&&!App=y",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, errs := Validate(s)
		r2, err := Compile(s)
		if (len(errs) == 0) != (err == nil) {
			t.Fatalf("Validate and Compile disagree on %q", s)
		}
		for _, e := range errs {
			if e.Offset < 0 || e.Offset > len(s) || e.Line < 1 || e.Column < 1 || e.Message == "" {
				t.Fatalf("bad error %+v for %q", e, s)
			}
		}
		if err != nil {
			return
		}
		if r.SQL != r2.SQL {
			t.Fatalf("non-deterministic")
		}
		for _, sql := range []string{r.SQL, r.ReverseSQL} {
			skel, _ := splitSQL(t, sql)
			checkSkeleton(t, skel)
		}
		r3, err := Compile(r.Normalized)
		if err != nil || r3.SQL != r.SQL || r3.ReverseSQL != r.ReverseSQL || r3.Normalized != r.Normalized {
			t.Fatalf("normalized %q of %q does not round-trip: %v\n%s\n%s", r.Normalized, s, err, r.SQL, r3.SQL)
		}
	})
}
