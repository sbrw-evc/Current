package classifier

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var addr = netip.MustParseAddr("192.0.2.1")

func TestExporterRules(t *testing.T) {
	s, err := New(Config{Exporter: []string{
		`exporter.name.matches("^edge-") ? {"role": "edge", "group": exporter.name.split("-")[0]} : {}`,
		`{"role": "ignored-because-set", "region": exporter.site.lowerAscii() == "dc1" ? "eu" : ""}`,
		`"core" in exporter.tags ? {"group": "core"} : {}`,
		`{"tenant": exporter.group == "edge" ? "netops" : "", "site": exporter.regexReplace("x", "y")}`,
	}})
	if err == nil {
		t.Fatal("regexReplace on a map should not compile")
	}
	s, err = New(Config{Exporter: []string{
		`exporter.name.matches("^edge-") ? {"role": "edge", "group": exporter.name.split("-")[0]} : {}`,
		`{"role": "ignored-because-set", "region": exporter.site.lowerAscii() == "dc1" ? "eu" : ""}`,
		`"core" in exporter.tags ? {"group": "core"} : {}`,
		`{"tenant": exporter.group == "edge" ? "netops" : ""}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	in := Exporter{Name: "edge-01", Address: "192.0.2.1", Site: "DC1", Role: "Edge router", Tags: []string{"core"}}
	out := s.Exporter(addr, in)
	want := Exporter{Name: "edge-01", Address: "192.0.2.1", Site: "DC1", Region: "eu", Role: "edge", Group: "edge", Tenant: "netops", Tags: []string{"core"}}
	if !out.equal(&want) {
		t.Fatalf("out = %+v", out)
	}
	// Cached.
	if out2 := s.Exporter(addr, in); !out2.equal(&want) {
		t.Fatalf("cached = %+v", out2)
	}
	// Input change invalidates the cached entry.
	in.Name = "core-01"
	if out := s.Exporter(addr, in); out.Role != "ignored-because-set" || out.Group != "core" || out.Tenant != "" {
		t.Fatalf("changed input = %+v", out)
	}
}

func TestInterfaceRules(t *testing.T) {
	s, err := New(Config{Interface: []string{
		`interface.description.startsWith("Transit:") ? {"boundary": "external", "connectivity": "transit",
		   "provider": interface.description.split(":")[1].trim().lowerAscii()} : {}`,
		`interface.speed == 0 ? {"speed": 1000000000} : {}`,
		`exporter.role == "edge" && interface.boundary == "" ? {"boundary": "internal"} : {}`,
		`regex.extract(interface.name, "^(\\w+)-").orValue("") == "xe" ? {"description": "10G " + interface.description} : {}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	exp := Exporter{Name: "edge-01", Role: "edge"}
	out := s.Interface(addr, exp, Interface{Index: 501, Name: "xe-0/0/0", Description: "Transit: Telia"})
	if out.Boundary != "external" || out.Connectivity != "transit" || out.Provider != "telia" || out.Speed != 1e9 ||
		out.Description != "10G Transit: Telia" {
		t.Fatalf("out = %+v", out)
	}
	out = s.Interface(addr, exp, Interface{Index: 502, Name: "ge-0/0/1", Speed: 10})
	if out.Boundary != "internal" || out.Speed != 10 {
		t.Fatalf("out = %+v", out)
	}
	if n, _ := s.EvalErrors(); n != 0 {
		t.Fatalf("eval errors = %d", n)
	}
}

func TestRuntimeErrors(t *testing.T) {
	s, err := New(Config{
		Interface: []string{`{"boundary": "outside"}`, `{"foo": "bar"}`, `{"speed": "fast"}`, `{"provider": interface.nope}`, `{"provider": "ok"}`},
		Exporter:  []string{`dyn(1)`},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := s.Interface(addr, Exporter{}, Interface{Index: 1})
	if out.Provider != "ok" || out.Boundary != "" {
		t.Fatalf("out = %+v", out)
	}
	s.Exporter(addr, Exporter{Name: "x"})
	n, msg := s.EvalErrors()
	if n != 5 || msg == "" {
		t.Fatalf("errors = %d %q", n, msg)
	}
}

func TestCompileErrors(t *testing.T) {
	_, err := New(Config{
		Exporter:  []string{`{"site": "a"}`, "{\"site\":\n  exporter.name +}"},
		Interface: []string{`"just a string"`, ``, `interface.name == 1 ?`},
	})
	var ce CompileErrors
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if len(ce) < 4 {
		t.Fatalf("errors = %+v", ce)
	}
	first := ce[0]
	if first.Kind != KindExporter || first.Index != 1 || first.Line != 2 || first.Column < 2 || first.Offset <= 10 {
		t.Fatalf("first = %+v", first)
	}
	if !strings.Contains(ce.Error(), "interface rule 1") || !strings.Contains(ce.Error(), "must return a map") {
		t.Fatalf("msg = %s", ce.Error())
	}
	if v := Validate(Config{Exporter: []string{`{}`}}); len(v) != 0 {
		t.Fatalf("validate = %v", v)
	}
}

func TestCostLimit(t *testing.T) {
	s, err := New(Config{CostLimit: 50, Exporter: []string{
		`[1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x*y > 0)) ? {"site": "x"} : {}`,
		`{"region": "r"}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := s.Exporter(addr, Exporter{})
	if out.Site != "" || out.Region != "r" {
		t.Fatalf("out = %+v", out)
	}
	if _, msg := s.EvalErrors(); !strings.Contains(msg, "cost") {
		t.Fatalf("msg = %q", msg)
	}
}

func TestCacheTTL(t *testing.T) {
	c := newTTLCache[int, int](2, time.Minute)
	now := time.Now()
	c.put(1, 1, now)
	c.put(2, 2, now)
	c.put(3, 3, now) // full: dropped everything
	if _, ok := c.get(1, now); ok {
		t.Fatal("should be evicted")
	}
	if v, ok := c.get(3, now); !ok || v != 3 {
		t.Fatal("missing 3")
	}
	if _, ok := c.get(3, now.Add(2*time.Minute)); ok {
		t.Fatal("should be expired")
	}
}

func TestPreview(t *testing.T) {
	var req PreviewRequest
	json.Unmarshal([]byte(`{"kind":"interface","rules":["interface.vlan == 100 ? {\"connectivity\": \"customer\", \"boundary\": \"external\"} : {}","{\"name\": 5}"],
		"sample":{"exporter":{"name":"edge-01"},"interface":{"index":3,"name":"ge-0/0/3","vlan":100}}}`), &req)
	res, err := Preview(req)
	if err != nil || !res.Valid || res.Interface == nil || res.Interface.Connectivity != "customer" || res.Interface.Name != "5" ||
		len(res.Steps) != 2 || res.Steps[0].Output["boundary"] != "external" {
		t.Fatalf("preview = %+v, %v", res, err)
	}
	res, _ = Preview(PreviewRequest{Kind: KindExporter, Rules: []string{`{"site": }`}})
	if res.Valid || len(res.Errors) == 0 {
		t.Fatalf("preview = %+v", res)
	}
	if _, err := Preview(PreviewRequest{Kind: "x"}); err == nil {
		t.Fatal("want error")
	}
}

func BenchmarkInterfaceCached(b *testing.B) {
	s, _ := New(Config{Interface: []string{`interface.description.startsWith("T") ? {"boundary": "external"} : {}`}})
	exp := Exporter{Name: "edge-01", Tags: []string{"a"}}
	in := Interface{Index: 1, Description: "Transit"}
	for b.Loop() {
		s.Interface(addr, exp, in)
	}
}
