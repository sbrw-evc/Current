package wiring_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/classifier"
	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/filter"
	"github.com/sbrw-evc/network/app/backend/internal/query"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/wiring"
)

func TestMapError(t *testing.T) {
	for _, err := range []error{&query.ValidationError{Field: "limit", Message: "too big"}, &filter.Error{Line: 1, Column: 2, Message: "bad"}} {
		s, ok := wiring.MapError(err).(interface{ HTTPStatus() int })
		if !ok || s.HTTPStatus() != 400 {
			t.Errorf("%T not mapped to 400", err)
		}
	}
}

func TestMergeExporters(t *testing.T) {
	now := time.Now().UTC()
	ch := []query.Exporter{{Address: "127.0.0.11", Name: "edge-01", SamplingRates: []uint64{1000},
		Interfaces: []query.ExporterInterface{{Index: 1, InBps: 5}}}}
	reg := []collector.ExporterInfo{
		{Address: netip.MustParseAddr("127.0.0.11"), LastSeen: now, FlowsPerSecond: 12, SamplingRates: []uint64{1000, 512},
			Interfaces: []collector.InterfaceInfo{{Index: 1, Name: "Te0/0/0", Description: "Transit"}, {Index: 2, Name: "Te0/0/1"}}},
		{Address: netip.MustParseAddr("127.0.0.13"), LastSeen: now},
	}
	out := wiring.MergeExporters(ch, reg)
	if len(out) != 2 || out[0].Name != "edge-01" || out[0].FlowsPerSecond != 12 || len(out[0].SamplingRates) != 2 ||
		len(out[0].Interfaces) != 2 || out[0].Interfaces[0].Name != "Te0/0/0" || out[0].Interfaces[0].InBps != 5 ||
		out[1].Address != "127.0.0.13" || !out[1].LastSeen.Equal(now) {
		t.Fatalf("%+v", out)
	}
}

func TestClassifierPreviewSamples(t *testing.T) {
	c := wiring.Classifiers{}
	rules := []string{`interface.description.startsWith("Transit:") ? {"boundary": "external"} : {}`}
	for _, sample := range []string{
		`{"exporter": {"address": "10.0.0.1"}, "index": 5, "name": "Te0", "description": "Transit: X"}`,
		`{"exporter": {"address": "10.0.0.1"}, "interface": {"description": "Transit: X"}}`,
	} {
		out, err := c.Preview(context.Background(), classifier.KindInterface, rules, json.RawMessage(sample))
		if err != nil {
			t.Fatal(err)
		}
		r := out.(classifier.PreviewResult)
		if !r.Valid || r.Interface == nil || r.Interface.Boundary != "external" {
			t.Errorf("%s: %+v", sample, r)
		}
	}
	out, err := c.Preview(context.Background(), classifier.KindExporter, []string{`exporter.name.startsWith("edge-") ? {"role": "edge"} : {}`},
		json.RawMessage(`{"address": "10.0.0.1", "name": "edge-msk-01"}`))
	if err != nil || out.(classifier.PreviewResult).Exporter.Role != "edge" {
		t.Fatal(out, err)
	}
	if err := c.Validate(classifier.KindExporter, []string{"exporter.name +"}); err == nil {
		t.Error("bad rule accepted")
	}
}

func TestSamplingOverrides(t *testing.T) {
	ov := wiring.SamplingOverrides([]store.SamplingOverride{
		{Exporter: netip.MustParsePrefix("10.0.0.0/8"), Rate: 100},
		{Exporter: netip.MustParsePrefix("10.0.0.1/32"), IfIndex: 3, Rate: 10},
	})
	if len(ov) != 2 || ov[0].Rate != 100 || ov[1].IfIndex != 3 || ov[1].Rate != 10 {
		t.Fatal(ov)
	}
}

func TestFilterService(t *testing.T) {
	f := &wiring.Filter{}
	out, err := f.Validate(context.Background(), json.RawMessage(`{"filter": "SrcAS = AS65000 and Proto = tcp"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	var v struct {
		Valid  bool   `json:"valid"`
		Parsed string `json:"parsed"`
	}
	_ = json.Unmarshal(b, &v)
	if !v.Valid || v.Parsed == "" {
		t.Fatalf("%s", b)
	}
	out, _ = f.Validate(context.Background(), json.RawMessage(`{"filter": "Nope = 1"}`))
	b, _ = json.Marshal(out)
	var bad struct {
		Valid  bool `json:"valid"`
		Errors []struct {
			Line    int    `json:"line"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(b, &bad)
	if bad.Valid || len(bad.Errors) == 0 || bad.Errors[0].Line != 1 {
		t.Fatalf("%s", b)
	}
	out, err = f.Complete(context.Background(), json.RawMessage(`{"what": "value", "column": "Proto", "prefix": "tc"}`))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ = json.Marshal(out); string(b) == `{"completions":[]}` {
		t.Fatalf("no static values: %s", b)
	}
}
