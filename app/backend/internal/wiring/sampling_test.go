package wiring_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/flow"
	"github.com/sbrw-evc/network/app/backend/internal/store"
	"github.com/sbrw-evc/network/app/backend/internal/wiring"
)

type nopSink struct{}

func (nopSink) Put(context.Context, []*flow.Flow) error { return nil }

func TestSamplingFromEnv(t *testing.T) {
	env := map[string]string{wiring.EnvSamplingOverrides: "10.0.0.0/8=100, 10.0.0.1@7=10; 10.0.0.1@xe-0/0/1=20"}
	ov, err := wiring.SamplingFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(ov) != 3 || ov[1].IfIndex != 7 || ov[2].IfName != "xe-0/0/1" {
		t.Fatalf("%+v", ov)
	}
	env[wiring.EnvSamplingOverrides] = "10.0.0.1@=5"
	if _, err := wiring.SamplingFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Error("bad value accepted")
	}
	if ov, err := wiring.SamplingFromEnv(func(string) string { return "" }); err != nil || ov != nil {
		t.Error(ov, err)
	}
}

func TestMergeSampling(t *testing.T) {
	stored := wiring.SamplingOverrides([]store.SamplingOverride{
		{Exporter: netip.MustParsePrefix("10.0.0.1/32"), IfIndex: 7, Rate: 1},
		{Exporter: netip.MustParsePrefix("10.0.0.0/8"), Rate: 2},
	})
	env := []collector.SamplingOverride{{Prefix: netip.MustParsePrefix("10.0.0.1/32"), IfIndex: 7, Rate: 99}}
	m := wiring.MergeSampling(env, stored)
	if len(m) != 2 || m[0].Rate != 99 || m[1].Rate != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestApplySamplingWithoutStore(t *testing.T) {
	c, err := collector.New(collector.Config{NetFlowListen: "127.0.0.1:0"}, nopSink{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := 0
	wc := &wiring.Collector{C: c, Env: []collector.SamplingOverride{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Rate: 5}},
		OpenStore: func(context.Context) (*store.Store, error) { opened++; return nil, wiring.ErrNoConfig }}
	if err := wc.ApplySampling(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := wc.ApplySampling(context.Background()); err != nil || opened != 2 {
		t.Fatal(err, opened)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wc.RunSampling(ctx, 0) // returns at once on a canceled context
}
