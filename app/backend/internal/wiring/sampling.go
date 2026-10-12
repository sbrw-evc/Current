package wiring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/collector"
	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// EnvSamplingOverrides is the environment variable with sampling overrides
// in the collector.ParseSamplingOverrides syntax
// ("192.0.2.0/24=1000, 192.0.2.1@17=4000, 192.0.2.1@Hu0/0/0/1=8000").
const EnvSamplingOverrides = "FLOW_SAMPLING_OVERRIDES"

// SamplingRefresh is how often the collector re-reads the stored overrides
// (changes made through the API of another process arrive this way).
const SamplingRefresh = time.Minute

// ErrNoConfig is returned by a store opener while flow.json is missing or
// the setup is not finished.
var ErrNoConfig = errors.New("flow.json is not there yet")

// SamplingFromEnv parses FLOW_SAMPLING_OVERRIDES through getenv (os.Getenv
// when nil).
func SamplingFromEnv(getenv func(string) string) ([]collector.SamplingOverride, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	v := strings.TrimSpace(getenv(EnvSamplingOverrides))
	if v == "" {
		return nil, nil
	}
	ov, err := collector.ParseSamplingOverrides(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvSamplingOverrides, err)
	}
	return ov, nil
}

// SamplingOverrides converts the stored overrides for the collector: an
// if_index ≠ 0 makes it a per-interface override.
func SamplingOverrides(in []store.SamplingOverride) []collector.SamplingOverride {
	out := make([]collector.SamplingOverride, 0, len(in))
	for _, o := range in {
		if !o.Exporter.IsValid() || o.Rate == 0 {
			continue
		}
		out = append(out, collector.SamplingOverride{Prefix: o.Exporter.Masked(), IfIndex: o.IfIndex, Rate: o.Rate})
	}
	return out
}

// MergeSampling puts env first and drops the stored overrides with the same
// prefix and interface: the environment wins.
func MergeSampling(env, stored []collector.SamplingOverride) []collector.SamplingOverride {
	type key struct {
		p   string
		idx uint32
		nm  string
	}
	k := func(o collector.SamplingOverride) key {
		return key{o.Prefix.Masked().String(), o.IfIndex, strings.ToLower(o.IfName)}
	}
	seen := map[key]bool{}
	out := make([]collector.SamplingOverride, 0, len(env)+len(stored))
	for _, o := range env {
		seen[k(o)] = true
		out = append(out, o)
	}
	for _, o := range stored {
		if !seen[k(o)] {
			out = append(out, o)
		}
	}
	return out
}

// ApplySampling reads the overrides from PostgreSQL (when connected), merges
// FLOW_SAMPLING_OVERRIDES and applies them. Without a store only the
// environment overrides are applied.
func (c *Collector) ApplySampling(ctx context.Context) error {
	c.smu.Lock()
	defer c.smu.Unlock()
	var stored []collector.SamplingOverride
	var err error
	if c.St == nil && c.OpenStore != nil {
		if st, oerr := c.OpenStore(ctx); oerr == nil {
			c.St, c.opened = st, true
		} else if !errors.Is(oerr, ErrNoConfig) {
			err = fmt.Errorf("PostgreSQL: %w", oerr)
		}
	}
	if c.St != nil {
		list, lerr := c.St.SamplingOverrides(ctx)
		if lerr != nil {
			// keep what is applied: a PostgreSQL outage must not reset the rates
			return lerr
		}
		stored = SamplingOverrides(list)
	}
	c.C.SetSamplingOverrides(MergeSampling(c.Env, stored))
	return err
}

// RunSampling applies the overrides now and then every interval (default
// SamplingRefresh) until ctx ends.
func (c *Collector) RunSampling(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = SamplingRefresh
	}
	logSampling(c.Log, c.Env)
	t := time.NewTicker(interval)
	defer t.Stop()
	defer func() {
		c.smu.Lock()
		if c.opened && c.St != nil {
			c.St.Close()
			c.St, c.opened = nil, false
		}
		c.smu.Unlock()
	}()
	for {
		err := c.ApplySampling(ctx)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != c.lastErr && c.Log != nil {
			if err != nil {
				c.Log.Warn("sampling overrides not refreshed", "err", err)
			} else {
				c.Log.Info("sampling overrides refreshed")
			}
		}
		c.lastErr = msg
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SamplingStore returns an opener of the PostgreSQL store for the
// standalone collector role: it reads flow.json from dataDir (the shared data
// volume in Docker), resolves the DSN through OpenBao and connects. It
// answers ErrNoConfig until the setup wizard has written flow.json.
func SamplingStore(dataDir string, wait time.Duration) func(ctx context.Context) (*store.Store, error) {
	if wait <= 0 || wait > 30*time.Second {
		wait = 30 * time.Second
	}
	return func(ctx context.Context) (*store.Store, error) {
		cfg, found, err := config.Read(dataDir)
		if err != nil {
			return nil, err
		}
		if !found || cfg.CompletedAt == nil {
			return nil, ErrNoConfig
		}
		vault, err := cfg.OpenBao.Client()
		if err != nil {
			return nil, err
		}
		var res secrets.Resolver
		if vault != nil {
			if err := vault.Ready(ctx, wait); err != nil {
				return nil, fmt.Errorf("OpenBao %s: %w", cfg.OpenBao.Addr, err)
			}
			res = vault
		}
		dsn, err := cfg.PostgresDSN(res)
		if err != nil {
			return nil, err
		}
		return store.Open(ctx, dsn)
	}
}

// logSampling describes the environment overrides at start-up.
func logSampling(log *slog.Logger, env []collector.SamplingOverride) {
	if log == nil || len(env) == 0 {
		return
	}
	items := make([]string, len(env))
	for i, o := range env {
		items[i] = o.String()
	}
	log.Info("sampling overrides from the environment", "overrides", strings.Join(items, ", "))
}
