package query

import (
	"bufio"
	"context"
	_ "embed"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	chstore "github.com/sbrw-evc/current/app/backend/internal/storage/clickhouse"
)

//go:embed asnames.csv
var builtinCSV string

var (
	builtinOnce  sync.Once
	builtinNames map[uint32]string
)

// BuiltinASName names a well-known AS from the small list bundled with the
// binary (asnames.csv), "" when it is not there. It is the last fallback for
// installs without GeoIP.
func BuiltinASName(asn uint32) string {
	builtinOnce.Do(func() { builtinNames = parseASNames(builtinCSV) })
	return builtinNames[asn]
}

// parseASNames reads "asn,name" lines; '#' starts a comment line.
func parseASNames(s string) map[uint32]string {
	out := map[uint32]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		a, name, ok := strings.Cut(line, ",")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(a)), "AS"), 10, 32)
		if err != nil || n == 0 || strings.TrimSpace(name) == "" {
			continue
		}
		out[uint32(n)] = strings.TrimSpace(name)
	}
	return out
}

// ASNamesRefresh is how often ASNames re-reads the asn_names table.
const ASNamesRefresh = 5 * time.Minute

// ASNames names ASes for labels across processes: first the GeoIP lookups
// of this process (Local, when the enricher runs here), then the names the
// enrichers stored in ClickHouse (asn_names, cached and refreshed every
// Refresh in the background), then the built-in list.
type ASNames struct {
	Conn    driver.Conn // nil: no ClickHouse cache
	Storage chstore.Config
	Local   ASNamer // optional
	Refresh time.Duration
	Log     *slog.Logger

	names      atomic.Pointer[map[uint32]string]
	loadedAt   atomic.Int64 // unix nanoseconds of the last attempt
	refreshing atomic.Bool
}

// Name is the ASNamer hook.
func (a *ASNames) Name(asn uint32) string {
	if a == nil {
		return BuiltinASName(asn)
	}
	if a.Local != nil {
		if n := a.Local(asn); n != "" {
			return n
		}
	}
	a.maybeRefresh()
	if m := a.names.Load(); m != nil {
		if n := (*m)[asn]; n != "" {
			return n
		}
	}
	return BuiltinASName(asn)
}

// maybeRefresh starts a background reload when the cache is older than
// Refresh. The first call (empty cache) waits for it briefly so the first
// answer already has the names.
func (a *ASNames) maybeRefresh() {
	if a.Conn == nil {
		return
	}
	every := a.Refresh
	if every <= 0 {
		every = ASNamesRefresh
	}
	if time.Since(time.Unix(0, a.loadedAt.Load())) < every || !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.refreshing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := a.Load(ctx); err != nil && a.Log != nil {
			a.Log.Warn("AS names not loaded from ClickHouse", "err", err)
		}
	}()
	if a.names.Load() == nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

// Load reads the asn_names table now.
func (a *ASNames) Load(ctx context.Context) error {
	a.loadedAt.Store(time.Now().UnixNano())
	m, err := chstore.ReadASNames(ctx, a.Conn, a.Storage)
	if err != nil {
		return err
	}
	a.names.Store(&m)
	return nil
}

// Len is the number of AS names in the ClickHouse cache.
func (a *ASNames) Len() int {
	if m := a.names.Load(); m != nil {
		return len(*m)
	}
	return 0
}
