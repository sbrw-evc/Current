// Package classifier runs CEL rules that classify exporters (site, region,
// role, group, tenant, name) and interfaces (boundary, connectivity,
// provider, name, description, speed).
//
// A rule is a CEL expression returning a map of fields to set, or an empty
// map. Rules run in order and the first non-empty value per key wins; later
// rules see the values set by earlier ones. Classifier output overrides the
// values coming from Inventory DB and the collector.
//
//	exporter.name.matches("^edge-") ? {"role": "edge"} : {}
//	interface.description.startsWith("Transit:") ? {"boundary": "external", "connectivity": "transit",
//	    "provider": interface.description.split(":")[1].trim().lowerAscii()} : {}
package classifier

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
)

// Rule kinds.
const (
	KindExporter  = "exporter"
	KindInterface = "interface"
)

// Keys rules may set.
var (
	ExporterKeys  = []string{"site", "region", "role", "group", "tenant", "name"}
	InterfaceKeys = []string{"boundary", "connectivity", "provider", "name", "description", "speed"}
)

// Exporter is what exporter rules see as `exporter`.
type Exporter struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	Site    string   `json:"site"`
	Region  string   `json:"region"`
	Role    string   `json:"role"`
	Group   string   `json:"group"`
	Tenant  string   `json:"tenant"`
	Tags    []string `json:"tags"`
}

func (e *Exporter) equal(o *Exporter) bool {
	return e.Name == o.Name && e.Address == o.Address && e.Site == o.Site && e.Region == o.Region && e.Role == o.Role &&
		e.Group == o.Group && e.Tenant == o.Tenant && slices.Equal(e.Tags, o.Tags)
}

func (e *Exporter) toMap() map[string]any {
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	return map[string]any{"name": e.Name, "address": e.Address, "site": e.Site, "region": e.Region, "role": e.Role,
		"group": e.Group, "tenant": e.Tenant, "tags": tags}
}

func (e *Exporter) set(k, v string) {
	switch k {
	case "site":
		e.Site = v
	case "region":
		e.Region = v
	case "role":
		e.Role = v
	case "group":
		e.Group = v
	case "tenant":
		e.Tenant = v
	case "name":
		e.Name = v
	}
}

// Interface is what interface rules see as `interface`.
type Interface struct {
	Index        uint32 `json:"index"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Speed        uint64 `json:"speed"` // bits per second
	Boundary     string `json:"boundary"`
	Connectivity string `json:"connectivity"`
	Provider     string `json:"provider"`
	Circuit      string `json:"circuit"`
	VLAN         uint32 `json:"vlan"`
}

func (i *Interface) toMap() map[string]any {
	return map[string]any{"index": int64(i.Index), "name": i.Name, "description": i.Description, "speed": int64(i.Speed),
		"boundary": i.Boundary, "connectivity": i.Connectivity, "provider": i.Provider, "circuit": i.Circuit,
		"vlan": int64(i.VLAN)}
}

func (i *Interface) set(k, v string) error {
	switch k {
	case "boundary":
		v = strings.ToLower(v)
		if v != "internal" && v != "external" {
			return fmt.Errorf("boundary must be \"internal\" or \"external\", got %q", v)
		}
		i.Boundary = v
	case "connectivity":
		i.Connectivity = strings.ToLower(v)
	case "provider":
		i.Provider = v
	case "name":
		i.Name = v
	case "description":
		i.Description = v
	case "speed":
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return fmt.Errorf("speed must be a number of bits per second, got %q", v)
		}
		i.Speed = n
	}
	return nil
}

// Config of a rule set.
type Config struct {
	Exporter  []string `json:"exporter"`
	Interface []string `json:"interface"`
	// CostLimit per rule evaluation (default 100000).
	CostLimit uint64 `json:"-"`
	// CacheTTL of classification results (default 5 min; negative disables).
	CacheTTL time.Duration `json:"-"`
	// CacheSize bounds each result cache (default 100000 entries).
	CacheSize int `json:"-"`
}

// CompileError is a rule that does not compile, with its position.
type CompileError struct {
	Kind    string `json:"kind"`
	Index   int    `json:"index"` // rule index
	Line    int    `json:"line"`  // 1-based
	Column  int    `json:"column"`
	Offset  int    `json:"offset"`
	Message string `json:"message"`
}

func (e CompileError) Error() string {
	return fmt.Sprintf("%s rule %d: %d:%d: %s", e.Kind, e.Index+1, e.Line, e.Column, e.Message)
}

// CompileErrors lists every compile error.
type CompileErrors []CompileError

func (e CompileErrors) Error() string {
	s := make([]string, len(e))
	for i, x := range e {
		s[i] = x.Error()
	}
	return strings.Join(s, "; ")
}

type rule struct {
	src  string
	prog cel.Program
}

var (
	envOnce sync.Once
	envVal  *cel.Env
	envErr  error
)

func env() (*cel.Env, error) {
	envOnce.Do(func() {
		envVal, envErr = cel.NewEnv(
			cel.Variable("exporter", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("interface", cel.MapType(cel.StringType, cel.DynType)),
			cel.OptionalTypes(),
			ext.Strings(),
			ext.Regex(),
		)
	})
	return envVal, envErr
}

func offsetOf(src string, line, col int) int {
	off := 0
	for l := 1; l < line; l++ {
		i := strings.IndexByte(src[off:], '\n')
		if i < 0 {
			return len(src)
		}
		off += i + 1
	}
	// col counts runes.
	n := 0
	for i := range src[off:] {
		if n == col {
			return off + i
		}
		n++
	}
	return len(src)
}

func compile(kind string, srcs []string, costLimit uint64) ([]rule, CompileErrors) {
	e, err := env()
	if err != nil {
		return nil, CompileErrors{{Kind: kind, Message: err.Error()}}
	}
	var errs CompileErrors
	rules := make([]rule, 0, len(srcs))
	for i, src := range srcs {
		if strings.TrimSpace(src) == "" {
			errs = append(errs, CompileError{Kind: kind, Index: i, Line: 1, Column: 1, Message: "empty rule"})
			continue
		}
		ast, iss := e.Compile(src)
		if iss != nil && iss.Err() != nil {
			for _, ce := range iss.Errors() {
				line, col := ce.Location.Line(), ce.Location.Column()
				errs = append(errs, CompileError{Kind: kind, Index: i, Line: line, Column: col + 1,
					Offset: offsetOf(src, line, col), Message: ce.Message})
			}
			continue
		}
		if t := ast.OutputType(); t.Kind() != types.MapKind && t.Kind() != types.DynKind && t.Kind() != types.NullTypeKind {
			errs = append(errs, CompileError{Kind: kind, Index: i, Line: 1, Column: 1,
				Message: fmt.Sprintf("rule must return a map of fields, not %s", t)})
			continue
		}
		prog, err := e.Program(ast, cel.CostLimit(costLimit), cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			errs = append(errs, CompileError{Kind: kind, Index: i, Line: 1, Column: 1, Message: err.Error()})
			continue
		}
		rules = append(rules, rule{src: src, prog: prog})
	}
	return rules, errs
}

// Validate compiles cfg and reports every error.
func Validate(cfg Config) CompileErrors {
	_, e1 := compile(KindExporter, cfg.Exporter, 1)
	_, e2 := compile(KindInterface, cfg.Interface, 1)
	return append(e1, e2...)
}

// Set is a compiled rule set with result caches. Safe for concurrent use.
type Set struct {
	cfg       Config
	exporter  []rule
	iface     []rule
	expCache  *ttlCache[netip.Addr, expEntry]
	ifCache   *ttlCache[ifKey, ifEntry]
	evalErrs  atomic.Uint64
	lastError atomic.Pointer[string]
}

type ifKey struct {
	exporter netip.Addr
	index    uint32
}

type expEntry struct {
	in, out Exporter
}

type ifEntry struct {
	exp     Exporter
	in, out Interface
}

// New compiles the rules; any compile error fails (as CompileErrors).
func New(cfg Config) (*Set, error) {
	if cfg.CostLimit == 0 {
		cfg.CostLimit = 100_000
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 100_000
	}
	er, e1 := compile(KindExporter, cfg.Exporter, cfg.CostLimit)
	ir, e2 := compile(KindInterface, cfg.Interface, cfg.CostLimit)
	if errs := append(e1, e2...); len(errs) > 0 {
		return nil, errs
	}
	return &Set{cfg: cfg, exporter: er, iface: ir,
		expCache: newTTLCache[netip.Addr, expEntry](cfg.CacheSize, cfg.CacheTTL),
		ifCache:  newTTLCache[ifKey, ifEntry](cfg.CacheSize, cfg.CacheTTL)}, nil
}

// Config returns the rules of the set.
func (s *Set) Config() Config { return s.cfg }

// Empty reports whether the set has no rules.
func (s *Set) Empty() bool { return s == nil || (len(s.exporter) == 0 && len(s.iface) == 0) }

// HasExporterRules / HasInterfaceRules report whether there is anything to run.
func (s *Set) HasExporterRules() bool  { return s != nil && len(s.exporter) > 0 }
func (s *Set) HasInterfaceRules() bool { return s != nil && len(s.iface) > 0 }

// Reset clears the caches (e.g. after an inventory sync).
func (s *Set) Reset() {
	if s == nil {
		return
	}
	s.expCache.clear()
	s.ifCache.clear()
}

// EvalErrors counts rule evaluation errors (runtime errors, cost limit,
// bad output) and returns the last message.
func (s *Set) EvalErrors() (uint64, string) {
	msg := ""
	if p := s.lastError.Load(); p != nil {
		msg = *p
	}
	return s.evalErrs.Load(), msg
}

func (s *Set) noteErr(err error) {
	s.evalErrs.Add(1)
	m := err.Error()
	s.lastError.Store(&m)
}

// outputs converts a rule result to string fields.
func outputs(v ref.Val) (map[string]string, error) {
	if v == nil || v.Type() == types.NullType {
		return nil, nil
	}
	m, ok := v.Value().(map[ref.Val]ref.Val)
	if !ok {
		native, err := v.ConvertToNative(mapStringAny)
		if err != nil {
			return nil, fmt.Errorf("rule must return a map, got %s", v.Type().TypeName())
		}
		out := map[string]string{}
		for k, x := range native.(map[string]any) {
			s, err := scalar(x)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = s
		}
		return out, nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		ks, ok := k.Value().(string)
		if !ok {
			return nil, fmt.Errorf("map keys must be strings")
		}
		s, err := scalar(x.Value())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ks, err)
		}
		out[ks] = s
	}
	return out, nil
}

var mapStringAny = reflectMapStringAny()

func scalar(x any) (string, error) {
	switch v := x.(type) {
	case string:
		return v, nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	case nil:
		return "", nil
	case ref.Val:
		return scalar(v.Value())
	}
	return "", fmt.Errorf("value must be a string or a number, got %T", x)
}

// Step is the outcome of one rule (for previews).
type Step struct {
	Index  int               `json:"index"`
	Output map[string]string `json:"output,omitempty"`
	Error  string            `json:"error,omitempty"`
}

func runExporter(rules []rule, in Exporter, steps *[]Step, onErr func(error)) Exporter {
	out := in
	setKeys := map[string]bool{}
	for i, r := range rules {
		v, _, err := r.prog.Eval(map[string]any{"exporter": out.toMap(), "interface": map[string]any{}})
		var fields map[string]string
		if err == nil {
			fields, err = outputs(v)
		}
		if err == nil {
			for k := range fields {
				if !slices.Contains(ExporterKeys, k) {
					err = fmt.Errorf("unknown exporter field %q (allowed: %s)", k, strings.Join(ExporterKeys, ", "))
					break
				}
			}
		}
		if steps != nil {
			st := Step{Index: i, Output: fields}
			if err != nil {
				st.Error = err.Error()
			}
			*steps = append(*steps, st)
		}
		if err != nil {
			onErr(fmt.Errorf("exporter rule %d: %w", i+1, err))
			continue
		}
		for _, k := range ExporterKeys {
			if v := fields[k]; v != "" && !setKeys[k] {
				setKeys[k] = true
				out.set(k, v)
			}
		}
		if len(setKeys) == len(ExporterKeys) {
			break
		}
	}
	return out
}

func runInterface(rules []rule, exp Exporter, in Interface, steps *[]Step, onErr func(error)) Interface {
	out := in
	setKeys := map[string]bool{}
	em := exp.toMap()
	for i, r := range rules {
		v, _, err := r.prog.Eval(map[string]any{"exporter": em, "interface": out.toMap()})
		var fields map[string]string
		if err == nil {
			fields, err = outputs(v)
		}
		if err == nil {
			for k := range fields {
				if !slices.Contains(InterfaceKeys, k) {
					err = fmt.Errorf("unknown interface field %q (allowed: %s)", k, strings.Join(InterfaceKeys, ", "))
					break
				}
			}
		}
		if err == nil {
			next := out
			for _, k := range InterfaceKeys {
				if v := fields[k]; v != "" && !setKeys[k] {
					if e := next.set(k, v); e != nil {
						err = e
						break
					}
				}
			}
			if err == nil {
				for _, k := range InterfaceKeys {
					if fields[k] != "" {
						setKeys[k] = true
					}
				}
				out = next
			}
		}
		if steps != nil {
			st := Step{Index: i, Output: fields}
			if err != nil {
				st.Error = err.Error()
			}
			*steps = append(*steps, st)
		}
		if err != nil {
			onErr(fmt.Errorf("interface rule %d: %w", i+1, err))
			continue
		}
		if len(setKeys) == len(InterfaceKeys) {
			break
		}
	}
	return out
}

// Exporter classifies an exporter. addr keys the cache; results are reused
// while the input is unchanged and the TTL has not expired.
func (s *Set) Exporter(addr netip.Addr, in Exporter) Exporter {
	if !s.HasExporterRules() {
		return in
	}
	now := time.Now()
	if e, ok := s.expCache.get(addr, now); ok && e.in.equal(&in) {
		return e.out
	}
	out := runExporter(s.exporter, in, nil, s.noteErr)
	s.expCache.put(addr, expEntry{in: in, out: out}, now)
	return out
}

// Interface classifies an interface of an (already classified) exporter.
func (s *Set) Interface(addr netip.Addr, exp Exporter, in Interface) Interface {
	if !s.HasInterfaceRules() {
		return in
	}
	now := time.Now()
	k := ifKey{addr, in.Index}
	if e, ok := s.ifCache.get(k, now); ok && e.in == in && e.exp.equal(&exp) {
		return e.out
	}
	out := runInterface(s.iface, exp, in, nil, s.noteErr)
	s.ifCache.put(k, ifEntry{exp: exp, in: in, out: out}, now)
	return out
}

// PreviewRequest is the body of POST /api/classifiers/preview.
type PreviewRequest struct {
	Kind   string   `json:"kind"` // "exporter" or "interface"
	Rules  []string `json:"rules"`
	Sample struct {
		Exporter  Exporter  `json:"exporter"`
		Interface Interface `json:"interface"`
	} `json:"sample"`
}

// PreviewResult is the answer of POST /api/classifiers/preview.
type PreviewResult struct {
	Valid     bool          `json:"valid"`
	Errors    CompileErrors `json:"errors"`
	Steps     []Step        `json:"steps"`
	Exporter  *Exporter     `json:"exporter,omitempty"`
	Interface *Interface    `json:"interface,omitempty"`
}

// Preview compiles and runs rules against a sample without caching.
func Preview(req PreviewRequest) (PreviewResult, error) {
	res := PreviewResult{Errors: CompileErrors{}, Steps: []Step{}}
	switch req.Kind {
	case KindExporter, KindInterface:
	default:
		return res, errors.New(`kind must be "exporter" or "interface"`)
	}
	rules, errs := compile(req.Kind, req.Rules, 100_000)
	if len(errs) > 0 {
		res.Errors = errs
		return res, nil
	}
	res.Valid = true
	ignore := func(error) {}
	if req.Kind == KindExporter {
		out := runExporter(rules, req.Sample.Exporter, &res.Steps, ignore)
		res.Exporter = &out
	} else {
		out := runInterface(rules, req.Sample.Exporter, req.Sample.Interface, &res.Steps, ignore)
		res.Interface = &out
	}
	return res, nil
}
