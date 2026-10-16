package query

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Traffic of Ledger objects (docs/integrations.md §2.1): current rates,
// a sparkline and the 95th percentile since the start of the month, for many
// objects of one type in a fixed number of queries.

// Ledger object types served by the integration.
const (
	ObjectDevice    = "dcim.device"
	ObjectInterface = "dcim.interface"
	ObjectCircuit   = "circuits.circuit"
)

// SparklinePoints is the number of sparkline points.
const SparklinePoints = 48

// CurrentWindow is the period of the "current" rates.
const CurrentWindow = 5 * time.Minute

// ObjectTarget says which flows belong to one object.
type ObjectTarget struct {
	ID string // result key
	// Ref is the device source_ref (ExporterRef) of a device or interface.
	Ref string
	// IfName is the interface name (case-insensitive).
	IfName string
	// Circuit is the circuit cid (InIfCircuit / OutIfCircuit).
	Circuit string
	// P95 asks for the monthly 95th percentile.
	P95 bool
}

// ObjectTrafficRequest asks for the traffic of objects of one type.
type ObjectTrafficRequest struct {
	Type    string // ObjectDevice, ObjectInterface, ObjectCircuit
	Targets []ObjectTarget
	Window  time.Duration // sparkline span (default 24 h)
}

// Sparkline of an object: SparklinePoints rates in bits per second.
type Sparkline struct {
	T   []time.Time `json:"t"`
	In  []float64   `json:"in"`
	Out []float64   `json:"out"`
}

// ObjectTraffic is the traffic of one object.
type ObjectTraffic struct {
	InBps  float64 // last CurrentWindow (complete minutes)
	OutBps float64
	// SpeedBps is the highest interface speed the flows carried (0 = unknown).
	SpeedBps  uint64
	Sparkline Sparkline
	LastSeen  *time.Time
	// P95MonthBps: 95th percentile of the 5-minute rates since the start of
	// the month (UTC), the larger of both directions; nil unless asked.
	P95MonthBps *float64
}

// objectKeys returns, for a type, the per-direction key expressions, the
// key of a target and a prefilter over the targets.
func objectKeys(typ string, targets []ObjectTarget) (in, out string, key func(ObjectTarget) string, pre string, err error) {
	switch typ {
	case ObjectDevice:
		refs := uniq(targets, func(t ObjectTarget) string { return t.Ref })
		return `if(InIfIndex != 0 OR InIfName != '', toString(ExporterRef), '')`,
			`if(OutIfIndex != 0 OR OutIfName != '', toString(ExporterRef), '')`,
			func(t ObjectTarget) string { return t.Ref },
			"ExporterRef IN " + stringList(refs), nil
	case ObjectInterface:
		refs := uniq(targets, func(t ObjectTarget) string { return t.Ref })
		names := uniq(targets, func(t ObjectTarget) string { return strings.ToLower(t.IfName) })
		return `concat(toString(ExporterRef), '|', lower(toString(InIfName)))`,
			`concat(toString(ExporterRef), '|', lower(toString(OutIfName)))`,
			func(t ObjectTarget) string { return t.Ref + "|" + strings.ToLower(t.IfName) },
			fmt.Sprintf("ExporterRef IN %[1]s AND (lower(toString(InIfName)) IN %[2]s OR lower(toString(OutIfName)) IN %[2]s)",
				stringList(refs), stringList(names)), nil
	case ObjectCircuit:
		cids := uniq(targets, func(t ObjectTarget) string { return t.Circuit })
		return "toString(InIfCircuit)", "toString(OutIfCircuit)",
			func(t ObjectTarget) string { return t.Circuit },
			fmt.Sprintf("(InIfCircuit IN %[1]s OR OutIfCircuit IN %[1]s)", stringList(cids)), nil
	}
	return "", "", nil, "", &ValidationError{Field: "object_type", Message: "must be dcim.device, dcim.interface or circuits.circuit"}
}

func uniq(ts []ObjectTarget, f func(ObjectTarget) string) []string {
	var out []string
	for _, t := range ts {
		if v := f(t); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func stringList(vs []string) string {
	if len(vs) == 0 {
		return "('')"
	}
	q := make([]string, len(vs))
	for i, v := range vs {
		q[i] = quoteString(v)
	}
	return "(" + strings.Join(q, ", ") + ")"
}

// objectRows is the inner query: one row per (direction, key) of every flow
// of the targets, with Bytes, TimeReceived and the interface speed.
func objectRows(table, in, out, pre string, start, end int64, keys string) string {
	return fmt.Sprintf(`SELECT j.1 AS d, j.2 AS k, j.3 AS speed, Bytes, TimeReceived
    FROM %[1]s
    ARRAY JOIN [(toUInt8(0), %[2]s, InIfSpeed), (toUInt8(1), %[3]s, OutIfSpeed)] AS j
    WHERE TimeReceived >= toDateTime(%[4]d) AND TimeReceived < toDateTime(%[5]d) AND (%[6]s) AND j.2 IN %[7]s`,
		table, in, out, start, end, pre, keys)
}

// ObjectTraffic returns the traffic of the targets by target ID. Targets
// without any flow in the window are present with zero rates and no
// last_seen.
func (q *Querier) ObjectTraffic(ctx context.Context, req ObjectTrafficRequest) (map[string]*ObjectTraffic, error) {
	out := map[string]*ObjectTraffic{}
	if req.Window <= 0 {
		req.Window = 24 * time.Hour
	}
	in, outE, keyOf, pre, err := objectKeys(req.Type, req.Targets)
	if err != nil {
		return nil, err
	}
	byKey := map[string][]string{}
	var keys []string
	for _, t := range req.Targets {
		k := keyOf(t)
		if k == "" || k == "|" {
			continue
		}
		if _, ok := byKey[k]; !ok {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], t.ID)
	}
	if len(keys) == 0 {
		return out, nil
	}
	keyList := stringList(keys)
	now := q.now().UTC()
	rollups := q.store.Rollups()
	r1m, r5m := rollups[0], rollups[1]

	// Sparkline: SparklinePoints complete buckets ending at the last bucket
	// boundary, from the coarsest table that fits.
	res := chooseResolution(q.store, []string{"ExporterRef", "InIfName", "OutIfName", "InIfCircuit", "OutIfCircuit"},
		now.Add(-req.Window), now, SparklinePoints, now)
	step := int64(math.Ceil(req.Window.Seconds() / SparklinePoints))
	if iv := int64(res.Interval / time.Second); iv > 0 {
		step = (step + iv - 1) / iv * iv
	}
	if step < 1 {
		step = 1
	}
	sEnd := now.Unix() / step * step
	sStart := sEnd - SparklinePoints*step
	ts := make([]time.Time, SparklinePoints)
	for i := range ts {
		ts[i] = time.Unix(sStart+int64(i)*step, 0).UTC()
	}
	get := func(k string) []*ObjectTraffic {
		var list []*ObjectTraffic
		for _, id := range byKey[k] {
			o := out[id]
			list = append(list, o)
		}
		return list
	}
	for _, t := range req.Targets {
		if _, ok := byKey[keyOf(t)]; !ok {
			continue
		}
		out[t.ID] = &ObjectTraffic{Sparkline: Sparkline{T: ts, In: make([]float64, SparklinePoints), Out: make([]float64, SparklinePoints)}}
	}

	// 1. current rates, speed and last seen (flows_1m over the window).
	mEnd := now.Unix() / 60 * 60
	curStart := mEnd - int64(CurrentWindow/time.Second)
	lsStart := now.Add(-req.Window).Unix()
	if ttl := now.Add(-r1m.TTL).Unix(); lsStart < ttl {
		lsStart = ttl
	}
	if lsStart > curStart {
		lsStart = curStart
	}
	sql1 := fmt.Sprintf(`SELECT k, d, toFloat64(sumIf(Bytes, TimeReceived >= toDateTime(%[1]d) AND TimeReceived < toDateTime(%[2]d))) * 8 / %[3]d,
    max(speed), max(TimeReceived)
FROM (%[4]s)
GROUP BY k, d`, curStart, mEnd, mEnd-curStart, objectRows(q.table(r1m), in, outE, pre, lsStart, now.Unix()+60, keyList))
	rows, err := q.conn.Query(ctx, sql1)
	if err != nil {
		return nil, fmt.Errorf("object traffic: %w", err)
	}
	for rows.Next() {
		var k string
		var d uint8
		var rate float64
		var speed uint64
		var last time.Time
		if err := rows.Scan(&k, &d, &rate, &speed, &last); err != nil {
			rows.Close()
			return nil, fmt.Errorf("object traffic: %w", err)
		}
		for _, o := range get(k) {
			if d == 0 {
				o.InBps = rate
			} else {
				o.OutBps = rate
			}
			o.SpeedBps = max(o.SpeedBps, speed)
			if !last.IsZero() && (o.LastSeen == nil || last.After(*o.LastSeen)) {
				l := last.UTC()
				o.LastSeen = &l
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("object traffic: %w", err)
	}

	// 2. sparkline.
	sql2 := fmt.Sprintf(`SELECT k, d, toUInt32(intDiv(toUInt32(TimeReceived) - %[1]d, %[2]d)) AS b, toFloat64(sum(Bytes)) * 8 / %[2]d
FROM (%[3]s)
GROUP BY k, d, b`, sStart, step, objectRows(q.table(res), in, outE, pre, sStart, sEnd, keyList))
	rows, err = q.conn.Query(ctx, sql2)
	if err != nil {
		return nil, fmt.Errorf("object traffic: sparkline: %w", err)
	}
	for rows.Next() {
		var k string
		var d uint8
		var b uint32
		var rate float64
		if err := rows.Scan(&k, &d, &b, &rate); err != nil {
			rows.Close()
			return nil, fmt.Errorf("object traffic: sparkline: %w", err)
		}
		if int(b) >= SparklinePoints {
			continue
		}
		for _, o := range get(k) {
			if d == 0 {
				o.Sparkline.In[b] = rate
			} else {
				o.Sparkline.Out[b] = rate
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("object traffic: sparkline: %w", err)
	}

	// 3. 95th percentile of the 5-minute rates since the start of the month,
	// counting 5-minute periods without traffic as zero.
	var p95Keys []string
	for _, t := range req.Targets {
		if k := keyOf(t); t.P95 && !slices.Contains(p95Keys, k) {
			if _, ok := byKey[k]; ok {
				p95Keys = append(p95Keys, k)
			}
		}
	}
	if len(p95Keys) == 0 {
		return out, nil
	}
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Unix()
	pEnd := now.Unix() / 300 * 300
	n := (pEnd - month) / 300
	if n < 1 {
		return out, nil
	}
	sql3 := fmt.Sprintf(`SELECT k,
    greatest(
        arrayReduce('quantileExact(0.95)', arrayResize(groupArrayIf(r, d = 0), %[1]d, toFloat64(0))),
        arrayReduce('quantileExact(0.95)', arrayResize(groupArrayIf(r, d = 1), %[1]d, toFloat64(0))))
FROM (
    SELECT k, d, toStartOfFiveMinutes(TimeReceived) AS b, toFloat64(sum(Bytes)) * 8 / 300 AS r
    FROM (%[2]s)
    GROUP BY k, d, b
)
GROUP BY k`, n, objectRows(q.table(r5m), in, outE, pre, month, pEnd, stringList(p95Keys)))
	rows, err = q.conn.Query(ctx, sql3)
	if err != nil {
		return nil, fmt.Errorf("object traffic: p95: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var k string
		var p float64
		if err := rows.Scan(&k, &p); err != nil {
			return nil, fmt.Errorf("object traffic: p95: %w", err)
		}
		seen[k] = true
		for _, o := range get(k) {
			v := p
			o.P95MonthBps = &v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("object traffic: p95: %w", err)
	}
	for _, k := range p95Keys {
		if !seen[k] {
			for _, o := range get(k) {
				zero := 0.0
				o.P95MonthBps = &zero
			}
		}
	}
	return out, nil
}

// PrefixAddress is an address seen in the flows inside a prefix.
type PrefixAddress struct {
	Address  netip.Addr
	Bytes    uint64
	Flows    uint64
	LastSeen time.Time
}

// MaxPrefixAddresses bounds PrefixAddresses.
const MaxPrefixAddresses = 1024

// PrefixAddresses lists the addresses inside prefix seen as source or
// destination in the raw flows of the last window (ordered by bytes, at most
// MaxPrefixAddresses). vrf, when set, keeps only the flow ends enriched with
// that IPAM VRF.
func (q *Querier) PrefixAddresses(ctx context.Context, prefix netip.Prefix, vrf string, window time.Duration) ([]PrefixAddress, error) {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return nil, &ValidationError{Field: "prefix", Message: "invalid prefix"}
	}
	raw := q.store.Raw()
	if window <= 0 {
		window = 24 * time.Hour
	}
	if window > raw.TTL {
		window = raw.TTL
	}
	lo, hi := prefixRange(prefix)
	now := q.now().UTC()
	cond := func(x string) string {
		return fmt.Sprintf("%[1]s >= toIPv6('%[2]s') AND %[1]s <= toIPv6('%[3]s')", x, lo, hi)
	}
	vrfCond := "1"
	if vrf != "" {
		vrfCond = "x.2 = " + quoteString(vrf)
	}
	sql := fmt.Sprintf(`SELECT toString(a.1) AS addr, sum(Bytes) AS bytes, count() AS flows, max(TimeReceived) AS last
FROM (
    SELECT arrayJoin(arrayDistinct(arrayFilter(x -> %[1]s AND %[2]s,
        [(SrcAddr, toString(SrcNetVRF)), (DstAddr, toString(DstNetVRF))]))) AS a, Bytes, TimeReceived
    FROM %[3]s
    WHERE TimeReceived >= toDateTime(%[4]d) AND TimeReceived <= toDateTime(%[5]d) AND ((%[6]s) OR (%[7]s))
)
GROUP BY addr
ORDER BY bytes DESC, addr
LIMIT %[8]d`, cond("x.1"), vrfCond, q.table(raw), now.Add(-window).Unix(), now.Unix(), cond("SrcAddr"), cond("DstAddr"), MaxPrefixAddresses)
	rows, err := q.conn.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("prefix addresses: %w", err)
	}
	defer rows.Close()
	out := []PrefixAddress{}
	for rows.Next() {
		var s string
		var p PrefixAddress
		if err := rows.Scan(&s, &p.Bytes, &p.Flows, &p.LastSeen); err != nil {
			return nil, fmt.Errorf("prefix addresses: %w", err)
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		p.Address, p.LastSeen = a.Unmap(), p.LastSeen.UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// prefixRange returns the first and last address of p as IPv6 text
// (IPv4 as IPv4-mapped, as ClickHouse stores it).
func prefixRange(p netip.Prefix) (string, string) {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		a = netip.AddrFrom16(a.As16())
		bits += 96
	}
	b := a.As16()
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return a.StringExpanded(), netip.AddrFrom16(b).StringExpanded()
}
