package detector

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/filter"
)

// observation is the evaluation of one group of one rule.
type observation struct {
	key    string
	group  string // human-readable group
	value  float64
	unit   string // bps, pps, %, min
	breach bool   // condition to enter pending / firing
	hold   bool   // condition to stay firing
	ci     string
	ref    string
	ip     string
	labels map[string]string
	vars   map[string]string // extra title variables
	// link: filter-language text, dimensions and units of the Visualize view.
	linkFilter string
	linkDims   []string
	linkUnits  string
	linkBefore time.Duration // range start before starts_at (default 30m)
}

// evalCtx is the context of one rule evaluation.
type evalCtx struct {
	rule   Rule
	fr     filter.Result
	now    time.Time
	active map[string]*AlertState // states of the rule by key
}

func (d *Detector) evaluate(ctx context.Context, e evalCtx) ([]observation, error) {
	switch e.rule.Kind {
	case KindLinkUtilization:
		return d.evalUtilization(ctx, e)
	case KindLinkCommit:
		return d.evalCommit(ctx, e)
	case KindDDoSVolumetric:
		return d.evalDDoS(ctx, e, false)
	case KindDDoSSyn:
		return d.evalDDoS(ctx, e, true)
	case KindTrafficAnomaly, KindTrafficDrop:
		return d.evalBaseline(ctx, e)
	case KindExporterSilent:
		return d.evalSilent(ctx, e)
	case KindCustom:
		return d.evalCustom(ctx, e)
	}
	return nil, fmt.Errorf("unknown kind %q", e.rule.Kind)
}

// rollupWindow returns the aligned [start, end) of a window over flows_1m.
func (d *Detector) rollupWindow(now time.Time, window time.Duration) (int64, int64) {
	end := now.Add(-d.lag).Truncate(time.Minute)
	if window < time.Minute {
		window = time.Minute
	}
	window = window.Truncate(time.Minute)
	return end.Add(-window).Unix(), end.Unix()
}

func (d *Detector) rawWindow(now time.Time, window time.Duration) (int64, int64) {
	end := now.Add(-d.lag).Truncate(time.Second)
	if window < 10*time.Second {
		window = 10 * time.Second
	}
	return end.Add(-window).Unix(), end.Unix()
}

// tableFor picks flows_1m when every column is in the aggregates, else raw.
func (d *Detector) tableFor(cols ...[]string) (string, bool) {
	for _, cs := range cols {
		for _, c := range cs {
			if !inRollup(c) {
				return d.store.Table(d.store.Raw().Table), false
			}
		}
	}
	return d.store.Table(d.store.Rollups()[0].Table), true
}

type ifaceRow struct {
	exporter, name, ref, dir, ifname, descr string
	speed                                   uint64
	circuit, boundary                       string
	bps, pps                                float64
}

// ifaceRows runs ifaceSQL, cached for the duration of a tick.
func (d *Detector) ifaceRows(ctx context.Context, table string, start, end int64, filterSQL string) ([]ifaceRow, error) {
	q := ifaceSQL(table, start, end, filterSQL)
	if v, ok := d.tickCache[q]; ok {
		return v.([]ifaceRow), nil
	}
	rows, err := d.conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("interfaces query: %w", err)
	}
	defer rows.Close()
	var out []ifaceRow
	for rows.Next() {
		var r ifaceRow
		if err := rows.Scan(&r.exporter, &r.name, &r.ref, &r.dir, &r.ifname, &r.descr, &r.speed, &r.circuit, &r.boundary, &r.bps, &r.pps); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if d.tickCache != nil {
		d.tickCache[q] = out
	}
	return out, nil
}

func deviceCI(name, addr string) string {
	if name != "" {
		return name
	}
	return addr
}

func ifaceFilter(addr, ifname, dir string) string {
	col := "InIfName"
	if dir == "out" {
		col = "OutIfName"
	}
	f := col + " = " + filterString(ifname)
	if a, err := netip.ParseAddr(addr); err == nil {
		f = "ExporterAddress = " + a.Unmap().String() + " AND " + f
	}
	return f
}

func (d *Detector) evalUtilization(ctx context.Context, e evalCtx) ([]observation, error) {
	table, rollup := d.tableFor(e.fr.Columns)
	var start, end int64
	if rollup {
		start, end = d.rollupWindow(e.now, e.rule.Window.D())
	} else {
		start, end = d.rawWindow(e.now, e.rule.Window.D())
	}
	rows, err := d.ifaceRows(ctx, table, start, end, e.fr.SQL)
	if err != nil {
		return nil, err
	}
	th := e.rule.Thresholds.Percent
	var out []observation
	for _, r := range rows {
		if r.speed == 0 {
			continue
		}
		pct := r.bps / float64(r.speed) * 100
		dev := deviceCI(r.name, r.exporter)
		out = append(out, observation{
			key:   r.exporter + "|" + r.ifname + "|" + r.dir,
			group: dev + " " + r.ifname + " " + r.dir,
			value: pct, unit: "%",
			breach: pct >= th, hold: pct >= th,
			ci: dev, ref: r.ref, ip: r.exporter,
			labels: map[string]string{
				"exporter": dev, "exporter_address": r.exporter, "interface": r.ifname, "direction": r.dir,
				"interface_description": r.descr, "speed_bps": fmt.Sprint(r.speed), "bps": fmt.Sprintf("%.0f", r.bps),
				"circuit": r.circuit, "boundary": r.boundary,
			},
			vars:       map[string]string{"threshold_text": formatRate(th, "%"), "bps_text": formatRate(r.bps, "bps")},
			linkFilter: andFilters(e.rule.Filter, ifaceFilter(r.exporter, r.ifname, r.dir)),
			linkDims:   []string{"SrcAS", "DstAS"},
		})
	}
	return out, nil
}

func (d *Detector) evalCommit(ctx context.Context, e evalCtx) ([]observation, error) {
	if d.commit == nil {
		return nil, nil
	}
	const step = int64(300)
	res := d.store.Rollups()[1] // 5m
	end := e.now.Add(-d.lag).Truncate(5 * time.Minute)
	var start time.Time
	if w := e.rule.Window.D(); w > 0 {
		start = end.Add(-w)
	} else {
		y, m, _ := end.UTC().Date()
		start = time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
	}
	if !start.Before(end) {
		return nil, nil
	}
	rows, err := d.conn.Query(ctx, commitSQL(d.store.Table(res.Table), start.Unix(), end.Unix(), step, e.fr.SQL))
	if err != nil {
		return nil, fmt.Errorf("commit query: %w", err)
	}
	defer rows.Close()
	type agg struct {
		exporter, ifname, name, ref, circuit, dir string
		p95                                       float64
	}
	byIface := map[string]*agg{}
	var order []string
	for rows.Next() {
		var exporter, dir, ifname, name, ref, circuit string
		var rates []float64
		var first int64
		if err := rows.Scan(&exporter, &dir, &ifname, &name, &ref, &circuit, &rates, &first); err != nil {
			return nil, err
		}
		total := int((end.Unix() - first) / step)
		p := percentile(rates, total, 95)
		k := exporter + "|" + ifname
		a := byIface[k]
		if a == nil {
			a = &agg{exporter: exporter, ifname: ifname, p95: -1}
			byIface[k] = a
			order = append(order, k)
		}
		if name != "" {
			a.name = name
		}
		if ref != "" {
			a.ref = ref
		}
		if circuit != "" {
			a.circuit = circuit
		}
		if p > a.p95 {
			a.p95, a.dir = p, dir
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []observation
	for _, k := range order {
		a := byIface[k]
		addr, _ := netip.ParseAddr(a.exporter)
		commit, ok := d.commit.Commit(IfaceKey{Exporter: addr, ExporterName: a.name, ExporterRef: a.ref, Interface: a.ifname, Circuit: a.circuit})
		if !ok || commit == 0 {
			continue
		}
		pct := a.p95 / float64(commit) * 100
		th := e.rule.Thresholds.Percent
		dev := deviceCI(a.name, a.exporter)
		out = append(out, observation{
			key: k, group: dev + " " + a.ifname,
			value: pct, unit: "%",
			breach: pct > th, hold: pct > th,
			ci: dev, ref: a.ref, ip: a.exporter,
			labels: map[string]string{
				"exporter": dev, "exporter_address": a.exporter, "interface": a.ifname, "direction": a.dir,
				"circuit": a.circuit, "p95_bps": fmt.Sprintf("%.0f", a.p95), "commit_bps": fmt.Sprint(commit),
			},
			vars: map[string]string{"p95_text": formatRate(a.p95, "bps"), "commit_text": formatRate(float64(commit), "bps"),
				"threshold_text": formatRate(th, "%")},
			linkFilter: andFilters(e.rule.Filter, ifaceFilter(a.exporter, a.ifname, a.dir)),
			linkDims:   []string{"SrcAS", "DstAS"},
			linkBefore: 24 * time.Hour,
		})
	}
	return out, nil
}

type dstRow struct {
	addr, host, ci, exporterName, exporterRef, exporterAddr, iface string
	proto                                                          uint8
	bps, pps, syn                                                  float64
}

func (d *Detector) evalDDoS(ctx context.Context, e evalCtx, syn bool) ([]observation, error) {
	table := d.store.Table(d.store.Raw().Table)
	start, end := d.rawWindow(e.now, e.rule.Window.D())
	th := e.rule.Thresholds
	var conds []string
	if syn {
		conds = append(conds, fmt.Sprintf("syn >= %g", th.PPS))
	} else {
		if th.BPS > 0 {
			conds = append(conds, fmt.Sprintf("bps >= %g", th.BPS))
		}
		if th.PPS > 0 {
			conds = append(conds, fmt.Sprintf("pps >= %g", th.PPS))
		}
	}
	var activeIPs []string
	for k := range e.active {
		activeIPs = append(activeIPs, k)
	}
	if l := ipList(activeIPs); l != "" {
		conds = append(conds, "DstAddr IN ("+l+")")
	}
	if len(conds) == 0 {
		conds = []string{"1"}
	}
	q := dstSQL(table, start, end, e.fr.SQL, syn, strings.Join(conds, " OR "), d.groupLimit)
	rows, err := d.conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dst query: %w", err)
	}
	var list []dstRow
	for rows.Next() {
		var r dstRow
		if err := rows.Scan(&r.addr, &r.host, &r.ci, &r.exporterName, &r.exporterRef, &r.exporterAddr, &r.iface, &r.proto, &r.bps, &r.pps, &r.syn); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Trailing baseline of the candidates (volumetric only).
	base := map[string][2]float64{}
	b := e.rule.Baseline
	if !syn && b != nil && b.Window > 0 && b.K > 0 && len(list) > 0 {
		ips := make([]string, len(list))
		for i, r := range list {
			ips[i] = r.addr
		}
		bq := dstBaselineSQL(table, start-int64(b.Window.D()/time.Second), start, e.fr.SQL, ipList(ips))
		brows, err := d.conn.Query(ctx, bq)
		if err != nil {
			return nil, fmt.Errorf("dst baseline query: %w", err)
		}
		for brows.Next() {
			var addr string
			var bps, pps float64
			if err := brows.Scan(&addr, &bps, &pps); err != nil {
				brows.Close()
				return nil, err
			}
			base[addr] = [2]float64{bps, pps}
		}
		brows.Close()
	}

	var out []observation
	for _, r := range list {
		o := observation{key: r.addr, group: r.addr, ip: r.addr}
		labels := map[string]string{"dst_ip": r.addr, "proto": protoName(r.proto), "bps": fmt.Sprintf("%.0f", r.bps),
			"pps": fmt.Sprintf("%.0f", r.pps), "exporter": r.exporterName, "interface": r.iface}
		vars := map[string]string{}
		if syn {
			ratio := 0.0
			if r.pps > 0 {
				ratio = r.syn / r.pps
			}
			o.value, o.unit = ratio*100, "%"
			o.breach = r.syn >= th.PPS && ratio >= th.Ratio
			o.hold = o.breach
			labels["syn_pps"] = fmt.Sprintf("%.0f", r.syn)
			labels["syn_ratio"] = trimFloat(ratio*100, 1) + " %"
			vars["threshold_text"] = formatRate(th.Ratio*100, "%")
			o.linkFilter = andFilters(e.rule.Filter, "DstAddr = "+r.addr+" AND Proto = 6")
			o.linkDims = []string{"SrcAddr", "DstPort"}
			o.linkUnits = "pps"
		} else {
			over := (th.BPS > 0 && r.bps >= th.BPS) || (th.PPS > 0 && r.pps >= th.PPS)
			o.hold = over
			bl := base[r.addr]
			k := 0.0
			if b != nil {
				k = b.K
			}
			aboveBase := (th.BPS > 0 && r.bps >= th.BPS && r.bps > k*bl[0]) || (th.PPS > 0 && r.pps >= th.PPS && r.pps > k*bl[1])
			o.breach = over && aboveBase
			o.value, o.unit = r.bps, "bps"
			if th.BPS <= 0 {
				o.value, o.unit = r.pps, "pps"
			}
			labels["baseline_bps"] = fmt.Sprintf("%.0f", bl[0])
			labels["baseline_pps"] = fmt.Sprintf("%.0f", bl[1])
			vars["threshold_text"] = formatRate(th.BPS, "bps")
			vars["pps_text"] = formatRate(r.pps, "pps")
			o.linkFilter = andFilters(e.rule.Filter, "DstAddr = "+r.addr)
			o.linkDims = []string{"SrcAddr", "Proto", "DstPort"}
		}
		// CI: the destination host (IPAM), else the edge router.
		switch {
		case r.ci != "":
			o.ref, o.ci = r.ci, r.host
		case r.host != "":
			o.ci = r.host
		default:
			o.ci, o.ref = deviceCI(r.exporterName, r.exporterAddr), r.exporterRef
		}
		if r.host != "" {
			labels["dst_host"] = r.host
		}
		if r.ci != "" {
			labels["dst_ci"] = r.ci
		}
		o.labels, o.vars = labels, vars
		out = append(out, o)
	}
	return out, nil
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 58:
		return "icmpv6"
	}
	return fmt.Sprint(p)
}

type groupRow struct {
	vals            []string
	name, ref, addr string
	bps, pps        float64
}

func groupKey(vals []string) string { return strings.Join(vals, "\x1f") }

func groupText(dims, vals []string) string {
	if len(dims) == 0 {
		return "весь трафик"
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		if v == "" {
			v = "—"
		}
		parts[i] = v
	}
	return strings.Join(parts, " / ")
}

func (d *Detector) groupRows(ctx context.Context, q string) ([]groupRow, error) {
	rows, err := d.conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("group query: %w", err)
	}
	defer rows.Close()
	var out []groupRow
	for rows.Next() {
		var r groupRow
		if err := rows.Scan(&r.vals, &r.name, &r.ref, &r.addr, &r.bps, &r.pps); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// groupObservation fills the CI, labels and link of a dimensions group.
func groupObservation(e evalCtx, vals []string, name, ref, addr string) observation {
	dims := e.rule.Dimensions
	o := observation{key: groupKey(vals), group: groupText(dims, vals), labels: map[string]string{}, vars: map[string]string{}}
	var eqs []string
	idx := map[string]string{}
	for i, dim := range dims {
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		idx[dim] = v
		o.labels[dim] = v
		eqs = append(eqs, dim+" = "+filterValue(dim, v))
	}
	switch {
	case idx["DstCI"] != "":
		o.ref = idx["DstCI"]
	case idx["SrcCI"] != "":
		o.ref = idx["SrcCI"]
	case idx["ExporterName"] != "":
		o.ci, o.ref, o.ip = idx["ExporterName"], ref, addr
	default:
		o.ci, o.ref, o.ip = deviceCI(name, addr), ref, addr
	}
	if v := idx["ExporterName"]; v != "" {
		o.labels["exporter"] = v
	} else if name != "" {
		o.labels["exporter"] = name
	}
	if v, ok := idx["InIfName"]; ok {
		o.labels["interface"] = v
	} else if v, ok := idx["OutIfName"]; ok {
		o.labels["interface"] = v
	}
	o.linkFilter = andFilters(e.rule.Filter, strings.Join(eqs, " AND "))
	o.linkDims = []string{"SrcAS", "DstAS"}
	return o
}

// evalBaseline handles traffic_anomaly and traffic_drop.
func (d *Detector) evalBaseline(ctx context.Context, e evalCtx) ([]observation, error) {
	r := e.rule
	b := *r.Baseline
	table1m := d.store.Table(d.store.Rollups()[0].Table)
	table1h := d.store.Table(d.store.Rollups()[2].Table)
	start, end := d.rollupWindow(e.now, r.Window.D())
	mid := time.Unix((start+end)/2, 0).UTC()
	hour := mid.Truncate(time.Hour).Unix()
	hours := make([]int64, b.Weeks)
	for w := 1; w <= b.Weeks; w++ {
		hours[w-1] = hour - int64(w)*7*24*3600
	}
	if len(hours) == 0 {
		return nil, nil
	}

	present := map[int64]bool{}
	prow, err := d.conn.Query(ctx, presentSQL(table1h, hours))
	if err != nil {
		return nil, fmt.Errorf("baseline presence query: %w", err)
	}
	for prow.Next() {
		var t int64
		if err := prow.Scan(&t); err != nil {
			prow.Close()
			return nil, err
		}
		present[t] = true
	}
	prow.Close()
	var weeks []int64 // week numbers with data
	for w := 1; w <= b.Weeks; w++ {
		if present[hours[w-1]] {
			weeks = append(weeks, int64(w))
		}
	}

	type bgroup struct {
		vals            []string
		byWeek          map[int64]float64
		name, ref, addr string
	}
	groups := map[string]*bgroup{}
	var order []string
	if len(weeks) > 0 {
		wrows, err := d.conn.Query(ctx, weeklySQL(table1h, hour, hours, r.Dimensions, e.fr.SQL))
		if err != nil {
			return nil, fmt.Errorf("baseline query: %w", err)
		}
		for wrows.Next() {
			var vals []string
			var week int64
			var bps float64
			var name, ref, addr string
			if err := wrows.Scan(&vals, &week, &bps, &name, &ref, &addr); err != nil {
				wrows.Close()
				return nil, err
			}
			k := groupKey(vals)
			g := groups[k]
			if g == nil {
				g = &bgroup{vals: vals, byWeek: map[int64]float64{}}
				groups[k] = g
				order = append(order, k)
			}
			g.byWeek[week] += bps
			if g.name == "" {
				g.name, g.ref, g.addr = name, ref, addr
			}
		}
		wrows.Close()
		if err := wrows.Err(); err != nil {
			return nil, err
		}
	}

	cur, err := d.groupRows(ctx, groupSQL(table1m, start, end, r.Dimensions, e.fr.SQL, "bps DESC", max(d.groupLimit, 10000)))
	if err != nil {
		return nil, err
	}
	current := map[string]groupRow{}
	for _, c := range cur {
		k := groupKey(c.vals)
		current[k] = c
		if groups[k] == nil {
			groups[k] = &bgroup{vals: c.vals, byWeek: map[int64]float64{}, name: c.name, ref: c.ref, addr: c.addr}
			order = append(order, k)
		}
	}

	var out []observation
	for _, k := range order {
		g := groups[k]
		samples := make([]float64, 0, len(weeks))
		for _, w := range weeks {
			samples = append(samples, g.byWeek[w])
		}
		c, seen := current[k]
		name, ref, addr := g.name, g.ref, g.addr
		if seen {
			name, ref, addr = c.name, c.ref, c.addr
		}
		o := groupObservation(e, g.vals, name, ref, addr)
		o.value, o.unit = c.bps, "bps"
		var expected float64
		if r.Kind == KindTrafficAnomaly {
			res := anomaly(c.bps, samples, b)
			expected, o.breach = res.Expected, res.Breach
			if res.Direction != "" {
				o.labels["deviation_direction"] = res.Direction
			}
			if !math.IsInf(res.Deviation, 0) {
				o.labels["deviation_sigma"] = trimFloat(res.Deviation, 1)
			}
		} else {
			expected, o.breach = drop(c.bps, samples, r.Thresholds.Ratio, b.MinVolume, b.MinSamples)
			if expected == 0 && !seen {
				continue
			}
		}
		if len(samples) < b.MinSamples && !seen {
			continue
		}
		o.hold = o.breach
		o.labels["expected_bps"] = fmt.Sprintf("%.0f", expected)
		o.labels["baseline_weeks"] = fmt.Sprint(len(samples))
		o.vars["expected_text"] = formatRate(expected, "bps")
		out = append(out, o)
	}
	return out, nil
}

func (d *Detector) evalCustom(ctx context.Context, e evalCtx) ([]observation, error) {
	r := e.rule
	table, rollup := d.tableFor(e.fr.Columns, r.Dimensions)
	var start, end int64
	if rollup {
		start, end = d.rollupWindow(e.now, r.Window.D())
	} else {
		start, end = d.rawWindow(e.now, r.Window.D())
	}
	metric, th := "bps", r.Thresholds.BPS
	if r.Metric == "pps" {
		metric, th = "pps", r.Thresholds.PPS
	}
	order := metric + " DESC"
	if r.Operator == "<" {
		order = metric + " ASC"
	}
	rows, err := d.groupRows(ctx, groupSQL(table, start, end, r.Dimensions, e.fr.SQL, order, d.groupLimit))
	if err != nil {
		return nil, err
	}
	var out []observation
	for _, g := range rows {
		o := groupObservation(e, g.vals, g.name, g.ref, g.addr)
		v := g.bps
		if metric == "pps" {
			v = g.pps
		}
		o.value, o.unit = v, metric
		if r.Operator == "<" {
			o.breach = v < th
		} else {
			o.breach = v > th
		}
		o.hold = o.breach
		o.vars["threshold_text"] = formatRate(th, metric)
		if metric == "pps" {
			o.linkUnits = "pps"
		}
		out = append(out, o)
	}
	return out, nil
}

type seenExporter struct {
	name, ref string
	last      time.Time
}

// exportersFromFlows returns the exporters seen in the flows of the last
// week: name, ref and last-seen (minute precision for the last 2 hours).
func (d *Detector) exportersFromFlows(ctx context.Context, now time.Time) (map[string]*seenExporter, error) {
	if v, ok := d.tickCache["exporters"]; ok {
		return v.(map[string]*seenExporter), nil
	}
	out := map[string]*seenExporter{}
	read := func(table string, since time.Time, width time.Duration) error {
		rows, err := d.conn.Query(ctx, exportersSeenSQL(table, since.Unix()))
		if err != nil {
			return fmt.Errorf("exporters query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var addr, name, ref string
			var last int64
			if err := rows.Scan(&addr, &name, &ref, &last); err != nil {
				return err
			}
			t := time.Unix(last, 0).Add(width)
			if t.After(now) {
				t = now
			}
			s := out[addr]
			if s == nil {
				s = &seenExporter{}
				out[addr] = s
			}
			if s.name == "" {
				s.name, s.ref = name, ref
			}
			if s.last.IsZero() || width == time.Minute {
				s.last = t
			}
		}
		return rows.Err()
	}
	if err := read(d.store.Table(d.store.Rollups()[2].Table), now.Add(-7*24*time.Hour).Truncate(time.Hour), time.Hour); err != nil {
		return nil, err
	}
	if err := read(d.store.Table(d.store.Rollups()[0].Table), now.Add(-2*time.Hour), time.Minute); err != nil {
		return nil, err
	}
	if d.tickCache != nil {
		d.tickCache["exporters"] = out
	}
	return out, nil
}

func (d *Detector) evalSilent(ctx context.Context, e evalCtx) ([]observation, error) {
	flows, err := d.exportersFromFlows(ctx, e.now)
	if err != nil && d.exporters == nil {
		return nil, err
	}
	type exp struct {
		addr, name, ref string
		last            time.Time
	}
	var list []exp
	if d.exporters != nil {
		for _, x := range d.exporters.Exporters() {
			if !x.Address.IsValid() || x.LastSeen.IsZero() {
				continue
			}
			a := x.Address.Unmap().String()
			ex := exp{addr: a, name: x.Name, ref: x.Ref, last: x.LastSeen}
			if f := flows[a]; f != nil {
				if ex.name == "" {
					ex.name = f.name
				}
				if ex.ref == "" {
					ex.ref = f.ref
				}
			}
			list = append(list, ex)
		}
	} else {
		for a, f := range flows {
			list = append(list, exp{addr: a, name: f.name, ref: f.ref, last: f.last})
		}
	}
	slices.SortFunc(list, func(a, b exp) int { return strings.Compare(a.addr, b.addr) })
	silence := e.rule.Thresholds.Silence.D()
	var out []observation
	for _, x := range list {
		gap := e.now.Sub(x.last)
		if gap < 0 {
			gap = 0
		}
		dev := deviceCI(x.name, x.addr)
		breach := gap >= silence
		out = append(out, observation{
			key: x.addr, group: dev, value: math.Floor(gap.Minutes()), unit: "min",
			breach: breach, hold: breach,
			ci: dev, ref: x.ref, ip: x.addr,
			labels:     map[string]string{"exporter": dev, "exporter_address": x.addr, "last_seen": rfc3339(x.last)},
			vars:       map[string]string{"threshold_text": formatRate(silence.Minutes(), "min")},
			linkFilter: "ExporterAddress = " + x.addr,
			linkDims:   []string{"ExporterName", "InIfName"},
			linkBefore: 2 * time.Hour,
		})
	}
	return out, nil
}
