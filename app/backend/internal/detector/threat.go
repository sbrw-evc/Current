package detector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KindThreatContact: contact of a host with an address of a threat list
// (flows with SrcThreat or DstThreat set by the enricher), per host on the
// non-threat side; bps ≥ Thresholds.BPS (default 0: any contact) over
// Window.
const KindThreatContact Kind = "threat_contact"

func init() {
	Kinds = append(Kinds, KindThreatContact)
	kindSignals[KindThreatContact] = struct{ signal, method string }{"sec.threat.contact", "RED"}
	kindDefaults[KindThreatContact] = struct{ window, interval time.Duration }{5 * time.Minute, time.Minute}
	defaultTitles[KindThreatContact] = text{
		"Контакт ${host} с адресом из списка угроз ${threat_list} (${threat_ip})",
		"Contact of ${host} with ${threat_ip} from the threat list ${threat_list}",
	}
}

// defaultThreatRule is the built-in threat contact rule.
func defaultThreatRule() Rule {
	m := func(d time.Duration) Duration { return Duration(d) }
	return Rule{
		ID: "threat-contact", Name: "Contact with a threat list address", Enabled: true, Kind: KindThreatContact,
		Window: m(5 * time.Minute), Interval: m(time.Minute), Hysteresis: m(30 * time.Minute), Severity: "error",
	}
}

// threatSQL: per internal host (the side that is not in a threat list) over
// [start, end). Columns: host, host name, CI, PTR, list, lists, threat ip,
// threat ips, outbound, inbound, exporter name, ref, address, bps, pps,
// flows.
func threatSQL(table string, start, end int64, filterSQL string, minBPS float64, limit int) string {
	secs := max(end-start, 1)
	return fmt.Sprintf(`SELECT
    %[1]s AS host,
    toString(argMax(hname, Bytes)),
    toString(argMax(hci, Bytes)),
    toString(argMax(hptr, Bytes)),
    toString(argMax(list, Bytes)),
    arraySort(groupUniqArray(16)(list)),
    %[2]s,
    uniqExact(t),
    countIf(outbound) > 0,
    countIf(NOT outbound) > 0,
    toString(argMax(ExporterName, Bytes)),
    toString(argMax(ExporterRef, Bytes)),
    %[3]s,
    toFloat64(sum(Bytes)) * 8 / %[4]d AS bps,
    toFloat64(sum(Packets)) / %[4]d AS pps,
    count()
FROM (
    SELECT
        SrcThreat = '' AS outbound,
        if(outbound, SrcAddr, DstAddr) AS h,
        if(outbound, DstAddr, SrcAddr) AS t,
        if(outbound, SrcHost, DstHost) AS hname,
        if(outbound, SrcCI, DstCI) AS hci,
        if(outbound, SrcHostPTR, DstHostPTR) AS hptr,
        if(outbound, DstThreat, SrcThreat) AS list,
        ExporterName, ExporterRef, ExporterAddress, Bytes, Packets
    FROM %[5]s
    WHERE %[6]s AND (SrcThreat != '') != (DstThreat != '')
)
GROUP BY h
HAVING bps >= %[7]g
ORDER BY bps DESC
LIMIT %[8]d`, ipExpr("h"), ipExpr("argMax(t, Bytes)"), ipExpr("argMax(ExporterAddress, Bytes)"), secs,
		table, timeWhere(start, end, filterSQL), minBPS, limit)
}

type threatRow struct {
	host, name, ci, ptr, list  string
	lists                      []string
	threatIP                   string
	threatIPs                  uint64
	outbound, inbound          bool
	exporter, exporterRef, exp string
	bps, pps                   float64
	flows                      uint64
}

func (d *Detector) evalThreat(ctx context.Context, e evalCtx) ([]observation, error) {
	table := d.store.Table(d.store.Raw().Table)
	start, end := d.rawWindow(e.now, e.rule.Window.D())
	rows, err := d.conn.Query(ctx, threatSQL(table, start, end, e.fr.SQL, e.rule.Thresholds.BPS, d.groupLimit))
	if err != nil {
		return nil, fmt.Errorf("threat query: %w", err)
	}
	defer rows.Close()
	var out []observation
	for rows.Next() {
		var r threatRow
		if err := rows.Scan(&r.host, &r.name, &r.ci, &r.ptr, &r.list, &r.lists, &r.threatIP, &r.threatIPs,
			&r.outbound, &r.inbound, &r.exporter, &r.exporterRef, &r.exp, &r.bps, &r.pps, &r.flows); err != nil {
			return nil, err
		}
		out = append(out, threatObservation(e, r))
	}
	return out, rows.Err()
}

func threatObservation(e evalCtx, r threatRow) observation {
	dir := "outbound"
	switch {
	case r.outbound && r.inbound:
		dir = "both"
	case r.inbound:
		dir = "inbound"
	}
	host := r.host
	switch {
	case r.name != "":
		host = r.name
	case r.ptr != "":
		host = r.ptr
	}
	sort.Strings(r.lists)
	o := observation{
		key: r.host, group: host, value: r.bps, unit: "bps", breach: true, hold: true,
		ip: r.host, ci: host,
		labels: map[string]string{
			"host_ip": r.host, "threat_list": r.list, "threat_lists": strings.Join(r.lists, ","),
			"threat_ip": r.threatIP, "threat_ips": fmt.Sprint(r.threatIPs), "direction": dir,
			"bps": fmt.Sprintf("%.0f", r.bps), "pps": fmt.Sprintf("%.0f", r.pps), "flows": fmt.Sprint(r.flows),
			"exporter": deviceCI(r.exporter, r.exp),
		},
		vars:       map[string]string{"host": host, "threshold_text": formatRate(e.rule.Thresholds.BPS, "bps", e.lang)},
		linkFilter: andFilters(e.rule.Filter, "(SrcAddr = "+r.host+" OR DstAddr = "+r.host+") AND (SrcThreat != '' OR DstThreat != '')"),
		linkDims:   []string{"SrcAddr", "DstAddr", "DstPort"},
	}
	if r.ci != "" {
		o.ref = r.ci
		o.labels["host_ci"] = r.ci
	}
	if r.name != "" {
		o.labels["host"] = r.name
	}
	if r.ptr != "" {
		o.labels["host_ptr"] = r.ptr
	}
	return o
}
