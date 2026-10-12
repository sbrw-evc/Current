package detector

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sbrw-evc/network/app/backend/internal/schema"
	chstore "github.com/sbrw-evc/network/app/backend/internal/storage/clickhouse"
)

// ipExpr renders an IPv6 column as text, IPv4-mapped addresses unmapped.
func ipExpr(expr string) string {
	return fmt.Sprintf(`replaceRegexpOne(toString(%s), '^::ffff:([0-9.]+)$', '\\1')`, expr)
}

// dimExpr is the String expression of a dimension column.
func dimExpr(name string) string {
	c, _ := schema.ByName(name)
	if c.Kind == schema.KindIP {
		return ipExpr(chstore.QuoteIdent(name))
	}
	return "toString(" + chstore.QuoteIdent(name) + ")"
}

func dimsArray(dims []string) string {
	if len(dims) == 0 {
		return "emptyArrayString()"
	}
	parts := make([]string, len(dims))
	for i, d := range dims {
		parts[i] = dimExpr(d)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func timeWhere(start, end int64, filterSQL string) string {
	if strings.TrimSpace(filterSQL) == "" {
		filterSQL = "1"
	}
	return fmt.Sprintf("TimeReceived >= toDateTime(%d) AND TimeReceived < toDateTime(%d) AND (%s)", start, end, filterSQL)
}

// ipList renders addresses as an IN list of IPv6 values ("" when empty).
func ipList(ips []string) string {
	var parts []string
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("toIPv6('%s')", netip.AddrFrom16(a.As16()).String()))
	}
	return strings.Join(parts, ", ")
}

// ifaceSQL: per exporter, direction and interface the rates over
// [start, end). Columns: exporter, name, ref, dir, ifname, description,
// speed, circuit, boundary, bps, pps.
func ifaceSQL(table string, start, end int64, filterSQL string) string {
	secs := max(end-start, 1)
	return fmt.Sprintf(`SELECT
    %[1]s AS exporter,
    toString(argMax(ExporterName, TimeReceived)),
    toString(argMax(ExporterRef, TimeReceived)),
    tupleElement(i, 1) AS dir,
    tupleElement(i, 2) AS ifname,
    argMax(tupleElement(i, 3), TimeReceived),
    max(tupleElement(i, 4)),
    argMax(tupleElement(i, 5), TimeReceived),
    argMax(tupleElement(i, 6), TimeReceived),
    toFloat64(sum(Bytes)) * 8 / %[2]d,
    toFloat64(sum(Packets)) / %[2]d
FROM %[3]s
ARRAY JOIN [
    ('in', toString(InIfName), toString(InIfDescription), InIfSpeed, toString(InIfCircuit), toString(InIfBoundary)),
    ('out', toString(OutIfName), toString(OutIfDescription), OutIfSpeed, toString(OutIfCircuit), toString(OutIfBoundary))
] AS i
WHERE %[4]s AND tupleElement(i, 2) != ''
GROUP BY exporter, dir, ifname
ORDER BY exporter, ifname, dir`, ipExpr("ExporterAddress"), secs, table, timeWhere(start, end, filterSQL))
}

// commitSQL: per exporter, direction and interface the array of 5-minute bit
// rates over [start, end) and the first bucket. Columns: exporter, dir,
// ifname, name, ref, circuit, rates, first.
func commitSQL(table string, start, end int64, step int64, filterSQL string) string {
	return fmt.Sprintf(`SELECT exporter, dir, ifname,
    toString(argMax(name, t)), toString(argMax(ref, t)), toString(argMax(circuit, t)),
    groupArray(bps), toInt64(toUnixTimestamp(min(t)))
FROM (
    SELECT
        %[1]s AS exporter,
        tupleElement(i, 1) AS dir,
        tupleElement(i, 2) AS ifname,
        TimeReceived AS t,
        any(ExporterName) AS name,
        any(ExporterRef) AS ref,
        any(tupleElement(i, 3)) AS circuit,
        toFloat64(sum(Bytes)) * 8 / %[2]d AS bps
    FROM %[3]s
    ARRAY JOIN [('in', toString(InIfName), toString(InIfCircuit)), ('out', toString(OutIfName), toString(OutIfCircuit))] AS i
    WHERE %[4]s AND tupleElement(i, 2) != ''
    GROUP BY exporter, dir, ifname, t
)
GROUP BY exporter, dir, ifname`, ipExpr("ExporterAddress"), step, table, timeWhere(start, end, filterSQL))
}

// dstSQL: per DstAddr over [start, end) — volumetric (syn false) or SYN
// (syn true) candidates. Columns: addr, host, ci, exporter name, exporter
// ref, exporter address, interface, proto, bps, pps, syn pps.
func dstSQL(table string, start, end int64, filterSQL string, syn bool, having string, limit int) string {
	secs := max(end-start, 1)
	where := timeWhere(start, end, filterSQL)
	order := "bps DESC"
	if syn {
		where += " AND Proto = 6"
		order = "syn DESC"
	}
	return fmt.Sprintf(`SELECT
    %[1]s AS addr,
    toString(argMax(DstHost, Bytes)),
    toString(argMax(DstCI, Bytes)),
    toString(argMax(ExporterName, Bytes)),
    toString(argMax(ExporterRef, Bytes)),
    %[2]s,
    toString(argMax(InIfName, Bytes)),
    toUInt8(topK(1)(Proto)[1]),
    toFloat64(sum(Bytes)) * 8 / %[3]d AS bps,
    toFloat64(sum(Packets)) / %[3]d AS pps,
    toFloat64(sumIf(Packets, bitAnd(TCPFlags, 2) != 0 AND bitAnd(TCPFlags, 16) = 0)) / %[3]d AS syn
FROM %[4]s
WHERE %[5]s
GROUP BY DstAddr
HAVING %[6]s
ORDER BY %[7]s
LIMIT %[8]d`, ipExpr("DstAddr"), ipExpr("argMax(ExporterAddress, Bytes)"), secs, table, where, having, order, limit)
}

// dstBaselineSQL: average bps / pps of the given addresses over [start, end).
func dstBaselineSQL(table string, start, end int64, filterSQL, ips string) string {
	secs := max(end-start, 1)
	return fmt.Sprintf(`SELECT %[1]s AS addr, toFloat64(sum(Bytes)) * 8 / %[2]d, toFloat64(sum(Packets)) / %[2]d
FROM %[3]s
WHERE %[4]s AND DstAddr IN (%[5]s)
GROUP BY DstAddr`, ipExpr("DstAddr"), secs, table, timeWhere(start, end, filterSQL), ips)
}

// groupSQL: per dimensions over [start, end). Columns: k, exporter name,
// exporter ref, exporter address, bps, pps.
func groupSQL(table string, start, end int64, dims []string, filterSQL, order string, limit int) string {
	secs := max(end-start, 1)
	return fmt.Sprintf(`SELECT
    %[1]s AS k,
    toString(argMax(ExporterName, Bytes)),
    toString(argMax(ExporterRef, Bytes)),
    %[2]s,
    toFloat64(sum(Bytes)) * 8 / %[3]d AS bps,
    toFloat64(sum(Packets)) / %[3]d AS pps
FROM %[4]s
WHERE %[5]s
GROUP BY k
ORDER BY %[6]s
LIMIT %[7]d`, dimsArray(dims), ipExpr("argMax(ExporterAddress, Bytes)"), secs, table, timeWhere(start, end, filterSQL), order, limit)
}

// weeklySQL: per dimensions and week back the hourly bit rate at the given
// hour starts of flows_1h. Columns: k, week, bps, exporter name, ref, address.
func weeklySQL(table string, hour int64, hours []int64, dims []string, filterSQL string) string {
	return fmt.Sprintf(`SELECT
    %[1]s AS k,
    toInt64(intDiv(%[2]d - toInt64(toUnixTimestamp(TimeReceived)), 604800)) AS week,
    toFloat64(sum(Bytes)) * 8 / 3600,
    toString(argMax(ExporterName, Bytes)),
    toString(argMax(ExporterRef, Bytes)),
    %[3]s
FROM %[4]s
WHERE TimeReceived IN (%[5]s) AND (%[6]s)
GROUP BY k, week`, dimsArray(dims), hour, ipExpr("argMax(ExporterAddress, Bytes)"), table, hoursList(hours), orOne(filterSQL))
}

// presentSQL: which of the hour starts have any data.
func presentSQL(table string, hours []int64) string {
	return fmt.Sprintf("SELECT DISTINCT toInt64(toUnixTimestamp(TimeReceived)) FROM %s WHERE TimeReceived IN (%s)", table, hoursList(hours))
}

func hoursList(hours []int64) string {
	parts := make([]string, len(hours))
	for i, h := range hours {
		parts[i] = fmt.Sprintf("toDateTime(%d)", h)
	}
	return strings.Join(parts, ", ")
}

func orOne(s string) string {
	if strings.TrimSpace(s) == "" {
		return "1"
	}
	return s
}

// exportersSeenSQL: per exporter the latest name, ref and bucket since start.
func exportersSeenSQL(table string, start int64) string {
	return fmt.Sprintf(`SELECT %s AS addr,
    toString(argMax(ExporterName, TimeReceived)),
    toString(argMax(ExporterRef, TimeReceived)),
    toInt64(toUnixTimestamp(max(TimeReceived)))
FROM %s
WHERE TimeReceived >= toDateTime(%d)
GROUP BY ExporterAddress`, ipExpr("ExporterAddress"), table, start)
}
