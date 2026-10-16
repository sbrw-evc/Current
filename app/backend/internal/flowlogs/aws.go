package flowlogs

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/flow"
)

// DefaultAWSFields is the default (version 2) VPC Flow Logs format.
var DefaultAWSFields = []string{"version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
	"protocol", "packets", "bytes", "start", "end", "action", "log-status"}

// Forwarding status values (IPFIX forwardingStatus, RFC 7270).
const (
	fwdForwarded = 64
	fwdDropped   = 128
)

// parseFields reads a custom format: "${version} ${srcaddr} …", "version
// srcaddr …" or "version,srcaddr,…"; underscores are taken as hyphens
// (Parquet / Athena names).
func parseFields(s string) []string {
	s = strings.NewReplacer("${", " ", "}", " ", ",", " ").Replace(s)
	fs := strings.Fields(s)
	for i, f := range fs {
		fs[i] = strings.ReplaceAll(strings.ToLower(f), "_", "-")
	}
	return fs
}

// isHeader: a line naming fields rather than holding values.
func isHeader(fs []string) bool {
	has := false
	for _, f := range fs {
		if f == "srcaddr" || f == "dstaddr" {
			has = true
		}
	}
	return has && len(fs) > 0 && (fs[0] < "0" || fs[0] > "9")
}

// awsParser converts lines with a field layout.
type awsParser struct {
	b      *batch
	fields []string
	idx    map[string]int
}

func newAWSParser(b *batch, fields string) *awsParser {
	p := &awsParser{b: b}
	if fs := parseFields(fields); len(fs) > 0 {
		p.setFields(fs)
	} else {
		p.setFields(DefaultAWSFields)
	}
	return p
}

func (p *awsParser) setFields(fs []string) {
	p.fields = fs
	p.idx = make(map[string]int, len(fs))
	for i, f := range fs {
		p.idx[f] = i
	}
}

func (p *awsParser) line(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	fs := strings.Fields(s)
	if isHeader(parseFields(s)) {
		p.setFields(parseFields(s))
		return
	}
	if len(fs) != len(p.fields) {
		p.b.skip()
		return
	}
	get := func(name string) string {
		if i, ok := p.idx[name]; ok {
			if v := fs[i]; v != "-" {
				return v
			}
		}
		return ""
	}
	if st := get("log-status"); st != "" && st != "OK" {
		p.b.skip() // NODATA / SKIPDATA
		return
	}
	src, err1 := netip.ParseAddr(get("srcaddr"))
	dst, err2 := netip.ParseAddr(get("dstaddr"))
	if err1 != nil || err2 != nil {
		p.b.skip()
		return
	}
	f := &flow.Flow{FlowType: FlowTypeAWS, SrcAddr: src, DstAddr: dst}
	f.SrcPort = uint16(num(get("srcport")))
	f.DstPort = uint16(num(get("dstport")))
	f.Proto = uint8(num(get("protocol")))
	f.Packets = num(get("packets"))
	f.Bytes = num(get("bytes"))
	f.TCPFlags = uint8(num(get("tcp-flags")))
	if s := num(get("start")); s > 0 {
		f.TimeFlowStart = time.Unix(int64(s), 0).UTC()
	}
	if e := num(get("end")); e > 0 {
		f.TimeFlowEnd = time.Unix(int64(e), 0).UTC()
	}
	switch get("action") {
	case "ACCEPT":
		f.ForwardingStatus = fwdForwarded
	case "REJECT":
		f.ForwardingStatus = fwdDropped
	}
	f.EType = etype(src)
	if t := get("type"); t == "IPv6" {
		f.EType = 0x86dd
	}
	eni, vpc, account := get("interface-id"), get("vpc-id"), get("account-id")
	name := strings.Trim(vpc+"/"+eni, "/")
	switch a, ok := awsAddr(eni); {
	case ok:
		f.ExporterAddress = exporter(a, name)
	default:
		if a, ok := awsAddr(vpc); ok {
			f.ExporterAddress = exporter(a, name)
		} else if account != "" {
			f.ExporterAddress = exporter(hashAddr("aws:"+account), "aws-"+account)
		} else {
			f.ExporterAddress = netip.IPv4Unspecified()
		}
	}
	p.b.add(f)
}

func etype(a netip.Addr) uint16 {
	if a.Unmap().Is4() {
		return 0x0800
	}
	return 0x86dd
}

func num(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// parseAWSBody reads plain text lines (S3 / CloudWatch export, optionally
// with a header line) or a CloudWatch Logs subscription JSON payload.
func parseAWSBody(body []byte, b *batch, fields string) error {
	body, err := gunzipMaybe(body, b.h.cfg.MaxBody)
	if err != nil {
		return badRequest("gzip: %v", err)
	}
	p := newAWSParser(b, fields)
	return p.payload(body)
}

// payload handles one block of data: CloudWatch Logs JSON or text lines.
func (p *awsParser) payload(data []byte) error {
	t := bytes.TrimSpace(data)
	if len(t) > 0 && t[0] == '{' {
		var cw struct {
			MessageType string `json:"messageType"`
			LogEvents   []struct {
				Message string `json:"message"`
			} `json:"logEvents"`
		}
		if err := json.Unmarshal(t, &cw); err != nil {
			return badRequest("JSON: %v", err)
		}
		if cw.MessageType == "CONTROL_MESSAGE" {
			return nil
		}
		for _, e := range cw.LogEvents {
			p.line(e.Message)
		}
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		p.line(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return badRequest("lines: %v", err)
	}
	return nil
}

// parseFirehose reads a Kinesis Data Firehose HTTP endpoint delivery
// request: {"requestId", "timestamp", "records": [{"data": base64}]}.
func parseFirehose(body []byte, b *batch, fields string) error {
	var req struct {
		RequestID string `json:"requestId"`
		Records   []struct {
			Data string `json:"data"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return badRequest("Firehose request: %v", err)
	}
	p := newAWSParser(b, fields)
	for _, r := range req.Records {
		raw, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			b.skip()
			continue
		}
		if raw, err = gunzipMaybe(raw, b.h.cfg.MaxBody); err != nil {
			b.skip()
			continue
		}
		if err := p.payload(raw); err != nil {
			b.skip()
		}
	}
	return nil
}
