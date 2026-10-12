package flowlogs

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// Azure flow logs, as written to the storage account and forwarded as is
// (Event Grid / Function / Logstash): {"records": [...]} or an array of
// records.
//
// NSG flow logs (category NetworkSecurityGroupFlowEvent):
//
//	properties.flows[].rule, .flows[].flows[].mac, .flowTuples[]:
//	v1 "ts,src,dst,sport,dport,T|U,I|O,A|D"
//	v2 "…,A|D,B|C|E,pkts s→d,bytes s→d,pkts d→s,bytes d→s"
//
// VNet flow logs (flowLogVersion 4, category FlowLogFlowEvent):
//
//	macAddress, flowRecords.flows[].flowGroups[].rule, .flowTuples[]:
//	"ts_ms,src,dst,sport,dport,proto,I|O,B|C|E|D,encryption,pkts s→d,bytes s→d,pkts d→s,bytes d→s"
type azureRecord struct {
	Time       string `json:"time"`
	ResourceID string `json:"resourceId"`
	Category   string `json:"category"`
	Properties struct {
		Version int `json:"Version"`
		Flows   []struct {
			Rule  string `json:"rule"`
			Flows []struct {
				MAC        string   `json:"mac"`
				FlowTuples []string `json:"flowTuples"`
			} `json:"flows"`
		} `json:"flows"`
	} `json:"properties"`

	FlowLogVersion   int    `json:"flowLogVersion"`
	MACAddress       string `json:"macAddress"`
	TargetResourceID string `json:"targetResourceID"`
	FlowRecords      struct {
		Flows []struct {
			ACLID      string `json:"aclID"`
			FlowGroups []struct {
				Rule       string   `json:"rule"`
				FlowTuples []string `json:"flowTuples"`
			} `json:"flowGroups"`
		} `json:"flows"`
	} `json:"flowRecords"`
}

func lastSegment(id string) string {
	id = strings.TrimRight(id, "/")
	return id[strings.LastIndexByte(id, '/')+1:]
}

func parseAzure(body []byte, b *batch) error {
	body, err := gunzipMaybe(body, b.h.cfg.MaxBody)
	if err != nil {
		return badRequest("gzip: %v", err)
	}
	t := bytes.TrimSpace(body)
	var records []azureRecord
	if len(t) > 0 && t[0] == '[' {
		err = json.Unmarshal(t, &records)
	} else {
		var doc struct {
			Records []azureRecord `json:"records"`
		}
		err = json.Unmarshal(t, &doc)
		records = doc.Records
	}
	if err != nil {
		return badRequest("Azure flow logs JSON: %v", err)
	}
	for i := range records {
		r := &records[i]
		if r.FlowLogVersion > 0 || len(r.FlowRecords.Flows) > 0 {
			addr, mac, ok := macAddr(r.MACAddress)
			name := strings.Trim(lastSegment(r.TargetResourceID)+"/"+mac, "/")
			if !ok {
				addr = hashAddr("azure:" + r.TargetResourceID)
			}
			ex := exporter(addr, name)
			for _, fl := range r.FlowRecords.Flows {
				for _, g := range fl.FlowGroups {
					for _, tu := range g.FlowTuples {
						azureTuple(b, tu, ex, true)
					}
				}
			}
			continue
		}
		nsg := lastSegment(r.ResourceID)
		for _, rule := range r.Properties.Flows {
			for _, fl := range rule.Flows {
				addr, mac, ok := macAddr(fl.MAC)
				if !ok {
					addr = hashAddr("azure:" + r.ResourceID)
				}
				ex := exporter(addr, strings.Trim(nsg+"/"+mac, "/"))
				for _, tu := range fl.FlowTuples {
					azureTuple(b, tu, ex, false)
				}
			}
		}
	}
	return nil
}

func azureProto(s string) (uint8, bool) {
	switch s {
	case "T":
		return 6, true
	case "U":
		return 17, true
	}
	v, err := strconv.ParseUint(s, 10, 8)
	return uint8(v), err == nil
}

// azureTuple adds the flows of one tuple: source → destination and, when
// counted, the reverse direction.
func azureTuple(b *batch, tuple string, ex netip.Addr, vnet bool) {
	fs := strings.Split(tuple, ",")
	if len(fs) < 8 {
		b.skip()
		return
	}
	ts, err1 := strconv.ParseInt(fs[0], 10, 64)
	src, err2 := netip.ParseAddr(fs[1])
	dst, err3 := netip.ParseAddr(fs[2])
	proto, ok := azureProto(fs[5])
	if err1 != nil || err2 != nil || err3 != nil || !ok {
		b.skip()
		return
	}
	var at time.Time
	if vnet || ts > 1e12 {
		at = time.UnixMilli(ts).UTC()
	} else {
		at = time.Unix(ts, 0).UTC()
	}
	sport, _ := strconv.ParseUint(fs[3], 10, 16)
	dport, _ := strconv.ParseUint(fs[4], 10, 16)
	fwd := uint8(fwdForwarded)
	// Field 8: NSG decision (A|D) or VNet flow state (D = denied).
	if fs[7] == "D" {
		fwd = fwdDropped
	}
	var counts []string
	if len(fs) >= 13 {
		counts = fs[9:13]
	}
	if len(counts) != 4 {
		b.skip() // version 1 tuples and flow begin records carry no volume
		return
	}
	pkts := [2]uint64{num(counts[0]), num(counts[2])}
	bytes := [2]uint64{num(counts[1]), num(counts[3])}
	if pkts[0]+pkts[1]+bytes[0]+bytes[1] == 0 {
		b.skip()
		return
	}
	for dir := range 2 {
		if pkts[dir] == 0 && bytes[dir] == 0 {
			continue
		}
		f := &flow.Flow{FlowType: FlowTypeAzure, ExporterAddress: ex, SrcAddr: src, DstAddr: dst,
			SrcPort: uint16(sport), DstPort: uint16(dport), Proto: proto, Packets: pkts[dir], Bytes: bytes[dir],
			TimeFlowEnd: at, ForwardingStatus: fwd, EType: etype(src)}
		if dir == 1 {
			f.SrcAddr, f.DstAddr, f.SrcPort, f.DstPort = dst, src, uint16(dport), uint16(sport)
		}
		b.add(f)
	}
}
