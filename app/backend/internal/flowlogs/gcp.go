package flowlogs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sbrw-evc/network/app/backend/internal/flow"
)

// GCP VPC Flow Logs arrive as Pub/Sub push messages (a log sink to a topic,
// a push subscription to this endpoint):
//
//	{"message": {"data": base64(LogEntry JSON), "messageId": …}, "subscription": …}
//
// A LogEntry, or an array of them, is also accepted directly.
type gcpEntry struct {
	Timestamp   string      `json:"timestamp"`
	JSONPayload *gcpPayload `json:"jsonPayload"`
	Resource    struct {
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
}

type gcpInstance struct {
	ProjectID string `json:"project_id"`
	VMName    string `json:"vm_name"`
	Zone      string `json:"zone"`
}

type gcpVPC struct {
	ProjectID      string `json:"project_id"`
	VPCName        string `json:"vpc_name"`
	SubnetworkName string `json:"subnetwork_name"`
}

type gcpPayload struct {
	Connection struct {
		SrcIP    string `json:"src_ip"`
		DestIP   string `json:"dest_ip"`
		SrcPort  int    `json:"src_port"`
		DestPort int    `json:"dest_port"`
		Protocol int    `json:"protocol"`
	} `json:"connection"`
	// int64 values are strings in LogEntry JSON; numbers are accepted too.
	BytesSent    jsonUint     `json:"bytes_sent"`
	PacketsSent  jsonUint     `json:"packets_sent"`
	StartTime    string       `json:"start_time"`
	EndTime      string       `json:"end_time"`
	Reporter     string       `json:"reporter"` // SRC | DEST
	SrcInstance  *gcpInstance `json:"src_instance"`
	DestInstance *gcpInstance `json:"dest_instance"`
	SrcVPC       *gcpVPC      `json:"src_vpc"`
	DestVPC      *gcpVPC      `json:"dest_vpc"`
}

type jsonUint uint64

func (u *jsonUint) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*u = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return err
		}
		v = uint64(f)
	}
	*u = jsonUint(v)
	return nil
}

func parseGCP(body []byte, b *batch) error {
	body, err := gunzipMaybe(body, b.h.cfg.MaxBody)
	if err != nil {
		return badRequest("gzip: %v", err)
	}
	t := bytes.TrimSpace(body)
	var entries []gcpEntry
	switch {
	case len(t) > 0 && t[0] == '[':
		if err := json.Unmarshal(t, &entries); err != nil {
			return badRequest("GCP LogEntry array: %v", err)
		}
	default:
		var push struct {
			Message *struct {
				Data string `json:"data"`
			} `json:"message"`
		}
		if err := json.Unmarshal(t, &push); err != nil {
			return badRequest("GCP JSON: %v", err)
		}
		data := t
		if push.Message != nil {
			raw, err := base64.StdEncoding.DecodeString(push.Message.Data)
			if err != nil {
				return badRequest("Pub/Sub message data: %v", err)
			}
			data = bytes.TrimSpace(raw)
		}
		if len(data) > 0 && data[0] == '[' {
			err = json.Unmarshal(data, &entries)
		} else {
			var e gcpEntry
			err = json.Unmarshal(data, &e)
			entries = []gcpEntry{e}
		}
		if err != nil {
			return badRequest("GCP LogEntry: %v", err)
		}
	}
	for i := range entries {
		gcpFlow(b, &entries[i])
	}
	return nil
}

func gcpFlow(b *batch, e *gcpEntry) {
	p := e.JSONPayload
	if p == nil {
		b.skip()
		return
	}
	src, err1 := netip.ParseAddr(p.Connection.SrcIP)
	dst, err2 := netip.ParseAddr(p.Connection.DestIP)
	if err1 != nil || err2 != nil {
		b.skip()
		return
	}
	f := &flow.Flow{FlowType: FlowTypeGCP, SrcAddr: src, DstAddr: dst,
		SrcPort: uint16(p.Connection.SrcPort), DstPort: uint16(p.Connection.DestPort), Proto: uint8(p.Connection.Protocol),
		Bytes: uint64(p.BytesSent), Packets: uint64(p.PacketsSent), EType: etype(src), ForwardingStatus: fwdForwarded}
	if t, err := time.Parse(time.RFC3339Nano, p.StartTime); err == nil {
		f.TimeFlowStart = t.UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, p.EndTime); err == nil {
		f.TimeFlowEnd = t.UTC()
	}
	// The exporter is the VM (or subnet) that reported the flow.
	inst, vpc := p.SrcInstance, p.SrcVPC
	if p.Reporter == "DEST" {
		inst, vpc = p.DestInstance, p.DestVPC
	}
	var name string
	switch {
	case inst != nil && inst.VMName != "":
		name = strings.Trim(inst.ProjectID+"/"+inst.VMName, "/")
	case vpc != nil && vpc.VPCName != "":
		name = strings.Trim(vpc.ProjectID+"/"+vpc.VPCName+"/"+vpc.SubnetworkName, "/")
	case e.Resource.Labels["subnetwork_name"] != "":
		l := e.Resource.Labels
		name = strings.Trim(l["project_id"]+"/"+l["subnetwork_name"], "/")
	}
	if name != "" {
		f.ExporterAddress = exporter(hashAddr("gcp:"+name), name)
	} else {
		f.ExporterAddress = netip.IPv4Unspecified()
	}
	b.add(f)
}
