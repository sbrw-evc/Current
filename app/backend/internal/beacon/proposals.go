package beacon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sbrw-evc/current/app/backend/internal/query"
)

// Source is the "source" of Current's proposal batches.
const Source = "umbrella-flow"

// Endpoint is one end of a proposed dependency.
type Endpoint struct {
	SourceRef string `json:"source_ref"`
	Name      string `json:"name,omitempty"`
	IP        string `json:"ip,omitempty"`
}

// Evidence is the traffic behind a proposal.
type Evidence struct {
	Protocol  string    `json:"protocol"`
	Port      uint16    `json:"port"`
	App       string    `json:"app,omitempty"`
	Bytes7d   uint64    `json:"bytes_7d"`
	Flows7d   uint64    `json:"flows_7d"`
	DaysSeen  uint64    `json:"days_seen"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	FlowURL   string    `json:"flow_url,omitempty"`
}

// Proposal is one "from depends on to" proposal (§3.3).
type Proposal struct {
	Key      string   `json:"key"`
	From     Endpoint `json:"from"`
	To       Endpoint `json:"to"`
	Type     string   `json:"type"`
	Evidence Evidence `json:"evidence"`
}

// ProtoName names the transport protocols discovery looks at.
func ProtoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 132:
		return "sctp"
	}
	return fmt.Sprint(p)
}

// ProposalKey is the stable key of a proposal:
// flow:<from ref>-><to ref>:<proto>/<port>.
func ProposalKey(from, to, proto string, port uint16) string {
	return fmt.Sprintf("flow:%s->%s:%s/%d", from, to, proto, port)
}

// BuildProposals turns discovered pairs into proposals: the client CI depends
// on the server CI. publicURL (Current's address) gives each a Visualize link
// over the discovery period; empty means no link.
func BuildProposals(pairs []query.DependencyPair, publicURL string, from, to time.Time) []Proposal {
	out := make([]Proposal, 0, len(pairs))
	seen := map[string]bool{}
	for _, p := range pairs {
		proto := ProtoName(p.Proto)
		key := ProposalKey(p.ClientRef, p.ServerRef, proto, p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		filter := fmt.Sprintf("SrcCI = %s AND DstCI = %s AND Proto = %d AND DstPort = %d",
			quote(p.ClientRef), quote(p.ServerRef), p.Proto, p.Port)
		out = append(out, Proposal{
			Key:  key,
			From: Endpoint{SourceRef: p.ClientRef, Name: p.ClientName, IP: p.ClientIP},
			To:   Endpoint{SourceRef: p.ServerRef, Name: p.ServerName, IP: p.ServerIP},
			Type: "depends_on",
			Evidence: Evidence{Protocol: proto, Port: p.Port, App: p.App, Bytes7d: p.Bytes, Flows7d: p.Flows,
				DaysSeen: p.DaysSeen, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
				FlowURL: VisualizeLink(publicURL, filter, []string{"SrcAddr", "DstAddr"}, from, to)},
		})
	}
	return out
}

// quote writes a string value of the filter language.
func quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// view is the URL state of the web Visualize page (app/web/src/pages/
// visualize/state.ts): ?q=base64url(JSON) with short keys, as the detector
// builds it.
type view struct {
	R [2]string `json:"r"`
	G string    `json:"g"`
	U string    `json:"u"`
	D []string  `json:"d"`
	L int       `json:"l"`
	F string    `json:"f"`
}

// VisualizeLink returns <publicURL>/visualize?q=… ("" without a public URL).
func VisualizeLink(publicURL, filterText string, dims []string, from, to time.Time) string {
	if publicURL == "" {
		return ""
	}
	if dims == nil {
		dims = []string{}
	}
	v := view{R: [2]string{from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)}, G: "stacked", U: "l3bps", D: dims, L: 10, F: filterText}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimRight(publicURL, "/") + "/visualize?q=" + base64.RawURLEncoding.EncodeToString(bytes.TrimSpace(buf.Bytes()))
}
