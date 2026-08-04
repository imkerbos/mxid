// Package auditsink mirrors audit records to a collector outside the database.
//
// # Why this exists
//
// The audit log is durable in PostgreSQL, and the tamper-evident chain proves
// nobody rewrote it. Neither of those helps if the person who can reach the
// database is the person you are auditing: they cannot forge history, but they
// can drop the whole table. A copy that leaves the machine as it is written is
// the part that survives that, and it is what "centralised log management"
// controls are asking for — China's MLPS 2.0 among them.
//
// # What it must never do
//
// Block. The audit write already happened and already committed; forwarding is
// a mirror, not the record of truth. A collector that stops reading must not be
// able to stall the audit path, because the audit path is synchronous with
// every write API in the product — a hung syslog socket would take the whole
// service down. So the queue is bounded and overflow is DROPPED and counted,
// never waited on. The dropped counter is the signal that the mirror is
// incomplete; the database still has the record either way.
package auditsink

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Syslog severities (RFC 5424 §6.2.1). Only the two the audit stream produces.
const (
	sevWarning = 4
	sevInfo    = 6
)

// nilValue is RFC 5424's placeholder for an absent field. A collector that sees
// it knows the value was not available, which an empty string does not say.
const nilValue = "-"

// Record is one audit entry, flattened for transport. It is deliberately not
// the audit domain's own type: the domain imports this package, so depending on
// it here would be a cycle, and pinning the wire shape separately means a
// column rename cannot silently change what a collector receives.
type Record struct {
	ID           int64           `json:"id"`
	TenantID     int64           `json:"tenant_id"`
	Time         time.Time       `json:"time"`
	EventType    string          `json:"event_type"`
	Success      bool            `json:"success"`
	ActorID      *int64          `json:"actor_id,omitempty"`
	ActorName    string          `json:"actor_name,omitempty"`
	ActorType    string          `json:"actor_type,omitempty"`
	ResourceType string          `json:"resource_type,omitempty"`
	ResourceID   *int64          `json:"resource_id,omitempty"`
	ResourceName string          `json:"resource_name,omitempty"`
	IP           string          `json:"ip,omitempty"`
	UserAgent    string          `json:"user_agent,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`
}

func (r Record) severity() int {
	if r.Success {
		return sevInfo
	}
	// A failed security-relevant action is the thing an operator wants a rule
	// on, so it arrives a level above the successful ones rather than being
	// indistinguishable from them in the stream.
	return sevWarning
}

// format renders the record as an RFC 5424 syslog message.
//
//	<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
//
// The MSG body is the record as JSON. Structured data would be the more
// idiomatic home for the fields, but every collector worth pointing this at
// parses a JSON payload, and JSON survives a field containing a `]` — SD-PARAM
// escaping does not survive contact with user-controlled values nearly as well.
func (r Record) format(facility int, hostname, appName string, now time.Time) string {
	pri := facility*8 + r.severity()

	ts := r.Time
	if ts.IsZero() {
		ts = now
	}

	body, err := json.Marshal(r)
	if err != nil {
		// Marshalling a struct of scalars plus a json.RawMessage can only fail
		// on invalid RawMessage. Report the entry rather than dropping it: a
		// record that arrives degraded still proves the action happened.
		body = fmt.Appendf(nil, `{"id":%d,"event_type":%q,"encode_error":%q}`,
			r.ID, r.EventType, err.Error())
	}

	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri,
		ts.UTC().Format(time.RFC3339Nano),
		sanitizeHeader(hostname),
		sanitizeHeader(appName),
		nilValue, // PROCID: a pid means nothing across replicas
		sanitizeHeader(r.EventType),
		nilValue, // STRUCTURED-DATA: everything is in the JSON body
		body,
	)
}

// sanitizeHeader keeps a header field to the printable US-ASCII RFC 5424 allows
// and bounds its length. Header fields are space-delimited, so a value carrying
// a space would shift every field after it — and EventType, one of these, is
// close enough to caller-influenced that it is not worth assuming.
func sanitizeHeader(s string) string {
	if s == "" {
		return nilValue
	}
	var b strings.Builder
	for _, r := range s {
		if r < 33 || r > 126 {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 48 {
			break
		}
	}
	if b.Len() == 0 {
		return nilValue
	}
	return b.String()
}
