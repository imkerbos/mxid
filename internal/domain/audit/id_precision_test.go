package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// A snowflake id must reach the client with every digit intact.
//
// This is the failure mode that hides best. 360787997051850752 and
// 360787997051850750 look identical at a glance, differ only past the 17th
// digit, and the wrong one is a perfectly well-formed number that simply
// matches no row. An operator reconstructing an incident copies the id out of
// the audit entry, searches, finds nothing, and concludes the record is about
// something that no longer exists.
//
// It was reaching the browser rounded through two separate hops:
//
//	projectDetail stored the id as a JSON number, and
//	toResponse decoded that JSON into map[string]any, where encoding/json
//	makes every number a float64 — 53 bits, against 18-19 digits.
//
// Neither hop errors. Both round.
const bigSnowflake int64 = 360787997051850752

func TestDetailKeepsSnowflakePrecisionThroughStorage(t *testing.T) {
	raw := projectDetail("group.member_added", map[string]any{
		"group_id":  bigSnowflake,
		"user_id":   int64(800000000000000006),
		"tenant_id": int64(1),
		"name":      "研发",
	})

	s := string(raw)
	if !strings.Contains(s, `"360787997051850752"`) {
		t.Errorf("group_id is not stored as an exact string: %s\n\nA JSON number "+
			"this size cannot survive the float64 round trip that every consumer "+
			"— Go's map[string]any and the browser alike — puts it through.", s)
	}
	// Small values stay numbers; quoting everything would be a needless API change.
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("stored detail is not valid JSON: %v", err)
	}
	if _, isNumber := back["tenant_id"].(float64); !isNumber {
		t.Errorf("tenant_id = %#v; a value well inside 2^53 should stay a number",
			back["tenant_id"])
	}
	if back["name"] != "研发" {
		t.Errorf("name = %#v, want unchanged", back["name"])
	}
}

func TestToResponsePassesDetailThroughUnchanged(t *testing.T) {
	stored := json.RawMessage(`{"group_id":360787997051850752,"added":13}`)
	resp := toResponse(&AuditLog{ID: 1, EventType: "group.rule_updated", Detail: stored})

	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if !strings.Contains(string(out), "360787997051850752") {
		t.Errorf("the id was altered on the way out: %s\n\nEven a row already "+
			"stored as a JSON number must not be re-rounded by the handler — "+
			"decoding to map[string]any and re-encoding is not a no-op.", out)
	}
}

func TestToResponseDropsUnparseableDetail(t *testing.T) {
	// Pass-through must not let a corrupt row make the whole response invalid
	// JSON — that would take out the entire audit page, not one entry.
	resp := toResponse(&AuditLog{ID: 1, Detail: json.RawMessage(`{"broken":`)})
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var check map[string]any
	if err := json.Unmarshal(out, &check); err != nil {
		t.Fatalf("a corrupt detail column made the whole response unparseable: %v", err)
	}
}

func TestStringifyBigIDsBoundary(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"just inside 2^53", int64(maxExactJSNumber), int64(maxExactJSNumber)},
		{"just past 2^53", int64(maxExactJSNumber + 1), "9007199254740992"},
		{"snowflake", bigSnowflake, "360787997051850752"},
		{"small", int64(42), int64(42)},
		{"negative small", int64(-42), int64(-42)},
		{"string untouched", "abc", "abc"},
		{"bool untouched", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stringifyBigIDs(map[string]any{"v": c.in})["v"]
			if got != c.want {
				t.Errorf("stringifyBigIDs(%#v) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}
