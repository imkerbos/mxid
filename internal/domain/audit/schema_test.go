package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
)

func decode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	return m
}

func TestProjectDetail_DropsSensitiveKeys(t *testing.T) {
	raw := projectDetail(event.LoginSuccess, map[string]any{
		"user_id":   int64(1),
		"password":  "hunter2",
		"secret":    "topsecret",
		"username":  "admin",
		"tenant_id": int64(1),
	})
	if strings.Contains(string(raw), "hunter2") {
		t.Errorf("password leaked: %s", raw)
	}
	if strings.Contains(string(raw), "topsecret") {
		t.Errorf("secret leaked: %s", raw)
	}
	m := decode(t, raw)
	if m["username"] != "admin" {
		t.Errorf("allowed field dropped: %v", m)
	}
}

func TestProjectDetail_KnownEventOnlyAllowsListed(t *testing.T) {
	raw := projectDetail(event.UserCreated, map[string]any{
		"user_id":      int64(99),
		"tenant_id":    int64(1),
		"username":     "alice",
		"display_name": "Alice",
		"unused_field": "should-not-appear",
		"another":      "nope",
	})
	m := decode(t, raw)
	if _, ok := m["unused_field"]; ok {
		t.Errorf("unlisted field present: %v", m)
	}
	if m["username"] != "alice" {
		t.Errorf("allowed field missing: %v", m)
	}
}

func TestProjectDetail_FallbackKeepsCommonFields(t *testing.T) {
	raw := projectDetail("unknown.event.type", map[string]any{
		"tenant_id":   int64(1),
		"user_id":     int64(7),
		"reason":      "policy",
		"random_key":  "drop",
		"new_token":   "secret-token",
	})
	m := decode(t, raw)
	if _, ok := m["random_key"]; ok {
		t.Errorf("fallback let arbitrary key through: %v", m)
	}
	if m["reason"] != "policy" {
		t.Errorf("fallback dropped a known key: %v", m)
	}
}

func TestProjectDetail_EmptyPayload(t *testing.T) {
	raw := projectDetail(event.UserDeleted, nil)
	if string(raw) != "{}" {
		t.Errorf("empty payload should marshal to {}, got %s", raw)
	}
}

func TestRegisteredEventTypes_NonEmpty(t *testing.T) {
	if len(RegisteredEventTypes()) == 0 {
		t.Fatalf("expected registered event types, got none")
	}
}
