package audit

import (
	"sort"
	"strings"
	"testing"
)

// No allow-list may name a field the sensitive filter then removes.
//
// The two lists express opposite intentions, and when they overlap the filter
// wins silently. That happened with "code": twelve events named it — the app
// code, the org code, the group code, the tenant code — and the filter dropped
// every one because the entry meant OTPs. The audit log then recorded that a
// group was created without recording its code, which is the exact string
// downstream systems match on to grant access.
//
// The failure mode is what makes this worth a test. Reviewing schema.go shows
// "code" in the allow-list and reads as covered. Reviewing the sensitive list
// shows "code" and reads as protected. Only running it shows the field is gone,
// and by then the row is written and nobody is looking.
func TestNoAllowListedFieldIsSilentlyFiltered(t *testing.T) {
	type conflict struct{ event, field string }
	var conflicts []conflict

	for eventType, schema := range detailSchemas {
		for _, field := range schema.allow {
			if isSensitiveKey(field) {
				conflicts = append(conflicts, conflict{eventType, field})
			}
		}
	}
	for _, field := range fallbackSchema.allow {
		if isSensitiveKey(field) {
			conflicts = append(conflicts, conflict{"<fallback>", field})
		}
	}

	if len(conflicts) == 0 {
		return
	}
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].field != conflicts[j].field {
			return conflicts[i].field < conflicts[j].field
		}
		return conflicts[i].event < conflicts[j].event
	})
	var lines []string
	for _, c := range conflicts {
		lines = append(lines, c.event+" allow-lists "+c.field)
	}
	t.Errorf("these fields are allow-listed for audit AND dropped by the "+
		"sensitive-key filter, so the allow-list is claiming coverage that does "+
		"not exist:\n  %s\n\nEither drop the field from the allow-list, or name "+
		"the sensitive key precisely enough that it stops matching this one "+
		"(e.g. otp_code rather than code).",
		strings.Join(lines, "\n  "))
}

// The filter must still do its job on the names it does claim.
func TestSensitiveKeysStillFilter(t *testing.T) {
	for _, k := range []string{
		"password", "old_password", "new_password", "password_hash",
		"secret", "client_secret", "otp", "otp_code", "token",
		"refresh_token", "access_token", "api_key", "private_key",
	} {
		if !isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = false — this must never be recorded", k)
		}
	}
	// A business identifier is not a secret.
	for _, k := range []string{"code", "name", "group_id", "tenant_id", "email"} {
		if isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = true — this is an identifier the audit "+
				"log exists to record", k)
		}
	}
}

// project() is where the two lists meet; assert the outcome directly rather
// than only asserting about the lists.
func TestProjectKeepsAllowedIdentifiersAndDropsSecrets(t *testing.T) {
	s := detailSchema{allow: []string{"group_id", "name", "code", "password"}}
	got := s.project(map[string]any{
		"group_id": int64(7),
		"name":     "研发",
		"code":     "engineering",
		"password": "hunter2",
		"unlisted": "x",
	})
	if got["code"] != "engineering" {
		t.Errorf(`project dropped "code" — the group code is what downstream ` +
			`systems match on, and the audit entry is unusable without it`)
	}
	if got["name"] != "研发" || got["group_id"] != int64(7) {
		t.Errorf("project dropped an allowed identifier: %+v", got)
	}
	if _, leaked := got["password"]; leaked {
		t.Error(`project kept "password" — the filter must win over the allow-list ` +
			`for genuine secrets`)
	}
	if _, leaked := got["unlisted"]; leaked {
		t.Error("project kept a field that was not allow-listed")
	}
}
