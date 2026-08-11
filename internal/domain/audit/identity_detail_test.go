package audit

// The identity-binding lifecycle rides on event.UserUpdated and carries its
// entire meaning in payload fields the allow-list used to drop: "action",
// "provider", "identity_id", "previous_user_id". Projected without them, an
// external identity moving from one account to another persisted as
// {"user_id":…,"tenant_id":…} — byte for byte what a display-name edit
// persists.
//
// That matters most for the takeover, because nothing else records it.
// takeOverIdentity (internal/domain/user/external_login.go) is reached only
// through GET /api/v1/portal-public/auth/external/:code/callback, and the
// catch-all api.* audit cannot see it twice over: middleware.go returns early
// for GET, and auditCatchAll is .Use'd on ConsoleGroup / PortalGroup but never
// on publicPortalGroup. The domain event is the whole record.
//
// These tests assert on the PERSISTED Detail — the projection's output, not the
// published payload — because the payload was always correct; the projection is
// where it was being thrown away.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// takeoverPayload mirrors, field for field, what Service.takeOverIdentity
// publishes in internal/domain/user/external_login.go. Kept literal rather than
// imported: the user domain is what this package must not depend on, and a
// silent divergence between the two is exactly what TestEverySchemaEventIs…
// style guards elsewhere exist for.
func takeoverPayload() map[string]any {
	return map[string]any{
		"user_id":          int64(1),
		"tenant_id":        int64(1),
		"action":           "identity_taken_over",
		"provider":         "lark",
		"previous_user_id": int64(3),
	}
}

func newDetailTestService(t *testing.T) (*Service, *captureRepo) {
	t.Helper()
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}
	repo := &captureRepo{}
	return NewService(repo, idGen, nil, zap.NewNop(), 1), repo
}

// A takeover's audit row must name the account the identity was taken FROM.
// Without previous_user_id the row says an identity was bound, and the account
// that lost it is unrecoverable from the audit log.
func TestUserUpdatedDetail_TakeoverKeepsPreviousOwner(t *testing.T) {
	svc, repo := newDetailTestService(t)

	svc.handleUserEvent(event.UserUpdated, EventStatusSuccess)(context.Background(), event.Event{
		Type:    event.UserUpdated,
		Payload: takeoverPayload(),
	})

	if repo.last == nil {
		t.Fatal("no audit row was created for the takeover")
	}
	var detail map[string]any
	if err := json.Unmarshal(repo.last.Detail, &detail); err != nil {
		t.Fatalf("decode persisted detail: %v", err)
	}

	prev, ok := detail["previous_user_id"]
	if !ok {
		t.Fatalf("the persisted detail of an identity takeover must name the "+
			"previous owner — the callback route it runs on is not covered by the "+
			"api.* catch-all, so this row is the only record. Got %v", detail)
	}
	// stringifyBigIDs leaves a small id as a JSON number; either shape is fine
	// as long as it identifies user 3.
	switch v := prev.(type) {
	case float64:
		if int64(v) != 3 {
			t.Fatalf("previous_user_id must be 3, got %v", prev)
		}
	case string:
		if v != "3" {
			t.Fatalf("previous_user_id must be 3, got %q", v)
		}
	default:
		t.Fatalf("unexpected previous_user_id type %T (%v)", prev, prev)
	}

	if detail["action"] != "identity_taken_over" {
		t.Fatalf("a takeover must be distinguishable from an ordinary update; "+
			"action was %v", detail["action"])
	}
	if detail["provider"] != "lark" {
		t.Fatalf("the provider the identity belongs to must be on record, got %v", detail["provider"])
	}
}

// The rest of the lifecycle rides on the same event type, and every one of them
// was projecting to the same two fields. identity_unbound / mfa_removed are the
// pre-existing half of the gap: the console operations the 2026-08-10 incident
// began with.
func TestUserUpdatedDetail_KeepsActionForEveryIdentityLifecycleEvent(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name:    "identity_unbound",
			payload: map[string]any{"user_id": int64(1), "action": "identity_unbound", "identity_id": int64(10)},
			want:    map[string]any{"action": "identity_unbound", "identity_id": float64(10)},
		},
		{
			name:    "identity_restored",
			payload: map[string]any{"user_id": int64(1), "action": "identity_restored", "identity_id": int64(10)},
			want:    map[string]any{"action": "identity_restored", "identity_id": float64(10)},
		},
		{
			name:    "identity_bound",
			payload: map[string]any{"user_id": int64(1), "action": "identity_bound", "provider": "lark"},
			want:    map[string]any{"action": "identity_bound", "provider": "lark"},
		},
		{
			name:    "user_restored",
			payload: map[string]any{"user_id": int64(1), "action": "user_restored"},
			want:    map[string]any{"action": "user_restored"},
		},
		{
			name:    "mfa_removed",
			payload: map[string]any{"user_id": int64(1), "action": "mfa_removed"},
			want:    map[string]any{"action": "mfa_removed"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newDetailTestService(t)
			svc.handleUserEvent(event.UserUpdated, EventStatusSuccess)(context.Background(), event.Event{
				Type:    event.UserUpdated,
				Payload: tc.payload,
			})
			if repo.last == nil {
				t.Fatal("no audit row created")
			}
			var detail map[string]any
			if err := json.Unmarshal(repo.last.Detail, &detail); err != nil {
				t.Fatalf("decode persisted detail: %v", err)
			}
			for k, want := range tc.want {
				if detail[k] != want {
					t.Fatalf("persisted detail must carry %s=%v, got %v (full detail %v)",
						k, want, detail[k], detail)
				}
			}
		})
	}
}
