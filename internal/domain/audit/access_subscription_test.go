package audit

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// captureRepo records the last AuditLog passed to Create so the handler's
// field mapping can be asserted without a database.
type captureRepo struct {
	last *AuditLog
}

func (c *captureRepo) Create(_ context.Context, log *AuditLog) error { c.last = log; return nil }
func (c *captureRepo) List(context.Context, ListParams) ([]*AuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureRepo) GetStats(context.Context, int64, time.Time, time.Time) (*AuditStatsResponse, error) {
	return nil, nil
}
func (c *captureRepo) PurgeOlderThan(context.Context, time.Time) (int64, error) { return 0, nil }

// TestResourceEventHandler_AccessPayloadMapping verifies the payload-driven
// handler used to wire access.* events: it must read resource_type/resource_id
// straight from the payload, carry tenant_id, and project the JIT detail fields.
func TestResourceEventHandler_AccessPayloadMapping(t *testing.T) {
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}
	repo := &captureRepo{}
	svc := NewService(repo, idGen, nil, zap.NewNop(), 42)

	h := svc.ResourceEventHandler("access.request.approved", "access_request")
	h(context.Background(), event.Event{
		Type: "access.request.approved",
		Payload: map[string]any{
			"resource_type": "access_request",
			"resource_id":   int64(777),
			"tenant_id":     int64(9),
			"requester_id":  int64(6),
			"role_id":       int64(123),
		},
	})

	got := repo.last
	if got == nil {
		t.Fatal("Create was not called")
	}
	if got.ResourceType == nil || *got.ResourceType != "access_request" {
		t.Errorf("resource_type = %v, want access_request", got.ResourceType)
	}
	if got.ResourceID == nil || *got.ResourceID != 777 {
		t.Errorf("resource_id = %v, want 777", got.ResourceID)
	}
	if got.TenantID != 9 {
		t.Errorf("tenant_id = %d, want 9", got.TenantID)
	}
	if got.EventType != "access.request.approved" {
		t.Errorf("event_type = %q, want access.request.approved", got.EventType)
	}
	// No auditctx in this background ctx → actor falls back to system.
	if got.ActorType != ActorSystem {
		t.Errorf("actor_type = %q, want %q", got.ActorType, ActorSystem)
	}
	detail := decode(t, got.Detail)
	if _, ok := detail["role_id"]; !ok {
		t.Errorf("detail missing role_id: %v", detail)
	}
	if _, ok := detail["requester_id"]; !ok {
		t.Errorf("detail missing requester_id: %v", detail)
	}
	// The actor COLUMN is owned by enrich(); the detail must never carry a
	// competing "actor_id" that could disagree with it (see schema.go).
	if _, ok := detail["actor_id"]; ok {
		t.Errorf("detail must not carry ambiguous actor_id: %v", detail)
	}
}

// TestResourceEventHandler_DefaultsResourceType ensures the default is used
// when the payload omits resource_type, and id falls back from resource_id.
func TestResourceEventHandler_DefaultsResourceType(t *testing.T) {
	idGen, _ := snowflake.New(1)
	repo := &captureRepo{}
	svc := NewService(repo, idGen, nil, zap.NewNop(), 1)

	h := svc.ResourceEventHandler("access.grant.expired", "access_request")
	h(context.Background(), event.Event{
		Type:    "access.grant.expired",
		Payload: map[string]any{"id": int64(55), "tenant_id": int64(3)},
	})

	if repo.last.ResourceType == nil || *repo.last.ResourceType != "access_request" {
		t.Errorf("resource_type = %v, want default access_request", repo.last.ResourceType)
	}
	if repo.last.ResourceID == nil || *repo.last.ResourceID != 55 {
		t.Errorf("resource_id = %v, want 55 (from id fallback)", repo.last.ResourceID)
	}
}
