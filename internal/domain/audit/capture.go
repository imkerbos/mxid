package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Event is what a producer hands to Capture. ChainClass and EventType are
// required; the rest are optional.
type Event struct {
	ChainClass   string
	EventType    string
	ResourceType string
	ResourceID   int64
	Before       map[string]any
	After        map[string]any
	Detail       map[string]any
	// ResourceName, GeoCity and GeoCountry are the human-readable context that
	// used to live only in mxid_audit_log. Optional: the ORM capture path often
	// cannot know them, and an empty value is recorded as absent rather than as
	// an assertion that the resource had no name.
	ResourceName string
	GeoCity      string
	GeoCountry   string
}

// Capturer writes captured events into mxid_audit_pending on the caller's
// transaction, so capture commits or rolls back atomically with the state
// change it accompanies.
type Capturer struct {
	idGen *snowflake.Generator
}

func NewCapturer(idGen *snowflake.Generator) *Capturer {
	return &Capturer{idGen: idGen}
}

func toJSON(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Capture inserts one pending row on tx. actor/ip/session are read from
// auditctx; absent context yields a system-attributed row.
func (c *Capturer) Capture(ctx context.Context, tx *gorm.DB, ev Event) error {
	actor, _ := auditctx.From(ctx)
	detail := ev.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	beforeJSON, err := toJSON(ev.Before)
	if err != nil {
		return fmt.Errorf("marshal audit before: %w", err)
	}
	afterJSON, err := toJSON(ev.After)
	if err != nil {
		return fmt.Errorf("marshal audit after: %w", err)
	}
	detailJSON, err := toJSON(detail)
	if err != nil {
		return fmt.Errorf("marshal audit detail: %w", err)
	}
	row := &AuditPending{
		ID:           c.idGen.Generate(),
		TenantID:     actor.TenantID,
		ChainClass:   ev.ChainClass,
		ActorID:      actor.ActorID,
		ActorType:    actor.ActorType,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Before:       beforeJSON,
		After:        afterJSON,
		IP:           actor.IP,
		UserAgent:    actor.UserAgent,
		SessionID:    actor.SessionID,
		Detail:       detailJSON,
		OccurredAt:   time.Now().UTC(),
		// Left NULL when unknown rather than stored as "": the ledger should say
		// "not recorded", not claim the actor had no name.
		ActorName:    nonEmpty(actor.ActorName),
		ResourceName: nonEmpty(ev.ResourceName),
		GeoCity:      nonEmpty(ev.GeoCity),
		GeoCountry:   nonEmpty(ev.GeoCountry),
	}
	return tx.WithContext(ctx).Create(row).Error
}

// nonEmpty returns a pointer to s, or nil when s is empty, so an unknown value
// is stored as NULL instead of an empty string.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// deref flattens a nullable column back to a string. NULL and "" both become
// "", which the payload then omits — the distinction between them is carried by
// the payload version, not by the field.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
