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
	}
	return tx.WithContext(ctx).Create(row).Error
}
