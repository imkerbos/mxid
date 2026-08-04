// Package auditalert turns selected audit records into outbound alerts.
//
// The console has offered an alert webhook and an event-type list since the
// settings were introduced, and nothing read them: an administrator filled the
// field in, got a "saved" toast, and no alert would ever have been sent. A
// control that reports success while doing nothing is worse than an absent one,
// because it is relied upon. This package is what makes it true.
//
// Delivery rides the transactional outbox rather than a goroutine, because an
// alert about a security event is exactly the thing that must not be lost to a
// process restart. The outbox already provides at-least-once delivery, capped
// retries with backoff, and a dead-letter state.
package auditalert

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/outbox"
)

// Kind is the outbox message kind this package enqueues.
const Kind = "audit.alert"

// DefaultCooldown is how long one (tenant, event type) stays quiet after an
// alert fires. Ten thousand failed logins is one incident, not ten thousand
// notifications — and an alert channel that floods is an alert channel that
// gets muted, which is the same as having none.
const DefaultCooldown = 5 * time.Minute

// Policy is the alerting configuration for one tenant.
type Policy struct {
	WebhookURL string
	EventTypes []string
}

// enabled reports whether this policy can produce an alert at all.
func (p Policy) enabled() bool { return p.WebhookURL != "" && len(p.EventTypes) > 0 }

// matches reports whether an event type is one the administrator asked about.
func (p Policy) matches(eventType string) bool {
	for _, t := range p.EventTypes {
		if strings.EqualFold(strings.TrimSpace(t), eventType) {
			return true
		}
	}
	return false
}

// PolicyProvider reads the alert policy for a tenant.
type PolicyProvider func(ctx context.Context, tenantID int64) (Policy, error)

// Enqueuer persists an outbox message.
type Enqueuer interface {
	Enqueue(ctx context.Context, msg *outbox.Message) error
}

// Alert is the payload delivered to the webhook. Field names are part of the
// contract with whatever the administrator points this at, so they are stable
// and self-describing rather than mirroring column names.
type Alert struct {
	AuditID      int64           `json:"audit_id"`
	TenantID     int64           `json:"tenant_id"`
	Time         time.Time       `json:"time"`
	EventType    string          `json:"event_type"`
	Success      bool            `json:"success"`
	ActorID      *int64          `json:"actor_id,omitempty"`
	ActorName    string          `json:"actor_name,omitempty"`
	ResourceType string          `json:"resource_type,omitempty"`
	ResourceID   *int64          `json:"resource_id,omitempty"`
	ResourceName string          `json:"resource_name,omitempty"`
	IP           string          `json:"ip,omitempty"`
	UserAgent    string          `json:"user_agent,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`
	// SuppressedSinceLast counts events of this type that were folded into the
	// cooldown since the previous alert. Non-zero means this notification
	// stands for more than one occurrence, which changes how urgent it reads.
	SuppressedSinceLast int64 `json:"suppressed_since_last"`
}

// Dispatcher decides which audit records become alerts and enqueues them.
type Dispatcher struct {
	policy   PolicyProvider
	outbox   Enqueuer
	rdb      *redis.Client
	cooldown time.Duration
	logger   *zap.Logger
}

// New builds a Dispatcher. rdb may be nil, which disables cooldown suppression
// — every matching event then alerts, which is noisy but never silent.
func New(policy PolicyProvider, enq Enqueuer, rdb *redis.Client, cooldown time.Duration, logger *zap.Logger) *Dispatcher {
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	return &Dispatcher{policy: policy, outbox: enq, rdb: rdb, cooldown: cooldown, logger: logger}
}

// Dispatch enqueues an alert for a record the policy selects.
//
// Called from the audit write path, so it must be cheap and must not propagate
// failures: the audited action has already happened and committed, and failing
// to notify about it is not a reason to make anything else fail.
func (d *Dispatcher) Dispatch(ctx context.Context, a Alert) {
	if d == nil || d.policy == nil || d.outbox == nil {
		return
	}

	pol, err := d.policy(ctx, a.TenantID)
	if err != nil {
		d.warn("audit alert policy unavailable", zap.Int64("tenant_id", a.TenantID), zap.Error(err))
		return
	}
	if !pol.enabled() || !pol.matches(a.EventType) {
		return
	}

	fire, suppressed := d.claim(ctx, a.TenantID, a.EventType)
	if !fire {
		return
	}
	a.SuppressedSinceLast = suppressed

	payload, err := json.Marshal(a)
	if err != nil {
		d.warn("audit alert payload", zap.Int64("audit_id", a.AuditID), zap.Error(err))
		return
	}
	msg := &outbox.Message{
		TenantID: a.TenantID,
		Kind:     Kind,
		Payload:  payload,
	}
	if err := d.outbox.Enqueue(ctx, msg); err != nil {
		d.warn("audit alert enqueue", zap.Int64("audit_id", a.AuditID), zap.Error(err))
	}
}

// claim opens the cooldown window for a (tenant, event type). It reports
// whether this caller may alert, and how many events were suppressed since the
// previous one fired.
//
// Fails OPEN: if Redis is unreachable the alert goes out. An alerting path that
// falls silent when its coordination store is down would be at its least useful
// exactly when infrastructure is misbehaving.
func (d *Dispatcher) claim(ctx context.Context, tenantID int64, eventType string) (fire bool, suppressed int64) {
	if d.rdb == nil {
		return true, 0
	}
	gate := fmt.Sprintf("mxid:alert:gate:%d:%s", tenantID, eventType)
	count := fmt.Sprintf("mxid:alert:suppressed:%d:%s", tenantID, eventType)

	ok, err := d.rdb.SetNX(ctx, gate, 1, d.cooldown).Result()
	if err != nil {
		return true, 0
	}
	if !ok {
		// Inside the window: fold this occurrence into the next alert. The
		// counter outlives the gate so the next alert can report it.
		_ = d.rdb.Incr(ctx, count).Err()
		_ = d.rdb.Expire(ctx, count, d.cooldown*4).Err()
		return false, 0
	}

	// We opened the window. Whatever accumulated under the previous one is
	// reported now and reset.
	n, err := d.rdb.GetDel(ctx, count).Int64()
	if err != nil {
		return true, 0
	}
	return true, n
}

func (d *Dispatcher) warn(msg string, fields ...zap.Field) {
	if d.logger != nil {
		d.logger.Warn(msg, fields...)
	}
}
