package event

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// Event represents a domain event.
type Event struct {
	Type    string
	Payload any
}

// Handler processes events.
type Handler func(ctx context.Context, event Event)

// Bus is an in-process event bus for module decoupling.
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
	logger   *zap.Logger
}

// NewBus creates a new event bus.
func NewBus(logger *zap.Logger) *Bus {
	return &Bus{
		handlers: make(map[string][]Handler),
		logger:   logger,
	}
}

// Subscribe registers a handler for an event type.
func (b *Bus) Subscribe(eventType string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Publish sends an event to all registered handlers asynchronously.
func (b *Bus) Publish(ctx context.Context, evt Event) {
	b.mu.RLock()
	handlers := b.handlers[evt.Type]
	b.mu.RUnlock()

	for _, h := range handlers {
		go func(handler Handler) {
			defer func() {
				if r := recover(); r != nil {
					b.logger.Error("event handler panic",
						zap.String("event_type", evt.Type),
						zap.Any("recover", r),
					)
				}
			}()
			handler(ctx, evt)
		}(h)
	}
}

// Event type constants.
const (
	UserCreated         = "user.created"
	UserUpdated         = "user.updated"
	UserDeleted         = "user.deleted"
	UserLocked          = "user.locked"
	UserUnlocked        = "user.unlocked"
	UserPasswordChanged = "user.password_changed"
	// UserPIIView fires when an admin reads another user's full PII
	// (phone / email / address / id-card). Self-views are excluded.
	// Carries actor_id, target_user_id, tenant_id, fields=[...]
	UserPIIView = "user.pii_view"
	// UserSuperAdminGrant / Revoke fires when the is_super_admin flag
	// flips on a user. Always audited; never auto-granted.
	UserSuperAdminGrant  = "user.super_admin.grant"
	UserSuperAdminRevoke = "user.super_admin.revoke"

	LoginSuccess = "login.success"
	LoginFailed  = "login.failed"
	Logout       = "logout"

	AppCreated  = "app.created"
	AppUpdated  = "app.updated"
	AppDeleted  = "app.deleted"
	AppLaunched = "app.launched" // portal user clicked an app card → drives "Recently used"

	OrgCreated     = "org.created"
	OrgUpdated     = "org.updated"
	OrgDeleted     = "org.deleted"
	OrgMemberMoved = "org.member_moved"

	GroupCreated       = "group.created"
	GroupUpdated       = "group.updated"
	GroupDeleted       = "group.deleted"
	GroupMemberAdded   = "group.member_added"
	GroupMemberRemoved = "group.member_removed"

	SessionKicked = "session.kicked"
	MFAEnabled    = "mfa.enabled"
	MFADisabled   = "mfa.disabled"

	// OIDC token-lifecycle events. Captured into the audit log so admins can
	// trace per-RP token issuance, refresh, revoke and reuse-detection
	// incidents across the IdP.
	OIDCTokenIssued       = "oidc.token.issued"
	OIDCTokenRefreshed    = "oidc.token.refreshed"
	OIDCTokenRevoked      = "oidc.token.revoked"
	OIDCTokenReuse        = "oidc.token.reuse_detected"
	OIDCConsentGranted    = "oidc.consent.granted"
	OIDCConsentRevoked    = "oidc.consent.revoked"
	OIDCBackchannelLogout = "oidc.backchannel_logout"
)
