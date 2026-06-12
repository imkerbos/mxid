package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// Service provides business logic for audit logging.
type Service struct {
	repo     Repository
	idGen    *snowflake.Generator
	eventBus *event.Bus
	logger   *zap.Logger
	tenantID int64
	geo      geoip.Resolver
}

// NewService creates a new audit service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus, logger *zap.Logger, tenantID int64) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
		logger:   logger,
		tenantID: tenantID,
		geo:      geoip.NoopResolver{},
	}
}

// SetGeoResolver wires the GeoIP backend. Pass geoip.NoopResolver{} to
// disable lookups (the default). Wrap with PrivateAwareResolver to skip
// RFC1918 / loopback addresses.
func (s *Service) SetGeoResolver(r geoip.Resolver) {
	if r == nil {
		s.geo = geoip.NoopResolver{}
		return
	}
	s.geo = r
}

// fillGeo resolves the IP and writes Country / City pointers onto the
// passed log. Errors are logged at debug and swallowed — geo enrichment
// is best-effort, never blocking the audit write.
func (s *Service) fillGeo(log *AuditLog, ip string) {
	if ip == "" || s.geo == nil {
		return
	}
	loc, err := s.geo.Lookup(ip)
	if err != nil {
		s.logger.Debug("geoip lookup", zap.String("ip", ip), zap.Error(err))
		return
	}
	if loc.Country != "" {
		c := loc.Country
		log.GeoCountry = &c
	}
	if loc.City != "" {
		c := loc.City
		log.GeoCity = &c
	}
}

// SubscribeEvents subscribes to domain events and creates audit logs automatically.
func (s *Service) SubscribeEvents() {
	// Login events
	s.eventBus.Subscribe(event.LoginSuccess, s.handleLoginSuccess)
	s.eventBus.Subscribe(event.LoginFailed, s.handleLoginFailed)
	s.eventBus.Subscribe(event.LoginRisk, s.handleLoginRisk)
	s.eventBus.Subscribe(event.Logout, s.handleLogout)

	// User events
	s.eventBus.Subscribe(event.UserCreated, s.handleUserEvent(event.UserCreated, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserUpdated, s.handleUserEvent(event.UserUpdated, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserDeleted, s.handleUserEvent(event.UserDeleted, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserLocked, s.handleUserEvent(event.UserLocked, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserUnlocked, s.handleUserEvent(event.UserUnlocked, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserPasswordChanged, s.handleUserEvent(event.UserPasswordChanged, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserPIIView, s.handleUserEvent(event.UserPIIView, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserSuperAdminGrant, s.handleUserEvent(event.UserSuperAdminGrant, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserSuperAdminRevoke, s.handleUserEvent(event.UserSuperAdminRevoke, EventStatusSuccess))

	// App events
	s.eventBus.Subscribe(event.AppCreated, s.handleResourceEvent(event.AppCreated, "app"))
	s.eventBus.Subscribe(event.AppUpdated, s.handleResourceEvent(event.AppUpdated, "app"))
	s.eventBus.Subscribe(event.AppDeleted, s.handleResourceEvent(event.AppDeleted, "app"))
	s.eventBus.Subscribe(event.AppLaunched, s.handleAppLaunched)

	// Org events
	s.eventBus.Subscribe(event.OrgCreated, s.handleResourceEvent(event.OrgCreated, "org"))
	s.eventBus.Subscribe(event.OrgUpdated, s.handleResourceEvent(event.OrgUpdated, "org"))
	s.eventBus.Subscribe(event.OrgDeleted, s.handleResourceEvent(event.OrgDeleted, "org"))

	// Session and MFA events
	s.eventBus.Subscribe(event.SessionKicked, s.handleGenericEvent(event.SessionKicked))
	s.eventBus.Subscribe(event.MFAEnabled, s.handleGenericEvent(event.MFAEnabled))
	s.eventBus.Subscribe(event.MFADisabled, s.handleGenericEvent(event.MFADisabled))

	// OIDC token-lifecycle events. Persisted as generic audit rows so
	// admins can trace per-RP issuance / refresh / reuse-detection / consent
	// across the IdP.
	s.eventBus.Subscribe(event.OIDCTokenIssued, s.handleGenericEvent(event.OIDCTokenIssued))
	s.eventBus.Subscribe(event.OIDCTokenRefreshed, s.handleGenericEvent(event.OIDCTokenRefreshed))
	s.eventBus.Subscribe(event.OIDCTokenRevoked, s.handleGenericEvent(event.OIDCTokenRevoked))
	s.eventBus.Subscribe(event.OIDCTokenReuse, s.handleGenericEvent(event.OIDCTokenReuse))
	s.eventBus.Subscribe(event.OIDCConsentGranted, s.handleGenericEvent(event.OIDCConsentGranted))
	s.eventBus.Subscribe(event.OIDCConsentRevoked, s.handleGenericEvent(event.OIDCConsentRevoked))
	s.eventBus.Subscribe(event.OIDCBackchannelLogout, s.handleGenericEvent(event.OIDCBackchannelLogout))
}

// List returns a paginated list of audit logs.
func (s *Service) List(ctx context.Context, params ListParams) ([]*AuditLog, int64, error) {
	return s.repo.List(ctx, params)
}

// GetStats returns audit statistics.
func (s *Service) GetStats(ctx context.Context, tenantID int64, start, end time.Time) (*AuditStatsResponse, error) {
	return s.repo.GetStats(ctx, tenantID, start, end)
}

// handleLoginSuccess creates an audit entry for a successful login.
func (s *Service) handleLoginSuccess(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	username := s.toString(payload["username"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)

	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      &userID,
		ActorName:    &username,
		ActorType:    ActorUser,
		EventType:    event.LoginSuccess,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		Detail:       s.marshalDetailFor(event.LoginSuccess, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLoginRisk records a conditional-access risk event: a login that fired a
// risk signal but was allowed through (the user had no second factor to
// challenge). Persisted so security operators can review risky logins.
func (s *Service) handleLoginRisk(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	ip := s.toString(payload["ip"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)
	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      &userID,
		ActorType:    ActorUser,
		EventType:    event.LoginRisk,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		Detail:       s.marshalDetailFor(event.LoginRisk, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLoginFailed creates an audit entry for a failed login attempt.
func (s *Service) handleLoginFailed(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	username := s.toString(payload["username"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)

	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      int64Ptr(userID),
		ActorName:    strPtr(username),
		ActorType:    ActorUser,
		EventType:    event.LoginFailed,
		EventStatus:  EventStatusFail,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		Detail:       s.marshalDetailFor(event.LoginFailed, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLogout creates an audit entry for a logout.
func (s *Service) handleLogout(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	sessionID := s.toString(payload["session_id"])

	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     s.tenantID,
		ActorID:      int64Ptr(userID),
		ActorType:    ActorUser,
		EventType:    event.Logout,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		SessionID:    strPtr(sessionID),
		Detail:       s.marshalDetailFor(event.Logout, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleUserEvent returns a handler for user-related domain events.
func (s *Service) handleUserEvent(eventType string, status int) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		userID := s.toInt64(payload["user_id"])
		resourceType := "user"

		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			ActorType:    ActorAdmin,
			EventType:    eventType,
			EventStatus:  status,
			ResourceType: &resourceType,
			ResourceID:   int64Ptr(userID),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}

		// If the event payload includes a username, use it as actor and resource name.
		if name := s.toString(payload["username"]); name != "" {
			log.ResourceName = &name
		}

		s.createLog(ctx, log)
	}
}

// handleResourceEvent returns a handler for generic resource events (app, org, etc.).
func (s *Service) handleResourceEvent(eventType, resourceType string) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		rt := resourceType
		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			ActorType:    ActorAdmin,
			EventType:    eventType,
			EventStatus:  EventStatusSuccess,
			ResourceType: &rt,
			ResourceID:   int64Ptr(s.toInt64(payload["id"])),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}

		if name := s.toString(payload["name"]); name != "" {
			log.ResourceName = &name
		}

		s.createLog(ctx, log)
	}
}

// handleAppLaunched records a portal-user app launch. ActorType is User
// (not Admin like CRUD writes) and ResourceID is the launched app — the
// "recently used" portal endpoint reads back via (actor_id, event_type,
// created_at DESC) so each field matters.
func (s *Service) handleAppLaunched(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	appID := s.toInt64(payload["app_id"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	sessionID := s.toString(payload["session_id"])

	rt := "app"
	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
		ActorID:      int64Ptr(userID),
		ActorType:    ActorUser,
		EventType:    event.AppLaunched,
		EventStatus:  EventStatusSuccess,
		ResourceType: &rt,
		ResourceID:   int64Ptr(appID),
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		SessionID:    strPtr(sessionID),
		Detail:       s.marshalDetailFor(event.AppLaunched, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleGenericEvent returns a handler for events that don't fit the resource pattern.
func (s *Service) handleGenericEvent(eventType string) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		log := &AuditLog{
			ID:          s.idGen.Generate(),
			TenantID:    s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			ActorType:   ActorSystem,
			EventType:   eventType,
			EventStatus: EventStatusSuccess,
			Detail:      s.marshalDetailFor(eventType, payload),
			CreatedAt:   time.Now(),
		}

		s.createLog(ctx, log)
	}
}

// createLog persists an audit log, logging any errors.
// Uses background context because event handlers may run after the HTTP request
// context is canceled.
func (s *Service) createLog(_ context.Context, log *AuditLog) {
	if log.IP != nil {
		s.fillGeo(log, *log.IP)
	}
	if err := s.repo.Create(context.Background(), log); err != nil {
		s.logger.Error("failed to create audit log",
			zap.String("event_type", log.EventType),
			zap.Error(err),
		)
	}
}

// --- helpers ---

func (s *Service) toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func (s *Service) toString(v any) string {
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

func (s *Service) toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}

func (s *Service) toInt64OrDefault(v any, def int64) int64 {
	val := s.toInt64(v)
	if val == 0 {
		return def
	}
	return val
}

// marshalDetailFor is the audit handlers' single path to producing the
// Detail column bytes. Routes through the per-event_type allow-list in
// schema.go so unrelated payload keys (incl. accidental secret leaks)
// are stripped before persist.
func (s *Service) marshalDetailFor(eventType string, payload map[string]any) json.RawMessage {
	return projectDetail(eventType, payload)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func int64Ptr(n int64) *int64 {
	if n == 0 {
		return nil
	}
	return &n
}
