package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Namespace prefixes for session isolation.
const (
	NamespaceConsole  = "mxid:session:console"
	NamespacePortal   = "mxid:session:portal"
	NamespaceProtocol = "mxid:session:protocol"
)

// Session represents an authenticated user session.
type Session struct {
	ID           string    `json:"id"`
	UserID       int64     `json:"user_id"`
	TenantID     int64     `json:"tenant_id"`
	Namespace    string    `json:"namespace"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	AuthType     string    `json:"auth_type"`
	MFAVerified  bool      `json:"mfa_verified"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// PolicyProvider returns runtime idle and absolute timeouts. When set,
// values are looked up per Create / Get call from admin-configured policy
// (DB-backed setting). Static fields stay as fallback when provider is nil
// or returns zero/negative values.
type PolicyProvider func(ctx context.Context) (idle, absolute time.Duration)

// Manager handles session lifecycle operations.
type Manager struct {
	redis           *redis.Client
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	policy          PolicyProvider
}

// NewManager creates a session manager.
func NewManager(rdb *redis.Client, idleTimeout, absoluteTimeout time.Duration) *Manager {
	return &Manager{
		redis:           rdb,
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
	}
}

// SetPolicyProvider installs a runtime policy lookup. Safe to call once
// after construction; not goroutine-safe for repeated swaps.
func (m *Manager) SetPolicyProvider(p PolicyProvider) { m.policy = p }

// resolveTimeouts returns the effective (idle, absolute) for this request,
// preferring the runtime policy and falling back to the static config.
func (m *Manager) resolveTimeouts(ctx context.Context) (time.Duration, time.Duration) {
	idle, abs := m.idleTimeout, m.absoluteTimeout
	if m.policy != nil {
		if pIdle, pAbs := m.policy(ctx); pIdle > 0 && pAbs > 0 {
			idle, abs = pIdle, pAbs
		}
	}
	return idle, abs
}

// Create creates a new session.
func (m *Manager) Create(ctx context.Context, namespace string, userID, tenantID int64, ip, userAgent, authType string) (*Session, error) {
	_, absolute := m.resolveTimeouts(ctx)
	now := time.Now()
	sess := &Session{
		ID:           uuid.New().String(),
		UserID:       userID,
		TenantID:     tenantID,
		Namespace:    namespace,
		IP:           ip,
		UserAgent:    userAgent,
		AuthType:     authType,
		CreatedAt:    now,
		ExpiresAt:    now.Add(absolute),
		LastActiveAt: now,
	}

	if err := m.save(ctx, sess); err != nil {
		return nil, err
	}

	// Add to user's session set for listing
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	m.redis.SAdd(ctx, userKey, sess.ID)
	m.redis.Expire(ctx, userKey, absolute)

	return sess, nil
}

// Get retrieves a session by ID. READ-ONLY: this method does NOT refresh
// LastActiveAt. Callers that represent a real user request (auth
// middleware) must call Touch() afterwards. Listing/inspection callers
// (security/sessions UI, admin tools) must NOT touch — otherwise every
// list view extends every idle session's clock and idle timeout never
// fires.
//
// Returns (nil, nil) when the session is absent, absolute-expired, or
// idle-expired. Idle/absolute expired rows are deleted as a side effect
// (cheap cleanup; idempotent).
func (m *Manager) Get(ctx context.Context, namespace, sessionID string) (*Session, error) {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	now := time.Now()
	idle, _ := m.resolveTimeouts(ctx)
	if now.After(sess.ExpiresAt) || now.After(sess.LastActiveAt.Add(idle)) {
		_ = m.Delete(ctx, namespace, sessionID)
		return nil, nil
	}

	return &sess, nil
}

// Touch refreshes LastActiveAt on a live session. Called by the auth
// middleware after Get() succeeds on a real user request. Errors are
// logged at the caller; we don't want a Redis hiccup to fail the request.
func (m *Manager) Touch(ctx context.Context, namespace, sessionID string) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("touch get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return fmt.Errorf("touch unmarshal: %w", err)
	}
	sess.LastActiveAt = time.Now()
	return m.save(ctx, &sess)
}

// Delete removes a session.
func (m *Manager) Delete(ctx context.Context, namespace, sessionID string) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	return m.redis.Del(ctx, key).Err()
}

// ListByUser returns all sessions for a user in a namespace.
func (m *Manager) ListByUser(ctx context.Context, namespace string, userID int64) ([]*Session, error) {
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	ids, err := m.redis.SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(ids))
	for _, id := range ids {
		sess, err := m.Get(ctx, namespace, id)
		if err != nil {
			continue
		}
		if sess != nil {
			sessions = append(sessions, sess)
		} else {
			// Cleanup stale reference
			m.redis.SRem(ctx, userKey, id)
		}
	}

	return sessions, nil
}

// DeleteAllByUser removes all sessions for a user in a namespace.
func (m *Manager) DeleteAllByUser(ctx context.Context, namespace string, userID int64) error {
	sessions, err := m.ListByUser(ctx, namespace, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		_ = m.Delete(ctx, namespace, s.ID)
	}
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	return m.redis.Del(ctx, userKey).Err()
}

func (m *Manager) save(ctx context.Context, sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	key := fmt.Sprintf("%s:%s", sess.Namespace, sess.ID)
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	return m.redis.Set(ctx, key, data, ttl).Err()
}
