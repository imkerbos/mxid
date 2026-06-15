package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	// ssoSessionPrefix matches the namespace used by pkg/session.Manager
	// when writing protocol-scope sessions in the login bridge, so SSO
	// authorize handlers can read what the auth gateway just wrote.
	ssoSessionPrefix    = "mxid:session:protocol:"
	portalSessionPrefix = "mxid:session:portal:"
	ssoSessionTTL       = 12 * time.Hour
)

// sessionResolverImpl implements SessionResolver using Redis.
type sessionResolverImpl struct {
	rdb *redis.Client
}

// NewSessionResolver creates a SessionResolver backed by Redis.
func NewSessionResolver(rdb *redis.Client) SessionResolver {
	return &sessionResolverImpl{rdb: rdb}
}

func (r *sessionResolverImpl) GetSSOSession(ctx context.Context, sessionID string) (*SSOSession, error) {
	// Look in the protocol namespace first (what login-bridge wrote), then
	// fall back to the portal namespace. IdP-initiated SSO from the portal
	// "我的应用" launcher arrives with only mxid_portal_sid set — falling
	// back here lets the protocol handler issue an assertion without
	// bouncing the user through /login a second time.
	prefixes := [...]string{ssoSessionPrefix, portalSessionPrefix}
	for _, prefix := range prefixes {
		data, err := r.rdb.Get(ctx, prefix+sessionID).Bytes()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return nil, fmt.Errorf("get sso session: %w", err)
		}
		var sess SSOSession
		if err := json.Unmarshal(data, &sess); err != nil {
			return nil, fmt.Errorf("unmarshal sso session: %w", err)
		}
		if time.Now().After(sess.ExpiresAt) {
			// Only the canonical protocol-prefixed key is owned by us; do
			// not clobber a portal session here.
			if prefix == ssoSessionPrefix {
				_ = r.DeleteSSOSession(ctx, sessionID)
			}
			return nil, nil
		}
		return &sess, nil
	}
	return nil, nil
}

func (r *sessionResolverImpl) CreateSSOSession(
	ctx context.Context,
	userID, tenantID int64,
	authType, ip, userAgent string,
) (*SSOSession, error) {
	sess := &SSOSession{
		ID:        uuid.New().String(),
		UserID:    userID,
		TenantID:  tenantID,
		AuthType:  authType,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ssoSessionTTL),
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("marshal sso session: %w", err)
	}

	key := ssoSessionPrefix + sess.ID
	if err := r.rdb.Set(ctx, key, data, ssoSessionTTL).Err(); err != nil {
		return nil, fmt.Errorf("store sso session: %w", err)
	}

	return sess, nil
}

func (r *sessionResolverImpl) DeleteSSOSession(ctx context.Context, sessionID string) error {
	key := ssoSessionPrefix + sessionID
	return r.rdb.Del(ctx, key).Err()
}
