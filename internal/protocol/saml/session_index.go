package saml

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SAMLSessionRef holds the session identifiers needed by IdP-initiated SLO
// to address a specific SAML session at the SP.
type SAMLSessionRef struct {
	SessionIndex string `json:"session_index"`
	NameID       string `json:"name_id"`
	SPEntityID   string `json:"sp_entity_id"`
	// NameIDFormat is the NameID format actually asserted at SSO time for
	// this session (captured alongside SessionIndex/NameID). It is threaded
	// through to the IdP-initiated LogoutRequest builder so SLO addresses
	// the SP with the same format it was originally given, rather than
	// whatever the app's config happens to hold at logout time.
	NameIDFormat string `json:"name_id_format"`
}

// SessionIndexStore persists per-user-per-app SAML session references in
// Redis so the IdP-initiated SLO path (Task L3) can look up every active
// SessionIndex + NameID to include in the LogoutRequest(s) it sends to the SP.
//
// Storage: Redis SET keyed mxid:saml:slo:<userID>:<appID>. Each member is a
// JSON-encoded SAMLSessionRef. This mirrors the CAS ServiceRegistry pattern
// (internal/protocol/cas/ticket_registry.go) and supports a user holding
// multiple concurrent SAML sessions to the same app (e.g. from different
// browsers/devices) — each SSO records its own ref, and SLO fans out a
// LogoutRequest per ref instead of only ever knowing about the most recent
// session.
type SessionIndexStore struct {
	rdb *redis.Client
}

// NewSessionIndexStore returns a SessionIndexStore backed by rdb.
func NewSessionIndexStore(rdb *redis.Client) *SessionIndexStore {
	return &SessionIndexStore{rdb: rdb}
}

func sloKey(userID, appID int64) string {
	return fmt.Sprintf("mxid:saml:slo:%d:%d", userID, appID)
}

// Record adds a SAML session ref to the set for userID+appID (does not
// overwrite any previous entry) and (re)sets the set's TTL. ttl should match
// the SAML assertion/session lifetime. If the same ref is recorded twice, the
// underlying Redis SET naturally de-dups the identical JSON member.
func (s *SessionIndexStore) Record(ctx context.Context, userID, appID int64, ref SAMLSessionRef, ttl time.Duration) error {
	b, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	key := sloKey(userID, appID)
	pipe := s.rdb.TxPipeline()
	pipe.SAdd(ctx, key, b)
	pipe.Expire(ctx, key, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// Get returns all stored session refs for userID+appID. Returns nil, nil
// when no entry is found (session expired or never recorded).
func (s *SessionIndexStore) Get(ctx context.Context, userID, appID int64) ([]SAMLSessionRef, error) {
	members, err := s.rdb.SMembers(ctx, sloKey(userID, appID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]SAMLSessionRef, 0, len(members))
	for _, m := range members {
		var ref SAMLSessionRef
		if json.Unmarshal([]byte(m), &ref) == nil {
			out = append(out, ref)
		}
	}
	return out, nil
}

// Delete removes all session refs for userID+appID. Called on logout.
func (s *SessionIndexStore) Delete(ctx context.Context, userID, appID int64) error {
	return s.rdb.Del(ctx, sloKey(userID, appID)).Err()
}
