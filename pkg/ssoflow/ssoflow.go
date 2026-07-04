// Package ssoflow issues and consumes one-time "SSO login confirmation" tokens.
//
// The product requirement: every SP-initiated SSO (a third-party app like
// JumpServer sends the user to us) must show a confirmation screen ("log in to
// App X as <you>? [confirm] [cancel]") before we release the assertion / code /
// ticket, while IdP-initiated launches (the user clicks an app in our portal)
// stay seamless.
//
// The mechanism: when the user approves on the confirmation page, we mint a
// short-lived token bound to (userID, appID). The protocol handler then replays
// its authorize/sso/login endpoint carrying that token and Consume()s it exactly
// once, which lets it skip re-confirming and proceed. Without this one-shot
// token the "confirm on every SP-initiated login" rule would loop forever
// (confirm → replay → confirm → …). The token is single-use and expires fast, so
// it grants no lasting consent — the next SP-initiated login confirms again.
package ssoflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix  = "ssoconfirm:"
	defaultTTL = 5 * time.Minute
)

// ConfirmStore is the Redis-backed one-time confirmation-token store.
type ConfirmStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewConfirmStore builds a store over the shared Redis client.
func NewConfirmStore(rdb *redis.Client) *ConfirmStore {
	return &ConfirmStore{rdb: rdb, ttl: defaultTTL}
}

// Issue mints a one-time confirmation token bound to (userID, appID) and stores
// it with a short TTL. Returned to the confirm page's approve handler; the
// protocol replay presents it back.
func (s *ConfirmStore) Issue(ctx context.Context, userID, appID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ssoflow: generate token: %w", err)
	}
	token := hex.EncodeToString(b)
	// Value binds the token to the exact (user, app) it was approved for, so a
	// token minted for one app can't be replayed against another.
	val := fmt.Sprintf("%d:%d", userID, appID)
	if err := s.rdb.Set(ctx, keyPrefix+token, val, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("ssoflow: store token: %w", err)
	}
	return token, nil
}

// Consume atomically fetches-and-deletes the token, returning true only when it
// exists AND was minted for this exact (userID, appID). Single-use: a second
// Consume of the same token returns false. Any Redis error is treated as "not
// valid" (fail-closed — the caller re-confirms).
func (s *ConfirmStore) Consume(ctx context.Context, token string, userID, appID int64) bool {
	if token == "" {
		return false
	}
	val, err := s.rdb.GetDel(ctx, keyPrefix+token).Result()
	if err != nil {
		return false
	}
	return val == fmt.Sprintf("%d:%d", userID, appID)
}
