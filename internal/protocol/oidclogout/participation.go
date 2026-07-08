package oidclogout

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ssoAppsPrefix tracks the set of OIDC apps that authenticated against a
// given protocol SSO session. Back-channel logout fan-out uses this to
// enumerate RPs to notify. Same Redis key shape as the retiring hand-rolled
// engine (internal/protocol/oidc/store.go) so both engines' participation
// data is interchangeable during the migration.
const ssoAppsPrefix = "mxid:sso:apps:"

// Index is the (sid -> appIDs) participation index over Redis, engine
// independent. Track/Peek/List mirror internal/protocol/oidc/store.go's
// TrackSSOApp/PeekSSOApps/ListSSOApps semantics exactly, including the
// destructive-List vs non-destructive-Peek distinction that JIT per-app
// logout depends on (Peek must never consume the tracking set, or a later
// full logout would silently miss the other participating apps).
type Index struct {
	rdb *redis.Client
}

// NewIndex wires an Index over the given Redis client.
func NewIndex(rdb *redis.Client) *Index {
	return &Index{rdb: rdb}
}

// Track records that the given OIDC app authenticated a user via the given
// protocol SSO session. Idempotent SADD — duplicate authorize calls for the
// same session/app pair leave the set untouched.
//
// ttl mirrors the SSO session's remaining absolute window so the set
// self-cleans after the session is gone; callers should pass
// time.Until(session.ExpiresAt).
func (x *Index) Track(ctx context.Context, sid string, appID int64, ttl time.Duration) error {
	if sid == "" {
		return nil
	}
	key := ssoAppsPrefix + sid
	pipe := x.rdb.Pipeline()
	pipe.SAdd(ctx, key, appID)
	if ttl > 0 {
		pipe.Expire(ctx, key, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Peek returns the app IDs a protocol SSO session authenticated against
// WITHOUT removing the tracking set. Use this for per-app JIT logout paths
// that must inspect the set but leave it intact so a subsequent full logout
// (List) can still fan out to all participating RPs.
func (x *Index) Peek(ctx context.Context, sid string) ([]int64, error) {
	if sid == "" {
		return nil, nil
	}
	return x.readMembers(ctx, ssoAppsPrefix+sid)
}

// List returns the app IDs a protocol SSO session authenticated against, then
// removes the tracking set. DESTRUCTIVE: the Redis key is deleted after the
// read. Intended for end-session / offboarding fan-out, which does not need
// the set to survive because the session itself is being torn down. For
// non-terminal per-app JIT logout, use Peek instead.
func (x *Index) List(ctx context.Context, sid string) ([]int64, error) {
	if sid == "" {
		return nil, nil
	}
	key := ssoAppsPrefix + sid
	ids, err := x.readMembers(ctx, key)
	if err != nil {
		return nil, err
	}
	x.rdb.Del(ctx, key)
	return ids, nil
}

func (x *Index) readMembers(ctx context.Context, key string) ([]int64, error) {
	members, err := x.rdb.SMembers(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	ids := make([]int64, 0, len(members))
	for _, m := range members {
		var id int64
		_, _ = fmt.Sscanf(m, "%d", &id)
		if id != 0 {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
