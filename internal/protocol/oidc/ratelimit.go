package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultTokenRateLimitPerMin is the IdP-wide fallback when an app has not
// set RateLimitPerMin in its protocol_config. 300 rps/min ≈ 5/sec, ample
// for normal interactive flows; M2M services that legitimately need more
// raise it per-app.
const DefaultTokenRateLimitPerMin = 300

// checkRateLimit performs a fixed-window 60-second rate limit check keyed
// by client_id. Returns (allowed, retryAfterSeconds, error).
//
// Implementation: INCR a per-minute bucket; first writer sets TTL=60s. The
// window jitter from fixed buckets is acceptable for protective limits and
// avoids the complexity of a sliding window log for this milestone.
func checkRateLimit(ctx context.Context, rdb *redis.Client, clientID string, limit int) (bool, int, error) {
	if clientID == "" || limit <= 0 {
		return true, 0, nil
	}
	bucket := time.Now().Unix() / 60
	key := fmt.Sprintf("mxid:oidc:ratelimit:%s:%d", clientID, bucket)

	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 65*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		// Fail-open on Redis hiccup — better to admit a few extra requests
		// than to outage the token endpoint when the limiter dependency is sick.
		return true, 0, err
	}
	count := int(incr.Val())
	if count > limit {
		retryAfter := 60 - int(time.Now().Unix()%60)
		return false, retryAfter, nil
	}
	return true, 0, nil
}
