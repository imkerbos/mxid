package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitRule describes one token-bucket rule. The middleware applies
// the rule whose scope matches the inbound request; multiple rules can
// stack (per-IP + per-user) by chaining middleware instances.
type RateLimitRule struct {
	// Name appears in the 429 response so clients can disambiguate.
	Name string
	// Limit is the request count cap per Window.
	Limit int
	// Window is the bucket length. Must be at least one second.
	Window time.Duration
	// KeyFunc derives the bucket key from the request. Returning ""
	// skips the rule for this request (e.g. anonymous user on a
	// per-user limiter).
	KeyFunc func(c *gin.Context) string
	// MethodFilter, when non-nil, restricts the rule to the listed
	// HTTP methods. Empty / nil = all methods.
	MethodFilter map[string]bool
	// PathFilter, when non-nil, restricts the rule to paths matching
	// any of the supplied prefixes.
	PathFilter []string
}

// RateLimiter applies the given rule using a Redis-backed fixed-window
// counter. On Redis outages we fail open (log + allow): denial of
// legitimate traffic by limiter outage is worse than letting a real
// attacker through during the few seconds until Redis comes back.
//
// On limit exceeded we return 429 with Retry-After header (seconds
// until the current window flips) plus a JSON body documenting which
// rule fired.
func RateLimiter(rdb *redis.Client, rule RateLimitRule) gin.HandlerFunc {
	if rule.Window <= 0 {
		rule.Window = time.Minute
	}
	if rule.Limit <= 0 {
		rule.Limit = 60
	}
	return func(c *gin.Context) {
		if rule.MethodFilter != nil && !rule.MethodFilter[c.Request.Method] {
			c.Next()
			return
		}
		if len(rule.PathFilter) > 0 && !hasAnyPrefix(c.Request.URL.Path, rule.PathFilter) {
			c.Next()
			return
		}
		key := rule.KeyFunc(c)
		if key == "" {
			c.Next()
			return
		}

		windowSec := int64(rule.Window.Seconds())
		now := time.Now().Unix()
		bucket := now / windowSec
		redisKey := fmt.Sprintf("rl:%s:%s:%d", rule.Name, key, bucket)
		expiresIn := time.Duration(windowSec-(now%windowSec)) * time.Second

		count, err := rdb.Incr(c.Request.Context(), redisKey).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			// Fail open.
			c.Next()
			return
		}
		if count == 1 {
			_ = rdb.Expire(c.Request.Context(), redisKey, expiresIn).Err()
		}
		if int(count) > rule.Limit {
			c.Header("Retry-After", strconv.Itoa(int(expiresIn.Seconds())))
			c.Header("X-RateLimit-Limit", strconv.Itoa(rule.Limit))
			c.Header("X-RateLimit-Remaining", "0")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    42901,
				"message": fmt.Sprintf("rate limit exceeded: %s", rule.Name),
			})
			return
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(rule.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(rule.Limit-int(count)))
		c.Next()
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

// KeyByClientIP keys the bucket on the request's resolved client IP.
// Behind a trusted proxy gin already populates ClientIP() from the
// X-Forwarded-For header per ServerConfig.TrustedProxies.
func KeyByClientIP(c *gin.Context) string {
	ip := c.ClientIP()
	if ip == "" {
		return ""
	}
	return "ip:" + ip
}

// KeyByUserID keys the bucket on the authenticated user ID stored in the
// gin context by authn middleware. Returns "" for unauthenticated
// requests so the limiter falls back to the IP limiter on top.
func KeyByUserID(ctxKey string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		v, ok := c.Get(ctxKey)
		if !ok {
			return ""
		}
		switch id := v.(type) {
		case int64:
			if id == 0 {
				return ""
			}
			return "u:" + strconv.FormatInt(id, 10)
		case string:
			if id == "" {
				return ""
			}
			return "u:" + id
		}
		return ""
	}
}

// AllMutationMethods is the canonical filter set for "anything that
// changes server state".
var AllMutationMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// Ensure context import retained for clarity in client code; the
// gin.Context.Request.Context() is what we actually use above.
var _ = context.Background
