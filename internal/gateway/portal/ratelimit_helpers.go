package portal

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/response"
)

// rateLimited returns the *RateLimitError when the identifier is currently
// locked by the limiter, or nil to proceed. A nil limiter (unwired) never
// blocks. Centralised so the sms-otp / magic-link / password-reset handlers
// share one Check-and-respond shape.
func rateLimited(ctx context.Context, l *ratelimit.Limiter, identifier string) *ratelimit.RateLimitError {
	if l == nil {
		return nil
	}
	err := l.Check(ctx, identifier)
	if err == nil {
		return nil
	}
	var rle *ratelimit.RateLimitError
	if errors.As(err, &rle) {
		return rle
	}
	// Non-typed error (shouldn't happen) — synthesize a generic lock so
	// fail-closed still surfaces a 429 rather than slipping through.
	return &ratelimit.RateLimitError{RetryAfter: 0}
}

// respondRateLimited writes a 429 with a Retry-After header derived from the
// limiter's remaining lock TTL.
func respondRateLimited(c *gin.Context, rle *ratelimit.RateLimitError) {
	if rle.RetryAfter > 0 {
		c.Header("Retry-After", strconv.Itoa(int(rle.RetryAfter.Seconds())))
	}
	response.Error(c, http.StatusTooManyRequests, 42901,
		"too many attempts, please try again later", "")
}
