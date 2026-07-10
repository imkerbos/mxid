package oidcop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// defaultTokenRateLimitPerMin is the IdP-wide fallback per-client cap on the
// token endpoint when the app has not set a custom rate_limit_per_min in its
// protocol_config (clientConfig.RateLimitPerMin, client.go). This is an
// independent copy of the hand-rolled engine's
// internal/protocol/oidc.DefaultTokenRateLimitPerMin — same value, same
// meaning — rather than an import, because oidcop is deliberately built to
// have no dependency on the hand-rolled package slated for retirement (see
// the "kept local" note on clientConfig in client.go for the identical
// reasoning).
const defaultTokenRateLimitPerMin = 300

// tokenEndpointPath is op's custom token-endpoint route, configured in
// NewProvider via op.WithCustomTokenEndpoint(op.NewEndpoint("token")). This is
// the path AFTER Mount's http.StripPrefix removes the issuer prefix — i.e.
// exactly what WithTokenRateLimit sees once composed (as the innermost wrap
// around provider) ahead of Mount's http.StripPrefix.
const tokenEndpointPath = "/token"

// WithTokenRateLimit wraps next and enforces the same per-client_id
// fixed-window rate limit on the token endpoint that the hand-rolled engine
// applies (internal/protocol/oidc/handler.go:558's checkRateLimit) — ported
// here so /protocol/oidc/token is throttled identically once served by the
// zitadel engine. Every other path/method passes through untouched.
//
// client_id is read from whichever client-authentication surface the request
// used, WITHOUT verifying the secret/assertion (that happens later, inside
// op) — this is bucketing for abuse control only, exactly like the
// hand-rolled engine's peekClientID:
//   - client_secret_post / public+PKCE: the client_id form field.
//   - client_secret_basic: the HTTP Basic-auth username.
//   - private_key_jwt (RFC 7523): the sub/iss claim of the client_assertion
//     JWT, since such clients commonly omit the client_id form field.
//
// Reading the form to recover client_id would otherwise consume r.Body,
// which op needs intact to parse the actual grant. To avoid that, the raw
// body bytes are parsed in place with url.ParseQuery, and r.Body is restored
// via a fresh io.NopCloser(bytes.NewReader(...)) before next ever sees the
// request — next always gets the original, unread body.
//
// rdb may be nil (fails open, no limiting) and apps may be nil (falls back
// to defaultTokenRateLimitPerMin for every client) — both are optional so
// callers/tests can compose this without a full app wiring.
func WithTokenRateLimit(rdb *redis.Client, apps resolver.AppResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != tokenEndpointPath {
				next.ServeHTTP(w, r)
				return
			}

			clientID := peekTokenClientID(r)
			if clientID == "" {
				// Mirrors the hand-rolled engine: if we cannot identify the
				// client without verification, skip limiting rather than
				// block/misattribute — op's own auth will reject a bogus
				// request regardless.
				next.ServeHTTP(w, r)
				return
			}

			limit := defaultTokenRateLimitPerMin
			if apps != nil {
				if app, _ := apps.GetAppByClientID(r.Context(), clientID); app != nil {
					if cfg := parseClientConfig(app.ProtocolConfig); cfg.RateLimitPerMin > 0 {
						limit = cfg.RateLimitPerMin
					}
				}
			}

			allowed, retryAfter, _ := checkTokenRateLimit(r.Context(), rdb, clientID, limit)
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				// "slow_down" is the OAuth-registered error (RFC 8628 §3.5) for
				// "back off and retry" — matches the hand-rolled engine's 429
				// body verbatim so client-visible behavior is identical
				// across engines.
				_, _ = w.Write([]byte(`{"error":"slow_down","error_description":"client token-endpoint rate limit exceeded; retry after the Retry-After interval"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// peekTokenClientID extracts the asserted client_id from a token request
// without verifying it — the zitadel-engine counterpart of the hand-rolled
// engine's peekClientID (internal/protocol/oidc/handler.go:591). The fallback
// order MATCHES the hand-rolled engine exactly so both engines bucket an
// identical request under an identical key:
//  1. the form `client_id` field (client_secret_post / public+PKCE);
//  2. the HTTP Basic-auth username (client_secret_basic);
//  3. the `sub` (then `iss`) claim of the `client_assertion` JWT
//     (private_key_jwt / RFC 7523), which such clients commonly present WITHOUT
//     a client_id form field.
func peekTokenClientID(r *http.Request) string {
	// Basic-auth is read from the header and doesn't touch the body, but per
	// the hand-rolled precedence the form client_id wins first — so parse the
	// body up front and evaluate in that order.
	basicUser, _, hasBasic := r.BasicAuth()

	if r.Body == nil {
		if hasBasic && basicUser != "" {
			return basicUser
		}
		return ""
	}
	buf, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	// Restore BEFORE any early return so op always sees the original body,
	// regardless of whether parsing below succeeds.
	r.Body = io.NopCloser(bytes.NewReader(buf))
	if err != nil {
		if hasBasic && basicUser != "" {
			return basicUser
		}
		return ""
	}
	values, _ := url.ParseQuery(string(buf))

	if v := values.Get("client_id"); v != "" {
		return v
	}
	if hasBasic && basicUser != "" {
		return basicUser
	}
	if assertion := values.Get("client_assertion"); assertion != "" {
		if id := clientIDFromAssertion(assertion); id != "" {
			return id
		}
	}
	return ""
}

// clientIDFromAssertion recovers the client identity from a client_assertion
// JWT for rate-limit bucketing ONLY — it decodes the payload segment WITHOUT
// verifying the signature (op still performs the real RFC 7523 assertion auth
// downstream). Prefers `sub` then falls back to `iss`, mirroring the
// hand-rolled peekClientID (internal/protocol/oidc/handler.go:598-610). No
// outbound HTTP, no signature/JWKS fetch — pure local base64+JSON decode.
func clientIDFromAssertion(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if claims.Sub != "" {
		return claims.Sub
	}
	return claims.Iss
}

// checkTokenRateLimit performs a fixed-window 60-second rate limit check
// keyed by client_id — a direct port of internal/protocol/oidc/ratelimit.go's
// checkRateLimit (identical key format, window, and fail-open behavior) so
// the zitadel engine's token endpoint throttles the same way as the
// hand-rolled one. Returns (allowed, retryAfterSeconds, error).
// rateLimitClock is the time source for the fixed-window bucket. Defaults to
// time.Now (zero runtime change); tests override it to freeze the window so two
// rapid requests provably share a bucket instead of straddling a 60-second
// boundary on a slow CI runner (which flaked the 429 assertions).
var rateLimitClock = time.Now

func checkTokenRateLimit(ctx context.Context, rdb *redis.Client, clientID string, limit int) (bool, int, error) {
	if rdb == nil || clientID == "" || limit <= 0 {
		return true, 0, nil
	}
	now := rateLimitClock().Unix()
	bucket := now / 60
	key := fmt.Sprintf("mxid:oidc:ratelimit:%s:%d", clientID, bucket)

	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 65*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		// Fail-open on Redis hiccup — better to admit a few extra requests
		// than to outage the token endpoint when the limiter dependency is
		// sick (same tradeoff as the hand-rolled engine's checkRateLimit).
		return true, 0, err
	}
	count := int(incr.Val())
	if count > limit {
		retryAfter := 60 - int(now%60)
		return false, retryAfter, nil
	}
	return true, 0, nil
}
