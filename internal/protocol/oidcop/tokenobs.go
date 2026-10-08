package oidcop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/metrics"
)

// GinCtxOIDCClientID and GinCtxOIDCError are the gin-context keys the token
// observer stamps and internal/middleware.Logger reads back. They are declared
// here (the producer) rather than in the logger, which treats both as optional
// and emits nothing when they are absent.
const (
	GinCtxOIDCClientID = "oidc_client_id"
	GinCtxOIDCError    = "oidc_error"
)

// maxCapturedErrorBody bounds the response bytes the observer retains in order
// to read the OAuth `error` code out of a rejection.
//
// An OIDC error response is a small fixed-shape object — {"error":"...",
// "error_description":"..."} (RFC 6749 §5.2) — so a couple of kilobytes is
// generous. The cap exists because a response body is an unbounded thing and
// this buffer sits on the request path: see the "bound anything an outsider can
// grow" rule. Truncation only costs the error code on a pathological body, and
// the audit event still records the client and the status.
const maxCapturedErrorBody = 2 << 10

// Burst thresholds for repeated token-endpoint rejections by ONE client.
//
// Chosen against the endpoint's own rate limit, which is a capacity guard, not
// a credential-abuse signal: at 300/min per client it does not react to a run
// of a few dozen rejections. Ten in five minutes sits far below any such run
// and far above the one or two rejections a healthy RP produces when a user
// takes the browser back button and redeems a stale code.
//
// A misconfigured RP looping on a bad secret will cross it too. That is
// intended: a client failing this often is either under attack or broken, and
// both want an operator looking.
const (
	grantRejectBurstThreshold = 10
	grantRejectBurstWindow    = 5 * time.Minute
)

// WithTokenObserver returns gin middleware that makes token-endpoint
// rejections attributable and alertable.
//
// WHY THIS EXISTS. The token endpoint had no usable failure record. zitadel
// logs its own protocol rejections through authorizer.Logger(), a plain
// *slog.Logger we never wired, so they came out as bare text with no request
// id, no client_id and no source IP — unjoinable to the access-log line next to
// them. And because the console's alert webhook dispatches off audit event
// types, and a protocol rejection produced no audit event, no configurable
// alert could ever cover one. A client secret being probed therefore left
// nothing an operator could alert on, and nothing afterwards that said which
// client it was.
//
// WHAT IT ADDS. Two optional fields on the existing access-log line
// (oidc_client_id, oidc_error) so one self-contained JSON record carries
// client, outcome, reason, IP and request id; and an event.OIDCGrantRejected on
// the bus so the audit chain and the alert webhook both see it.
//
// SAFETY. A successful token response contains the access and refresh tokens,
// so two separate mechanisms keep one out of a log line or an audit row. The
// status check below decides not to read the buffer on a 2xx; the Reset that
// follows it empties the buffer so a later edit CANNOT read it. Only the first
// is testable from outside — TestTokenObserver_SuccessExposesNoToken proves
// nothing observable carries a token today and that a success publishes no
// event, but no test can forbid a future line that logs a buffer, which is why
// the buffer is emptied instead of merely left alone.
//
// Publishing is on the event bus, not a direct audit write, for a second
// deliberate reason: this is the protocol REJECTION path. Our audit design
// aborts a business write whose audit capture fails, which is right for a write
// API and would be badly wrong here — it would turn a correct 400 into a 500
// and hand an attacker an availability lever. event.Bus dispatches detached
// from the request, so a sick audit pipeline cannot change the protocol answer.
//
// tokenPath is the FULL request path of the token endpoint (issuer path +
// "/token"): unlike WithTokenRateLimit this runs at the gin layer, above
// Mount's http.StripPrefix, so it sees the un-stripped path. Every other path
// and method falls through untouched.
//
// rdb, bus and apps may all be nil — the observer then logs what it can and
// publishes or counts nothing, so tests and reduced wirings compose without
// stubs.
func WithTokenObserver(rdb *redis.Client, bus *event.Bus, apps resolver.AppResolver, tokenPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || c.Request.URL.Path != tokenPath {
			c.Next()
			return
		}

		// Reuses the rate limiter's peek: the asserted client_id off whichever
		// client-authentication surface the request used, body restored intact
		// for op. Unverified by design — it is the identity being CLAIMED, which
		// is exactly what a rejection record needs to name.
		clientID := peekTokenClientID(c.Request)
		if clientID != "" {
			c.Set(GinCtxOIDCClientID, clientID)
		}

		// Stamp an actor so the audit row has an IP and an actor type like every
		// other row. Nothing else does it here: a token call carries no session
		// cookie, so no auth middleware runs and enrich() would find no
		// auditctx at all. TypeAPI, not TypeUser — the caller is a machine.
		c.Request = c.Request.WithContext(auditctx.With(c.Request.Context(), auditctx.Actor{
			ActorID:   0,
			ActorType: auditctx.TypeAPI,
			ActorName: clientID,
			TenantID:  0,
			SessionID: "",
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}))

		rec := &errorBodyRecorder{ResponseWriter: c.Writer, buf: bytes.Buffer{}}
		c.Writer = rec

		c.Next()

		status := c.Writer.Status()
		if status < http.StatusBadRequest {
			// A 2xx body IS the access and refresh tokens. Drop the copy here
			// rather than merely declining to read it: the early return is a
			// decision a later edit can move, an emptied buffer is a property
			// nothing downstream can undo. Tests can assert "no token reached
			// anything observable" but cannot stop a future change from logging
			// this buffer — so leave it with nothing to log.
			rec.buf.Reset()
			return
		}

		errCode := oauthErrorCode(rec.buf.Bytes())
		if errCode != "" {
			c.Set(GinCtxOIDCError, errCode)
		}

		metrics.OIDCGrantRejected(errCode)

		if bus == nil {
			return
		}
		payload := map[string]any{
			"client_id": clientID,
			"error":     errCode,
			"ip":        c.ClientIP(),
		}
		// app_id / tenant_id only when the claimed client resolves to a real
		// app. A probe naming a client that does not exist is still worth a
		// record — it just has nothing to attach to.
		if apps != nil && clientID != "" {
			if app, _ := apps.GetAppByClientID(c.Request.Context(), clientID); app != nil {
				payload["app_id"] = app.ID
				payload["tenant_id"] = app.TenantID
			}
		}
		bus.Publish(c.Request.Context(), event.Event{Type: event.OIDCGrantRejected, Payload: payload})

		// Per-client burst signal. Published exactly once per window — on the
		// request that crosses the threshold — so it alerts without needing the
		// dispatcher's suppression gate, whose tenant+event_type key would let
		// one noisy client bury another's.
		if n, crossed := bumpGrantRejectBurst(c.Request.Context(), rdb, clientID); crossed {
			burst := make(map[string]any, len(payload)+2)
			for k, v := range payload {
				burst[k] = v
			}
			burst["count"] = n
			burst["window_seconds"] = int(grantRejectBurstWindow.Seconds())
			bus.Publish(c.Request.Context(), event.Event{Type: event.OIDCGrantRejectedBurst, Payload: burst})
		}
	}
}

// bumpGrantRejectBurst counts this client's rejections in a fixed window and
// reports whether THIS request is the one that crossed the threshold.
//
// Fixed window, same shape as checkTokenRateLimit: a sliding window would be
// more precise and needs a sorted set per client, which is a bigger thing to
// run on the request path for a signal whose job is "wake someone up". Firing
// on equality (not >=) is what makes it one event per window instead of one per
// request after the threshold.
//
// Fails CLOSED in the sense that matters here: a Redis error reports no burst
// rather than a spurious one, because every individual rejection is already
// published as OIDCGrantRejected — the burst event is an escalation, and a
// broken counter must not invent an incident. The underlying rejections are
// never lost to it.
func bumpGrantRejectBurst(ctx context.Context, rdb *redis.Client, clientID string) (int64, bool) {
	if rdb == nil || clientID == "" {
		return 0, false
	}
	bucket := time.Now().Unix() / int64(grantRejectBurstWindow.Seconds())
	key := fmt.Sprintf("mxid:oidc:grantreject:%s:%d", clientID, bucket)

	pipe := rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, grantRejectBurstWindow+time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, false
	}
	n := incr.Val()
	return n, n == grantRejectBurstThreshold
}

// errorBodyRecorder tees the response into a bounded buffer so a rejection's
// OAuth error code can be read after the handler has written it.
//
// It wraps rather than replaces gin's writer: op writes the real response
// straight through, and the copy is incidental. Writes past the cap are
// forwarded but not retained.
type errorBodyRecorder struct {
	gin.ResponseWriter
	buf bytes.Buffer
}

func (r *errorBodyRecorder) Write(b []byte) (int, error) {
	r.keep(b)
	return r.ResponseWriter.Write(b)
}

func (r *errorBodyRecorder) WriteString(s string) (int, error) {
	r.keep([]byte(s))
	return r.ResponseWriter.WriteString(s)
}

func (r *errorBodyRecorder) keep(b []byte) {
	if room := maxCapturedErrorBody - r.buf.Len(); room > 0 {
		if len(b) > room {
			b = b[:room]
		}
		r.buf.Write(b)
	}
}

// oauthErrorCode extracts the `error` member of an OAuth/OIDC error response
// (RFC 6749 §5.2). Returns "" when the body is not such an object — a
// non-JSON 4xx from a layer above op, say — in which case the record carries
// the status without a reason rather than a guess.
//
// The value is clamped: it is echoed into a log field and an audit detail, and
// it arrives from a library response, so it is treated as untrusted length.
func oauthErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	code := strings.TrimSpace(resp.Error)
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}
