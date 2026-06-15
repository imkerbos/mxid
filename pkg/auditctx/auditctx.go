// Package auditctx carries request-scoped actor identity (who / from where)
// through the standard context.Context so audit writes can attribute an event
// to the authenticated caller without every publisher hand-assembling the
// fields.
//
// The auth middleware stamps an Actor onto c.Request.Context() once per
// request; domain services pass that context down into eventBus.Publish, and
// the audit handlers read it back via From. Crucially the Actor is stored as a
// context *value* (not tied to cancellation), so an async audit handler that
// runs after the HTTP request context is already canceled can still read it —
// the previous design resolved the actor name with the canceled request
// context and silently got an empty string.
package auditctx

import "context"

// Actor type values. Mirror audit.ActorType constants but kept here as plain
// strings to avoid an import cycle (audit imports auditctx, not vice versa).
const (
	TypeUser   = "user"
	TypeAdmin  = "admin"
	TypeSystem = "system"
	TypeAPI    = "api"
)

// Actor is the request-scoped identity of the caller plus the network context
// of the current request. IP / UserAgent are the LIVE request values (not the
// login-time session values) so an audit row reflects where THIS action came
// from.
type Actor struct {
	ActorID   int64
	ActorType string
	ActorName string
	TenantID  int64
	SessionID string
	IP        string
	UserAgent string
}

type ctxKey struct{}

// With returns a copy of ctx carrying the given actor.
func With(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// From extracts the actor stamped by the auth middleware. ok is false when the
// request was unauthenticated (public route) or the context never passed
// through the stamping middleware.
func From(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(ctxKey{}).(Actor)
	return a, ok
}
