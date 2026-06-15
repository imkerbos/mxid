// Package tenantscope carries the request's effective tenant isolation scope
// through the standard context.Context so the gorm tenant-isolation plugin
// (see Plugin) can enforce multi-tenant row isolation at the data layer —
// secure-by-default, without every repository remembering to add a
// `WHERE tenant_id = ?` predicate.
//
// Why a std-context value (not gin.Context)?
//
//	The gorm callback only ever sees db.Statement.Context — the std context the
//	repository was handed (c.Request.Context()). It cannot read the gin.Context
//	map. So the effective tenant + any cross-tenant escape MUST live on the std
//	context. This mirrors pkg/auditctx, which stamps the request actor the same
//	way.
//
// Fail-closed posture:
//
//	A query against a tenant-scoped model (one implementing the Tenanted marker)
//	with NO scope in context is an ERROR — never an unscoped read. The only way
//	to legitimately span tenants is an EXPLICIT, auditable escape: SystemContext
//	(background jobs / seeds) or WithCrossTenant (verified super_admin aggregate
//	reads). There is intentionally no blanket bypass.
package tenantscope

import (
	"context"
	"errors"
)

// ErrNoTenantScope is added to the gorm statement when a tenant-scoped model is
// queried without any scope in context. It surfaces as the query's error so a
// forgotten context fails closed instead of leaking another tenant's rows.
var ErrNoTenantScope = errors.New("tenantscope: no tenant scope in context for a tenant-scoped model (fail-closed)")

// Scope is the request's effective tenant isolation decision.
//
//	TenantID    the tenant every tenant-scoped query is pinned to.
//	CrossTenant a verified super_admin aggregate / cross-tenant read — skip the
//	            filter. Set ONLY by the tenant switcher / explicit aggregate paths.
//	System      a background job / seed / migration with no request — skip the
//	            filter. Set ONLY via SystemContext.
type Scope struct {
	TenantID    int64
	CrossTenant bool
	System      bool
}

type ctxKey struct{}

// With returns a copy of ctx carrying the given tenant scope.
func With(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// WithTenant is the common case: pin the context to a single tenant.
func WithTenant(ctx context.Context, tenantID int64) context.Context {
	return With(ctx, Scope{TenantID: tenantID})
}

// WithCrossTenant marks ctx as an explicit, verified cross-tenant operation
// (super_admin aggregate read across tenants). The plugin then skips the
// tenant filter. Use sparingly and only where the caller's authority to span
// tenants has already been checked.
func WithCrossTenant(ctx context.Context) context.Context {
	s, _ := From(ctx)
	s.CrossTenant = true
	return With(ctx, s)
}

// SystemContext returns a fresh context flagged as a system/background scope
// (no request, no tenant). Use for cron jobs, bootstrap seeds, and policy
// syncs that intentionally span all tenants. This is the ONLY sanctioned way
// for a context-less goroutine to touch tenant-scoped tables.
func SystemContext() context.Context {
	return With(context.Background(), Scope{System: true})
}

// WithSystem flags an existing context as a system scope (escape the filter).
func WithSystem(ctx context.Context) context.Context {
	s, _ := From(ctx)
	s.System = true
	return With(ctx, s)
}

// From extracts the scope. ok is false when no scope was ever stamped (e.g. a
// public route that never passed through the tenant middleware, or a
// background goroutine that forgot SystemContext) — which the plugin treats as
// fail-closed for tenant-scoped models.
func From(ctx context.Context) (Scope, bool) {
	if ctx == nil {
		return Scope{}, false
	}
	s, ok := ctx.Value(ctxKey{}).(Scope)
	return s, ok
}
