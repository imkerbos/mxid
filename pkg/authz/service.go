package authz

import (
	"context"
	"fmt"
	"time"
)

// Service answers "may this user perform this permission on this target?".
//
// State: holds only collaborators (BindingProvider, OrgAncestry). It does
// not cache results here — wrap with a Redis cache in front if needed.
// EffectiveBindingsForUser is expected to be cheap enough on its own (one
// flat join per call) for an MVP.
type Service struct {
	bindings BindingProvider
	orgTree  OrgAncestry

	// casbin owns the role→permission catalog decision. When nil the engine
	// falls back to the binding's own Permissions set (legacy path, used by
	// pure-logic tests and by any deployment that hasn't wired the enforcer).
	casbin *CasbinEngine
}

// NewService wires a Service. The role→permission decision uses the binding's
// inlined Permissions set unless a Casbin engine is attached via WithCasbin.
func NewService(b BindingProvider, o OrgAncestry) *Service {
	return &Service{bindings: b, orgTree: o}
}

// WithCasbin attaches a Casbin engine as the role→permission authority. The
// engine answers "does this binding's role hold perm in this tenant"; the Go
// scopeCovers below still decides instance scope (org ltree / group / kind).
// Returns the same Service for chaining.
func (s *Service) WithCasbin(e *CasbinEngine) *Service {
	s.casbin = e
	return s
}

// Check is the engine's only entry point. Semantics:
//
//   - super_admin (binding holding the wildcard "*" permission) short-circuits
//     to allow without scope checks. This mirrors AWS's "iam:*" and Okta's
//     super admin behaviour.
//   - Any other binding must satisfy BOTH:
//       1. its permission set contains `perm`
//       2. its scope covers `target` (see scopeCovers)
//   - target == nil treats the call as scope-agnostic: any matching binding
//     allows. Use for queries that internally filter by scope themselves.
//
// Returns a structured error only when the input is malformed; permission
// denial is signalled by allow=false, err=nil. Engine errors (DB lookup
// failures) default to deny.
func (s *Service) Check(ctx context.Context, tenantID, userID int64, perm string, target *ScopeTarget) (bool, error) {
	if perm == "" {
		return false, fmt.Errorf("authz: empty permission")
	}
	if s.bindings == nil {
		return false, fmt.Errorf("authz: binding provider not configured")
	}

	binds, err := s.bindings.EffectiveBindingsForUser(ctx, tenantID, userID)
	if err != nil {
		// Fail-closed on lookup error — never accidentally widen access.
		return false, fmt.Errorf("load effective bindings: %w", err)
	}

	now := time.Now()
	for _, b := range binds {
		// Final enforcement of time-bound (JIT) grant expiry. The DB resolver
		// and cache-serialization carry ExpiresAt through, but cached decisions
		// can lag the actual TTL by up to the sweeper interval (~30s). Skipping
		// expired bindings here makes expiry immediate regardless of cache/
		// sweeper timing. A nil ExpiresAt is a permanent binding — honor it.
		if b.ExpiresAt != nil && b.ExpiresAt.Before(now) {
			continue
		}
		if !s.bindingGrantsPerm(tenantID, b, perm) {
			continue
		}
		ok, err := s.scopeCovers(ctx, b, target)
		if err != nil {
			// Same fail-closed posture as above.
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// bindingGrantsPerm decides the role→permission half of a binding match. With
// a Casbin engine attached the decision is delegated to the enforcer
// (Enforce(roleSubject, tenantDomain, perm)); otherwise it falls back to the
// binding's inlined Permissions set. Both honour the "*" super-permission and
// keep matching EXACT (no globs).
func (s *Service) bindingGrantsPerm(tenantID int64, b EffectiveBinding, perm string) bool {
	if s.casbin == nil {
		return hasPermission(b.Permissions, perm)
	}
	return s.casbin.RoleHasPermission(tenantID, bindingRoleSubject(b), perm)
}

// bindingRoleSubject maps an EffectiveBinding to the Casbin role subject the
// enforcer was loaded with. The super-admin binding (synthesized with
// RoleID==0 and the "*" wildcard) maps to the synthetic super_admin role;
// every other binding maps to its concrete role id.
func bindingRoleSubject(b EffectiveBinding) string {
	if b.RoleID == 0 {
		if _, ok := b.Permissions["*"]; ok {
			return superAdminRole
		}
	}
	return roleSubject(b.RoleID)
}

// hasPermission reports whether the binding's permission set covers `perm`.
// Wildcard "*" means super admin — matches anything.
func hasPermission(set map[string]struct{}, perm string) bool {
	if _, ok := set["*"]; ok {
		return true
	}
	_, ok := set[perm]
	return ok
}

// scopeCovers decides whether a binding's scope contains the target.
//
//	binding.global  → covers everything
//	binding.org=X   → covers target.kind=org if X is ancestor-or-self of target.ID;
//	                  also covers target.kind=group only when scope rules
//	                  delegate (NOT in MVP — return false).
//	binding.group=X → covers target.kind=group iff X == target.ID. group scope
//	                  does not extend to user/org targets.
//	target == nil   → always covered (caller does its own filtering).
func (s *Service) scopeCovers(ctx context.Context, b EffectiveBinding, target *ScopeTarget) (bool, error) {
	if b.ScopeType == ScopeGlobal {
		return true, nil
	}
	if target == nil {
		return true, nil
	}

	switch b.ScopeType {
	case ScopeOrg:
		if target.Kind != ScopeOrg {
			// A scope_type=org binding only authorises operations on org
			// resources for now. user/group scoping flows through other
			// bindings (group-inherited / direct).
			return false, nil
		}
		if s.orgTree == nil {
			return false, fmt.Errorf("authz: org ancestry checker missing for org-scoped check")
		}
		return s.orgTree.IsAncestorOrSelf(ctx, b.ScopeID, target.ID)
	case ScopeGroup:
		if target.Kind != ScopeGroup {
			return false, nil
		}
		return b.ScopeID == target.ID, nil
	}
	return false, nil
}

// PermissionsForUser collects every permission code the user holds across
// all bindings, regardless of scope. Useful for "what can I do?" UIs.
func (s *Service) PermissionsForUser(ctx context.Context, tenantID, userID int64) (map[string]struct{}, error) {
	binds, err := s.bindings.EffectiveBindingsForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, b := range binds {
		for p := range b.Permissions {
			out[p] = struct{}{}
		}
	}
	return out, nil
}

// EffectiveBindings exposes the raw binding set — needed by features like
// "list orgs scoped to me". The result is a snapshot copy so callers can
// mutate freely.
func (s *Service) EffectiveBindings(ctx context.Context, tenantID, userID int64) ([]EffectiveBinding, error) {
	return s.bindings.EffectiveBindingsForUser(ctx, tenantID, userID)
}
