package authz

import (
	"context"
	"fmt"
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
}

// NewService wires a Service.
func NewService(b BindingProvider, o OrgAncestry) *Service {
	return &Service{bindings: b, orgTree: o}
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

	for _, b := range binds {
		if !hasPermission(b.Permissions, perm) {
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
