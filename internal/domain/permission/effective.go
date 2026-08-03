package permission

import (
	"context"
	"fmt"
)

// GroupLookup is the minimal interface the effective-role resolver needs
// from the group domain — given a user, return the IDs of the groups they
// belong to. Defined here so this package does NOT import group/, which
// would create a cycle with the group module's GET /users/:id/groups
// cross-domain route.
type GroupLookup interface {
	GroupIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error)
}

// OrgLookup is the minimal interface the effective-role resolver needs from
// the org domain. AncestorIDsForUser must return every org_id the user is
// directly in PLUS every ancestor along the ltree path so a binding on
// "root.eng" applies to descendants of "root.eng.platform" too.
type OrgLookup interface {
	AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error)
}

// EffectiveRoleSource explains why a user has a given role binding.
type EffectiveRoleSource string

const (
	SourceDirect EffectiveRoleSource = "direct" // explicit user→role binding
	SourceGroup  EffectiveRoleSource = "group"  // inherited via group→role
	SourceOrg    EffectiveRoleSource = "org"    // inherited via org→role (incl. ancestors)
)

// EffectiveRoleResponse is the API view of one role assigned to a user,
// annotated with how the user obtained it. A user can hold the same role
// via multiple sources (direct + several groups); each appears as its own
// entry so the console can show the full provenance.
type EffectiveRoleResponse struct {
	Role       *RoleResponse       `json:"role"`
	Source     EffectiveRoleSource `json:"source"`
	SourceID   int64               `json:"source_id,string"`
	SourceName string              `json:"source_name,omitempty"`
}

// EffectiveRolesForUser resolves every role a user holds across all three
// binding paths:
//
//  1. direct (user → role)
//  2. group (member of group → role on group)
//  3. org (member of org or any of its ancestors → role on that org)
//
// Duplicates are preserved on purpose — the same role coming in from two
// paths shows up twice with different `source` so the UI can render the
// full provenance chain. Callers who need a deduplicated set should fold
// over Role.ID themselves.
//
// Lookup failures on the group/org side return the partial set rather than
// blanking direct bindings — a registry blip should not look like "user
// suddenly has no permissions".
func (s *Service) EffectiveRolesForUser(
	ctx context.Context,
	tenantID, userID int64,
	groups GroupLookup,
	orgs OrgLookup,
) ([]*EffectiveRoleResponse, error) {
	// Collected first, resolved second. The previous shape issued one binding
	// query per group and per org ancestor, then one role query per binding —
	// for a user in eight groups under a five-level org that is roughly 55 round
	// trips, every one of them landing on mxid_role_binding. The batch methods
	// this now uses were already in the repository and simply unused here.
	type pending struct {
		roleID   int64
		source   EffectiveRoleSource
		sourceID int64
	}
	var want []pending

	direct, err := s.repo.GetBySubject(ctx, "user", userID)
	if err != nil {
		return nil, fmt.Errorf("get direct bindings: %w", err)
	}
	for _, b := range direct {
		want = append(want, pending{b.RoleID, SourceDirect, userID})
	}

	// Group and org lookups stay best-effort, as before: a failure to resolve
	// membership degrades the answer rather than failing the request.
	if groups != nil {
		if groupIDs, gerr := groups.GroupIDsForUser(ctx, tenantID, userID); gerr == nil && len(groupIDs) > 0 {
			bindings, berr := s.repo.GetBySubjects(ctx, "group", groupIDs)
			if berr != nil {
				return nil, fmt.Errorf("get group bindings: %w", berr)
			}
			for _, b := range bindings {
				want = append(want, pending{b.RoleID, SourceGroup, b.SubjectID})
			}
		}
	}

	if orgs != nil {
		if orgIDs, oerr := orgs.AncestorIDsForUser(ctx, tenantID, userID); oerr == nil && len(orgIDs) > 0 {
			bindings, berr := s.repo.GetBySubjects(ctx, "org", orgIDs)
			if berr != nil {
				return nil, fmt.Errorf("get org bindings: %w", berr)
			}
			for _, b := range bindings {
				want = append(want, pending{b.RoleID, SourceOrg, b.SubjectID})
			}
		}
	}

	out := make([]*EffectiveRoleResponse, 0, len(want))
	if len(want) == 0 {
		return out, nil
	}

	roleIDs := make([]int64, 0, len(want))
	for _, p := range want {
		roleIDs = append(roleIDs, p.roleID)
	}
	roles, err := s.repo.GetRolesByIDs(ctx, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("get roles: %w", err)
	}
	for _, p := range want {
		r, ok := roles[p.roleID]
		if !ok {
			// A binding pointing at a deleted role: skipped, as before.
			continue
		}
		out = append(out, &EffectiveRoleResponse{
			Role:     ToRoleResponse(r, nil, 0),
			Source:   p.source,
			SourceID: p.sourceID,
		})
	}
	return out, nil
}
