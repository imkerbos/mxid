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
	Role        *RoleResponse       `json:"role"`
	Source      EffectiveRoleSource `json:"source"`
	SourceID    int64               `json:"source_id,string"`
	SourceName  string              `json:"source_name,omitempty"`
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
	out := make([]*EffectiveRoleResponse, 0)

	// 1. Direct user→role bindings.
	directBindings, err := s.repo.GetBySubject(ctx, "user", userID)
	if err != nil {
		return nil, fmt.Errorf("get direct bindings: %w", err)
	}
	for _, b := range directBindings {
		r, err := s.repo.GetRoleByID(ctx, b.RoleID)
		if err != nil {
			continue
		}
		out = append(out, &EffectiveRoleResponse{
			Role:     ToRoleResponse(r, nil, 0),
			Source:   SourceDirect,
			SourceID: userID,
		})
	}

	// 2. Group-inherited bindings.
	if groups != nil {
		groupIDs, err := groups.GroupIDsForUser(ctx, tenantID, userID)
		if err == nil {
			for _, gid := range groupIDs {
				bindings, err := s.repo.GetBySubject(ctx, "group", gid)
				if err != nil {
					continue
				}
				for _, b := range bindings {
					r, err := s.repo.GetRoleByID(ctx, b.RoleID)
					if err != nil {
						continue
					}
					out = append(out, &EffectiveRoleResponse{
						Role:     ToRoleResponse(r, nil, 0),
						Source:   SourceGroup,
						SourceID: gid,
					})
				}
			}
		}
	}

	// 3. Org-inherited bindings (member orgs + every ancestor on the ltree path).
	if orgs != nil {
		orgIDs, err := orgs.AncestorIDsForUser(ctx, tenantID, userID)
		if err == nil {
			for _, oid := range orgIDs {
				bindings, err := s.repo.GetBySubject(ctx, "org", oid)
				if err != nil {
					continue
				}
				for _, b := range bindings {
					r, err := s.repo.GetRoleByID(ctx, b.RoleID)
					if err != nil {
						continue
					}
					out = append(out, &EffectiveRoleResponse{
						Role:     ToRoleResponse(r, nil, 0),
						Source:   SourceOrg,
						SourceID: oid,
					})
				}
			}
		}
	}

	return out, nil
}
