package org

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// RootOrgID is the ID of the seeded root organization (see migration 000013).
// The root acts as the implicit parent for all org-tree work; deleting it
// would orphan every downstream subtree, so Delete refuses to remove it.
const RootOrgID int64 = 1

// ErrRootOrgDelete is returned when a caller tries to delete the seeded root.
var ErrRootOrgDelete = errors.New("root organization cannot be deleted")

// ErrOrgNotFound is returned when an organization is absent — or, because the
// org repo is tenant-scoped by the tenantscope plugin, when the requested org
// belongs to another tenant (the plugin appends tenant_id=?, so a cross-tenant
// id resolves to gorm.ErrRecordNotFound).
var ErrOrgNotFound = errors.New("organization not found")

// Service handles organization business logic.
type Service struct {
	repo     Repository
	idGen    *snowflake.Generator
	eventBus *event.Bus
}

// NewService creates a new organization service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
	}
}

// Create creates a new organization with a generated ID and computed path.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateOrgRequest) (*Organization, error) {
	// Build path based on parent
	path := req.Code
	if req.ParentID != nil {
		parent, err := s.repo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return nil, fmt.Errorf("get parent organization: %w", err)
		}
		path = parent.Path + "." + req.Code
	}

	org := &Organization{
		ID:        s.idGen.Generate(),
		TenantID:  tenantID,
		Name:      req.Name,
		Code:      req.Code,
		ParentID:  req.ParentID,
		Path:      path,
		SortOrder: req.SortOrder,
		Status:    1,
		Extra:     make(JSONMap),
	}

	if err := s.repo.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("create organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgCreated,
		Payload: org,
	})

	return org, nil
}

// GetByID retrieves an organization by ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*Organization, error) {
	org, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return org, nil
}

// requireOrg fetches the parent org via the tenant-scoped repo. A cross-tenant
// orgID resolves to ErrRecordNotFound, surfaced as ErrOrgNotFound. This is the
// parent-ownership guard the tenant-less child table mxid_user_org (org_id)
// relies on, since the column plugin cannot filter it.
func (s *Service) requireOrg(ctx context.Context, orgID int64) error {
	if _, err := s.repo.GetByID(ctx, orgID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOrgNotFound
		}
		return fmt.Errorf("get organization: %w", err)
	}
	return nil
}

// Update updates an existing organization.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateOrgRequest) (*Organization, error) {
	org, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get organization for update: %w", err)
	}

	org.Name = req.Name
	org.SortOrder = req.SortOrder
	org.Status = req.Status

	if err := s.repo.Update(ctx, org); err != nil {
		return nil, fmt.Errorf("update organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgUpdated,
		Payload: org,
	})

	return org, nil
}

// Delete soft-deletes an organization. Refuses to remove the seeded root.
func (s *Service) Delete(ctx context.Context, id int64) error {
	if id == RootOrgID {
		return ErrRootOrgDelete
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgDeleted,
		Payload: map[string]int64{"id": id},
	})

	return nil
}

// GetTree retrieves the full organization tree for a tenant.
func (s *Service) GetTree(ctx context.Context, tenantID int64) ([]*OrgResponse, error) {
	orgs, err := s.repo.GetTree(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get organization tree: %w", err)
	}

	return buildTree(orgs), nil
}

// Move moves an organization to a new parent, recalculating paths.
func (s *Service) Move(ctx context.Context, id int64, req *MoveOrgRequest) error {
	org, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get organization for move: %w", err)
	}

	// Build new path
	newPath := org.Code
	if req.ParentID != nil {
		parent, err := s.repo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return fmt.Errorf("get new parent organization: %w", err)
		}
		newPath = parent.Path + "." + org.Code
	}

	if err := s.repo.Move(ctx, id, req.ParentID, newPath); err != nil {
		return fmt.Errorf("move organization: %w", err)
	}

	return nil
}

// AddMember adds a user to an organization.
func (s *Service) AddMember(ctx context.Context, orgID int64, req *AddMemberRequest) error {
	// Tenant-ownership guard on the parent org before planting a membership.
	if err := s.requireOrg(ctx, orgID); err != nil {
		return err
	}
	rel := &UserOrg{
		ID:        s.idGen.Generate(),
		UserID:    req.UserID,
		OrgID:     orgID,
		IsPrimary: req.IsPrimary,
	}

	if err := s.repo.AddMember(ctx, rel); err != nil {
		return fmt.Errorf("add member: %w", err)
	}

	return nil
}

// RemoveMember removes a user from an organization.
func (s *Service) RemoveMember(ctx context.Context, userID, orgID int64) error {
	// Tenant-ownership guard on the parent org before the delete.
	if err := s.requireOrg(ctx, orgID); err != nil {
		return err
	}
	if err := s.repo.RemoveMember(ctx, userID, orgID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// IsAncestorOrSelf delegates to the repo's ltree-based check. Used by the
// authz scope engine to decide whether a binding's org scope covers a
// target org.
func (s *Service) IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error) {
	return s.repo.IsAncestorOrSelf(ctx, ancestor, descendant)
}

// AncestorIDsForUser returns every org_id the user belongs to plus every
// ancestor in the ltree path. The permission resolver uses this to climb
// org-inherited role bindings (a binding on "root.eng" applies to every
// descendant org member).
func (s *Service) AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error) {
	ids, err := s.repo.AncestorIDsForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, nil
}

// GetMembers returns paginated user IDs for an organization.
//
// Empty result returns an empty (non-nil) slice so JSON encoders emit `[]`,
// not `null`.
func (s *Service) GetMembers(ctx context.Context, orgID int64, page, pageSize int) ([]int64, int64, error) {
	if err := s.requireOrg(ctx, orgID); err != nil {
		return nil, 0, err
	}
	ids, total, err := s.repo.GetMembers(ctx, orgID, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, total, nil
}

// buildTree converts a flat list of organizations (ordered by path) into a tree.
// Returns an empty (non-nil) slice when there are no organizations so the JSON
// response is `[]` instead of `null` — frontends iterate the result directly
// without nil-guarding.
func buildTree(orgs []*Organization) []*OrgResponse {
	responseMap := make(map[int64]*OrgResponse, len(orgs))
	roots := make([]*OrgResponse, 0, len(orgs))

	// First pass: convert all to responses
	for _, org := range orgs {
		resp := ToOrgResponse(org)
		resp.Children = make([]*OrgResponse, 0)
		responseMap[org.ID] = resp
	}

	// Second pass: build tree
	for _, org := range orgs {
		resp := responseMap[org.ID]
		if org.ParentID == nil {
			roots = append(roots, resp)
		} else {
			parent, ok := responseMap[*org.ParentID]
			if ok {
				parent.Children = append(parent.Children, resp)
			} else {
				// Parent not found (possibly deleted), treat as root
				roots = append(roots, resp)
			}
		}
	}

	return roots
}
