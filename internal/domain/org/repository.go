package org

import "context"

// Repository defines the data access interface for organizations.
type Repository interface {
	Create(ctx context.Context, org *Organization) error
	GetByID(ctx context.Context, id int64) (*Organization, error)
	GetByCode(ctx context.Context, tenantID int64, code string) (*Organization, error)
	Update(ctx context.Context, org *Organization) error
	Delete(ctx context.Context, id int64) error
	GetTree(ctx context.Context, tenantID int64) ([]*Organization, error)
	GetChildren(ctx context.Context, parentID int64) ([]*Organization, error)
	GetByPath(ctx context.Context, tenantID int64, path string) ([]*Organization, error)
	Move(ctx context.Context, id int64, newParentID *int64, newPath string) error

	// Members
	AddMember(ctx context.Context, rel *UserOrg) error
	RemoveMember(ctx context.Context, userID, orgID int64) error
	GetMembers(ctx context.Context, orgID int64, page, pageSize int) ([]int64, int64, error)
	GetUserOrgs(ctx context.Context, userID int64) ([]*UserOrg, error)
	// AncestorIDsForUser returns every org_id the user belongs to, expanded
	// along the ltree path so each membership pulls in its ancestors. Used by
	// the permission resolver to climb org-inherited role bindings.
	AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error)
	// IsAncestorOrSelf reports whether `ancestor` is on the path of `descendant`
	// (inclusive). Used by authz scope checks: a binding scoped to org A
	// covers any operation on org B iff A is an ancestor or equals B.
	IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error)
}
