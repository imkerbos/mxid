package permission

import "context"

// RoleListParams holds parameters for listing roles.
type RoleListParams struct {
	Page     int
	PageSize int
}

// MemberListParams holds parameters for listing role members.
type MemberListParams struct {
	Page     int
	PageSize int
}

// Repository defines the data access interface for the permission domain.
type Repository interface {
	// Role CRUD
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, id int64) (*Role, error)
	GetRoleByCode(ctx context.Context, tenantID int64, code string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id int64) error
	ListRoles(ctx context.Context, tenantID int64, params RoleListParams) ([]*Role, int64, error)

	// RoleBinding
	AddMember(ctx context.Context, binding *RoleBinding) error
	RemoveMember(ctx context.Context, id int64) error
	ListMembers(ctx context.Context, roleID int64, params MemberListParams) ([]*RoleBinding, int64, error)
	GetBySubject(ctx context.Context, subjectType string, subjectID int64) ([]*RoleBinding, error)
	// GetBySubjects fetches role bindings for multiple subject IDs of the same
	// type in a single query. Used by the authz engine to compute a user's
	// effective bindings across all of their groups/orgs at once.
	GetBySubjects(ctx context.Context, subjectType string, subjectIDs []int64) ([]*RoleBinding, error)
	CountMembers(ctx context.Context, roleID int64) (int64, error)
	// PermissionCodesByRoleIDs returns, for each role in the input list, the
	// set of permission codes assigned to it.
	PermissionCodesByRoleIDs(ctx context.Context, roleIDs []int64) (map[int64][]string, error)

	// Permission
	ListPermissions(ctx context.Context, tenantID int64) ([]*Permission, error)
	GetPermissionsByIDs(ctx context.Context, ids []int64) ([]*Permission, error)

	// RolePermission
	SetRolePermissions(ctx context.Context, roleID int64, permissions []RolePermission) error
	GetRolePermissions(ctx context.Context, roleID int64) ([]*RolePermission, error)
}
