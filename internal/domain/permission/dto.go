package permission

import "time"

// CreateRoleRequest is the request body for creating a role.
type CreateRoleRequest struct {
	Name        string  `json:"name" binding:"required,min=1,max=128"`
	Code        string  `json:"code" binding:"required,min=1,max=64"`
	Type        int     `json:"type" binding:"required,oneof=1 2"`
	Description *string `json:"description" binding:"omitempty"`
}

// UpdateRoleRequest is the request body for updating a role.
type UpdateRoleRequest struct {
	Name        *string `json:"name" binding:"omitempty,min=1,max=128"`
	Description *string `json:"description" binding:"omitempty"`
}

// RoleResponse is the API response for a role.
type RoleResponse struct {
	ID          int64                `json:"id,string"`
	TenantID    int64                `json:"tenant_id,string"`
	Name        string               `json:"name"`
	Code        string               `json:"code"`
	Type        int                  `json:"type"`
	Description *string              `json:"description"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Permissions []PermissionResponse `json:"permissions,omitempty"`
	MemberCount int64                `json:"member_count"`
}

// PermissionResponse is the API response for a permission.
type PermissionResponse struct {
	ID          int64     `json:"id,string"`
	TenantID    int64     `json:"tenant_id,string"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AddMemberRequest is the request body for adding a member to a role.
//
// SubjectID uses ,string so the frontend can send snowflake int64 IDs as JSON
// strings (JS Number rounds 18-digit integers).
//
// ScopeType (optional): "org" | "group". When set, ScopeID must point to the
// matching resource. NULL/empty ScopeType = global binding.
type AddMemberRequest struct {
	SubjectType string  `json:"subject_type" binding:"required,oneof=user group org"`
	SubjectID   int64   `json:"subject_id,string" binding:"required"`
	ScopeType   *string `json:"scope_type,omitempty" binding:"omitempty,oneof=org group"`
	ScopeID     *int64  `json:"scope_id,string,omitempty"`
}

// MemberResponse is the API response for one role member (a role binding),
// enriched with the subject's display name so the console shows "who" instead
// of a raw snowflake id. Field names/types mirror RoleBinding's JSON so the
// existing frontend keeps working; SubjectName/SubjectSecondary are additive.
//
// SubjectName falls back to the string id when the resolver can't find the
// subject (deleted user, missing resolver) — the UI always has something to
// show. SubjectSecondary is an optional disambiguator (e.g. a user's email).
type MemberResponse struct {
	ID               int64     `json:"id,string"`
	RoleID           int64     `json:"role_id,string"`
	SubjectType      string    `json:"subject_type"`
	SubjectID        int64     `json:"subject_id,string"`
	SubjectName      string    `json:"subject_name"`
	SubjectSecondary string    `json:"subject_secondary,omitempty"`
	ScopeType        *string   `json:"scope_type,omitempty"`
	ScopeID          *int64    `json:"scope_id,string,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// UpdatePermissionsRequest is the request body for setting role permissions.
// PermissionIDs is []string for the same reason BatchMembersRequest is — the
// `,string` json tag does not propagate into slice elements. The handler
// parses these into int64 before invoking the service.
type UpdatePermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

// ToRoleResponse converts a Role model to a RoleResponse.
func ToRoleResponse(r *Role, perms []PermissionResponse, memberCount int64) *RoleResponse {
	return &RoleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Code:        r.Code,
		Type:        r.Type,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		Permissions: perms,
		MemberCount: memberCount,
	}
}

// ToPermissionResponse converts a Permission model to a PermissionResponse.
func ToPermissionResponse(p *Permission) PermissionResponse {
	return PermissionResponse{
		ID:          p.ID,
		TenantID:    p.TenantID,
		Name:        p.Name,
		Code:        p.Code,
		Resource:    p.Resource,
		Action:      p.Action,
		Description: p.Description,
		CreatedAt:   p.CreatedAt,
	}
}
