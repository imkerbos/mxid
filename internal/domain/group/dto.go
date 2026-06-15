package group

import "time"

// CreateGroupRequest is the request body for creating a user group.
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required,max=128"`
	Code        string `json:"code" binding:"required,max=64"`
	Description string `json:"description"`
}

// UpdateGroupRequest is the request body for updating a user group.
type UpdateGroupRequest struct {
	Name        string `json:"name" binding:"required,max=128"`
	Description string `json:"description"`
}

// AddMemberRequest is the request body for adding a member to a group.
//
// UserID uses ,string so the frontend can send snowflake int64 values as JSON
// strings (JS Number cannot represent 18-digit ints without rounding off the
// trailing few digits, which would create the wrong FK lookup).
type AddMemberRequest struct {
	UserID int64 `json:"user_id,string" binding:"required"`
}

// BatchMembersRequest carries a list of user IDs for batch add/remove member
// operations. Cap at 500 per call to keep the transaction bounded.
//
// UserIDs is []string for the same reason AddMemberRequest.UserID uses ,string:
// the encoding/json `,string` tag does NOT propagate into slice elements, so
// []int64 cannot decode `["123","456"]`. The handler parses each entry into
// int64 before passing to the service.
type BatchMembersRequest struct {
	UserIDs []string `json:"user_ids" binding:"required,min=1,max=500"`
}

// BatchMembersResponse reports what happened per user in a batch operation.
// Skipped lists rows that were no-ops (already a member on add, not a member on remove)
// so the UI can show a "X added, Y already in group" toast without a second roundtrip.
//
// Skipped is []string at the wire so snowflake IDs survive JS number
// precision loss (Number.MAX_SAFE_INTEGER < 2^63). Backend converts in
// the service layer before populating this struct.
type BatchMembersResponse struct {
	Affected int      `json:"affected"`
	Skipped  []string `json:"skipped"`
}

// MemberInfo enriches a group member with the user-facing fields the console
// needs (username, display_name, email). Selected via a raw join on mxid_user
// so this package stays decoupled from the user domain.
type MemberInfo struct {
	UserID      int64   `gorm:"column:user_id" json:"user_id,string"`
	Username    string  `gorm:"column:username" json:"username"`
	DisplayName *string `gorm:"column:display_name" json:"display_name,omitempty"`
	Email       *string `gorm:"column:email" json:"email,omitempty"`
	Avatar      *string `gorm:"column:avatar" json:"avatar,omitempty"`
	Status      int     `gorm:"column:status" json:"status"`
}

// GroupResponse is the API response for a single user group.
type GroupResponse struct {
	ID          int64     `json:"id,string"`
	TenantID    int64     `json:"tenant_id,string"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description *string   `json:"description,omitempty"`
	// Type: 1=static (members managed manually), 2=dynamic (rule-driven).
	Type        int       `json:"type"`
	MemberCount int64     `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RuleResponse is the API view of a dynamic group's rule including the last
// sync metadata. expr is returned as the original JSON DSL so the frontend
// rule editor can rehydrate the form.
type RuleResponse struct {
	GroupID         int64      `json:"group_id,string"`
	Expr            RuleExpr   `json:"expr"`
	Status          int        `json:"status"`
	LastSyncAt      *time.Time `json:"last_sync_at"`
	LastSyncAdded   int        `json:"last_sync_added"`
	LastSyncRemoved int        `json:"last_sync_removed"`
	LastSyncError   *string    `json:"last_sync_error,omitempty"`
}

// ToGroupResponse converts a UserGroup model to a GroupResponse.
func ToGroupResponse(g *UserGroup, memberCount int64) *GroupResponse {
	return &GroupResponse{
		ID:          g.ID,
		TenantID:    g.TenantID,
		Name:        g.Name,
		Code:        g.Code,
		Description: g.Description,
		Type:        g.Type,
		MemberCount: memberCount,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
}
