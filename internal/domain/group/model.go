package group

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Group type constants. Static groups are member-managed; dynamic groups derive
// their members from an attached rule and are refreshed by the sync engine.
const (
	TypeStatic  = 1
	TypeDynamic = 2
)

// Rule status constants.
const (
	RuleEnabled = 1
	RulePaused  = 2
)

// UserGroup represents the mxid_user_group table.
//
// Some handlers serialize this model directly (ListByUserID). int64 ID
// fields use `,string` so Snowflake values survive JS Number precision.
type UserGroup struct {
	ID          int64          `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID    int64          `gorm:"column:tenant_id;not null" json:"tenant_id,string"`
	Name        string         `gorm:"column:name;size:128;not null" json:"name"`
	Code        string         `gorm:"column:code;size:64;not null" json:"code"`
	Description *string        `gorm:"column:description" json:"description"`
	Type        int            `gorm:"column:type;not null;default:1" json:"type"`
	CreatedAt   time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	CreatedBy   *int64         `gorm:"column:created_by" json:"created_by,string,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

func (UserGroup) TableName() string {
	return "mxid_user_group"
}

// UserGroupRule represents a dynamic group's membership rule. Exactly one
// rule per group (UNIQUE on group_id at the DB level).
//
// Expr is the JSON rule body — see rule.go for the DSL grammar.
type UserGroupRule struct {
	ID               int64          `gorm:"column:id;primaryKey" json:"id"`
	GroupID          int64          `gorm:"column:group_id;not null;uniqueIndex" json:"group_id"`
	Expr             datatypes.JSON `gorm:"column:expr;type:jsonb;not null" json:"expr"`
	Status           int            `gorm:"column:status;not null;default:1" json:"status"`
	LastSyncAt       *time.Time     `gorm:"column:last_sync_at" json:"last_sync_at"`
	LastSyncAdded    int            `gorm:"column:last_sync_added;not null;default:0" json:"last_sync_added"`
	LastSyncRemoved  int            `gorm:"column:last_sync_removed;not null;default:0" json:"last_sync_removed"`
	LastSyncError    *string        `gorm:"column:last_sync_error" json:"last_sync_error"`
	CreatedAt        time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (UserGroupRule) TableName() string {
	return "mxid_user_group_rule"
}

// UserGroupMember represents the mxid_user_group_member table.
type UserGroupMember struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	GroupID   int64     `gorm:"column:group_id;not null" json:"group_id"`
	UserID    int64     `gorm:"column:user_id;not null" json:"user_id"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (UserGroupMember) TableName() string {
	return "mxid_user_group_member"
}
