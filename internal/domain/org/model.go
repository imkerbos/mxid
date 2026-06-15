package org

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// JSONMap is a JSON column type for GORM.
type JSONMap map[string]any

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	data, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("marshal json map: %w", err)
	}
	return string(data), nil
}

func (j *JSONMap) Scan(src any) error {
	if src == nil {
		*j = make(JSONMap)
		return nil
	}
	var source []byte
	switch v := src.(type) {
	case string:
		source = []byte(v)
	case []byte:
		source = v
	default:
		return fmt.Errorf("unsupported type for JSONMap: %T", src)
	}
	return json.Unmarshal(source, j)
}

// Organization represents the mxid_organization table.
type Organization struct {
	ID        int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID  int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	Name      string         `gorm:"column:name;size:128;not null" json:"name"`
	Code      string         `gorm:"column:code;size:64;not null" json:"code"`
	ParentID  *int64         `gorm:"column:parent_id" json:"parent_id"`
	Path      string         `gorm:"column:path;not null" json:"path"`
	SortOrder int            `gorm:"column:sort_order;not null;default:0" json:"sort_order"`
	Status    int16          `gorm:"column:status;not null;default:1" json:"status"`
	Extra     JSONMap        `gorm:"column:extra;type:jsonb;default:'{}'" json:"extra"`
	CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	CreatedBy *int64         `gorm:"column:created_by" json:"created_by"`
	UpdatedBy *int64         `gorm:"column:updated_by" json:"updated_by"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

func (Organization) TableName() string {
	return "mxid_organization"
}

// TenantScoped marks mxid_organization for automatic tenant isolation.
func (Organization) TenantScoped() {}

// UserOrg represents the mxid_user_org table.
type UserOrg struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID    int64     `gorm:"column:user_id;not null" json:"user_id"`
	OrgID     int64     `gorm:"column:org_id;not null" json:"org_id"`
	IsPrimary bool      `gorm:"column:is_primary;not null;default:false" json:"is_primary"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (UserOrg) TableName() string {
	return "mxid_user_org"
}
