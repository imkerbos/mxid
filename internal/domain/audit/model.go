package audit

import (
	"encoding/json"
	"time"
)

// Actor type constants.
const (
	ActorUser   = "user"
	ActorAdmin  = "admin"
	ActorSystem = "system"
	ActorAPI    = "api"
)

// Event status constants.
const (
	EventStatusFail    = 0
	EventStatusSuccess = 1
)

// AuditLog represents the mxid_audit_log table.
type AuditLog struct {
	ID           int64           `gorm:"column:id;primaryKey" json:"id"`
	TenantID     int64           `gorm:"column:tenant_id;not null" json:"tenant_id"`
	ActorID      *int64          `gorm:"column:actor_id" json:"actor_id"`
	ActorName    *string         `gorm:"column:actor_name;size:128" json:"actor_name"`
	ActorType    string          `gorm:"column:actor_type;not null;size:16" json:"actor_type"`
	EventType    string          `gorm:"column:event_type;not null;size:64" json:"event_type"`
	EventStatus  int             `gorm:"column:event_status;not null" json:"event_status"`
	ResourceType *string         `gorm:"column:resource_type;size:32" json:"resource_type"`
	ResourceID   *int64          `gorm:"column:resource_id" json:"resource_id"`
	ResourceName *string         `gorm:"column:resource_name;size:256" json:"resource_name"`
	Detail       json.RawMessage `gorm:"column:detail;type:jsonb;default:'{}'" json:"detail"`
	IP           *string         `gorm:"column:ip;size:64" json:"ip"`
	UserAgent    *string         `gorm:"column:user_agent;size:512" json:"user_agent"`
	GeoCity      *string         `gorm:"column:geo_city;size:64" json:"geo_city"`
	GeoCountry   *string         `gorm:"column:geo_country;size:64" json:"geo_country"`
	SessionID    *string         `gorm:"column:session_id;size:128" json:"session_id"`
	CreatedAt    time.Time       `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for AuditLog.
func (AuditLog) TableName() string {
	return "mxid_audit_log"
}

// TenantScoped marks mxid_audit_log for automatic tenant isolation. Reads are
// tenant-pinned; the retention purge escapes via tenantscope.SystemContext.
func (AuditLog) TenantScoped() {}
