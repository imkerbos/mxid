// Package upload stores uploaded binary assets (app icons, brand logos) in the
// database instead of on local disk, so the backend carries NO local file
// state. Under k8s that removes any PVC / ReadWriteOnce volume — the thing that
// dead-locks a second replica (Multi-Attach) or hangs a cross-node rolling
// update; under docker an icon survives container restarts; and every replica
// serves the same bytes. Assets are small (<= 2 MB) and rarely change, so a
// bytea column (TOAST-backed) plus strong HTTP caching keeps DB load negligible.
//
// NOT tenant-scoped: icons are public assets fetched by the pre-auth login page
// (an <img> with no cookie), so the serve path has no tenant scope. The id is a
// non-enumerable Snowflake, so by-id fetch needs no tenant filter; tenant_id is
// kept only as metadata for cleanup / audit.
package upload

import "time"

// Upload is one stored binary asset row from mxid_upload.
type Upload struct {
	ID        int64     `gorm:"column:id;primaryKey"`
	TenantID  int64     `gorm:"column:tenant_id"`
	Category  string    `gorm:"column:category;size:32"`
	Mime      string    `gorm:"column:mime;size:64"`
	Ext       string    `gorm:"column:ext;size:8"`
	Size      int       `gorm:"column:size"`
	Data      []byte    `gorm:"column:data;type:bytea"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (Upload) TableName() string { return "mxid_upload" }
