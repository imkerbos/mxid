// Package platformconfig stores deployment-wide singleton configuration that is
// NOT tenant data — currently the EE license token and the installation
// fingerprint UUID.
//
// Why separate from internal/domain/setting:
//
//	mxid_setting is tenant-scoped and fail-closed (the tenantscope gorm plugin
//	rejects any read without a tenant scope in context). The license + install
//	UUID are read at BOOT and BEFORE login — phases with no tenant scope — so
//	reading them from a tenant-scoped table fails closed and the caller silently
//	regenerates / downgrades. They are also platform singletons (one per
//	deployment, never per tenant). This table has no tenant_id and does NOT
//	implement the tenantscope marker, so boot reads need no scope and no tenant
//	can override platform config.
package platformconfig

import "time"

// Well-known keys (kept identical to the legacy mxid_setting keys so the 000040
// migration relocates rows verbatim).
const (
	KeyLicense     = "license"
	KeyInstallUUID = "system.install_uuid"
)

// PlatformConfig is one KV row from mxid_platform_config.
type PlatformConfig struct {
	Key       string    `gorm:"column:key;primaryKey;size:128"`
	Value     []byte    `gorm:"column:value;type:jsonb;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (PlatformConfig) TableName() string { return "mxid_platform_config" }
