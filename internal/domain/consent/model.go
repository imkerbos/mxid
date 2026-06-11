// Package consent persists the scope-grants a user has given to OIDC
// applications. The scope set on a row is cumulative — granting `email`
// after `openid profile` upgrades the existing record, not creates a new
// one. Revocation either deletes the row or stamps `revoked_at`, both of
// which cause the next /authorize call to re-prompt.
package consent

import (
	"time"

	"github.com/lib/pq"
)

// UserAppConsent represents one row in mxid_user_app_consent.
type UserAppConsent struct {
	ID         int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID   int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	UserID     int64          `gorm:"column:user_id;not null" json:"user_id"`
	AppID      int64          `gorm:"column:app_id;not null" json:"app_id"`
	Scopes     pq.StringArray `gorm:"column:scopes;type:text[]" json:"scopes"`
	GrantedAt  time.Time      `gorm:"column:granted_at;not null" json:"granted_at"`
	RevokedAt  *time.Time     `gorm:"column:revoked_at" json:"revoked_at"`
}

// TableName returns the table name for UserAppConsent.
func (UserAppConsent) TableName() string {
	return "mxid_user_app_consent"
}
