// Package appaccess implements authorization policy for "who can use
// which app". This sits BETWEEN authentication (login succeeded) and
// protocol issuance (OIDC code / SAML assertion / CAS ticket) — every
// /authorize/sso/login path queries Service.CanAccess before proceeding.
//
// Policy rules:
//   - No allow entry  →  deny (default-secure)
//   - Any deny entry that matches subject  →  deny (deny wins)
//   - Else allow entry that matches subject  →  allow
//   - 'public' allow entry matches every authenticated user
//
// Subject expansion: when the policy stores subject_type='group' with
// subject_id=42, a user is considered to match if they're a member of
// group 42. Same for org (subtree match) and role (binding match).
package appaccess

import "time"

// Subject types — keep in sync with migration 000023 enum-by-convention.
const (
	SubjectPublic = "public"
	SubjectUser   = "user"
	SubjectGroup  = "group"
	SubjectOrg    = "org"
	SubjectRole   = "role"
)

// Effects.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Policy is a single access rule row. Exactly one of AppID / AppGroupID
// is set per row — the CHECK constraint in migration 000024 enforces this.
//
// AppID is set     →  rule applies only to this specific app
// AppGroupID is set →  rule applies to every app currently in this group;
//                       new apps added later inherit automatically
type Policy struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id,string"`
	AppID       *int64    `gorm:"column:app_id" json:"app_id,omitempty,string"`
	AppGroupID  *int64    `gorm:"column:app_group_id" json:"app_group_id,omitempty,string"`
	TenantID    int64     `gorm:"column:tenant_id;not null;default:0" json:"tenant_id,string"`
	SubjectType string    `gorm:"column:subject_type;size:16;not null" json:"subject_type"`
	SubjectID   int64     `gorm:"column:subject_id;not null;default:0" json:"subject_id,string"`
	Effect      string    `gorm:"column:effect;size:8;not null;default:allow" json:"effect"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	CreatedBy   *int64    `gorm:"column:created_by" json:"created_by,string,omitempty"`
}

func (Policy) TableName() string { return "mxid_app_access_policy" }

// TenantScoped marks mxid_app_access_policy for automatic tenant isolation.
func (Policy) TenantScoped() {}

// PolicyView is a Policy enriched with the resolved subject's display
// name — handed to the console UI so it can render rows without N+1
// round-trips for each subject lookup.
type PolicyView struct {
	*Policy
	SubjectName string `json:"subject_name,omitempty"`
	SubjectCode string `json:"subject_code,omitempty"`
}

// AccessDecision is the result of a check. Reason is for audit logging
// + portal error pages (so the user knows why they were denied).
type AccessDecision struct {
	Allowed     bool
	MatchedRule *Policy // nil when default-denied
	Reason      string  // "public" | "group:devops" | "deny:user:42" | "no-rule-matched"
}
