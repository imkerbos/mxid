// Package externalidp encapsulates third-party identity provider integrations
// (social login + enterprise IdP). Each provider implements the Provider
// interface and is registered into the central Registry; the gateway layer
// dispatches /api/v1/{portal,console}-public/auth/external/:code/start + /callback to the right
// provider based on the mxid_external_idp.code field.
package externalidp

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Provider type identifiers. Each constant here MUST have a matching factory
// registered in registry.go — adding a new provider means adding the type
// constant + factory + (usually) a new file in providers/.
const (
	TypeLark    = "lark"     // Feishu (国际版) — same OAuth2 endpoints; we expose both
	TypeFeishu  = "feishu"   // alias of Lark for CN deployments
	TypeTeams   = "teams"    // Microsoft Teams via Azure AD / Microsoft Identity Platform
	// Placeholders kept for future expansion — NOT registered with the
	// runtime registry. Adding one is a 2-step process: implement a
	// providers/<name>.go file and let its init() Register itself.
	TypeDingTalk = "dingtalk"
	TypeWeCom   = "wecom"    // 企业微信
	TypeGitHub  = "github"
	TypeGoogle  = "google"
	TypeWeChat  = "wechat"
	TypeOIDC    = "oidc"     // generic OIDC IdP (any provider with discovery)
)

// Status constants.
const (
	StatusEnabled  = 1
	StatusDisabled = 2
)

// ExternalIDP represents the mxid_external_idp row.
//
// Config is intentionally schema-less JSONB; every provider documents its
// expected fields in its providers/*.go file (e.g. providers/lark.go for
// client_id/secret/scopes).
type ExternalIDP struct {
	ID            int64          `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID      int64          `gorm:"column:tenant_id;not null" json:"tenant_id,string"`
	Type          string         `gorm:"column:type;size:32;not null" json:"type"`
	Name          string         `gorm:"column:name;size:128;not null" json:"name"`
	Code          string         `gorm:"column:code;size:64;not null" json:"code"`
	Icon          *string        `gorm:"column:icon;size:512" json:"icon"`
	Description   *string        `gorm:"column:description" json:"description"`
	Config        datatypes.JSON `gorm:"column:config;type:jsonb;not null" json:"config"`
	Status        int            `gorm:"column:status;not null;default:1" json:"status"`
	AutoCreate    bool           `gorm:"column:auto_create;not null;default:true" json:"auto_create"`
	DefaultOrgID  *int64         `gorm:"column:default_org_id" json:"default_org_id,string,omitempty"`
	SortOrder     int            `gorm:"column:sort_order;not null;default:0" json:"sort_order"`
	CreatedAt     time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the postgres table.
func (ExternalIDP) TableName() string { return "mxid_external_idp" }
