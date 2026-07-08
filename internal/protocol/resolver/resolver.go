package resolver

import (
	"context"
	"encoding/json"
	"time"
)

// AppConfig holds the protocol-relevant configuration for an application.
//
// ClientSecret holds the bcrypt hash (verify-only). HomeURL is the RP's own
// landing page used for portal-initiated launch (OIDC RP-initiated flow).
type AppConfig struct {
	ID              int64
	TenantID        int64 // 0 = shared app
	Scope           int   // 1=tenant 2=shared
	SubjectStrategy string
	Name            string
	Code            string
	Protocol        string
	ClientType      string // web_app | spa | native | m2m
	Status          int
	ClientID        string
	ClientSecret    string // bcrypt hash; verify via bcrypt.CompareHashAndPassword
	HomeURL         string
	FirstParty      bool
	RequireConsent  bool
	ProtocolConfig  json.RawMessage
	RedirectURIs    []string
	LoginURL        string
	LogoutURL       string
	AccessPolicy    int
}

// IsFirstParty reports whether the application is a first-party
// (organization-owned) RP. Used by the OIDC handler to decide whether to
// skip consent prompts for trusted internal apps (Auth0 / Okta convention).
func (a *AppConfig) IsFirstParty() bool { return a.FirstParty }

// CertConfig holds a signing certificate for an application.
//
// PrivateKey is already plaintext PEM at this layer — the adapter layer is
// responsible for decrypting the at-rest ciphertext (see app.KeyService).
type CertConfig struct {
	ID         int64
	AppID      int64
	CertType   string
	Algorithm  string
	PublicKey  string
	PrivateKey string // plaintext PEM
	KID        string
	NotBefore  *time.Time
	ExpiresAt  *time.Time
	Status     int
}

// IdentityInfo holds user identity information for protocol claims.
//
// Detail is a sparse map of nested attributes (employee_no, department,
// job_title, address, custom extras) sourced from mxid_user_detail. Empty
// when no detail row exists. The map keys mirror the column names so claim
// mappers can address them with `user.detail.<col>` paths.
type IdentityInfo struct {
	ID            int64
	TenantID      int64
	Username      string
	Email         string
	EmailVerified bool
	Phone         string
	DisplayName   string
	Avatar        string
	Locale        string
	UpdatedAt     int64 // unix seconds
	Groups        []string
	Status        int
	Detail        map[string]any
}

// ClaimMapping defines how user attributes map to protocol claims.
type ClaimMapping struct {
	Scope      string
	Attributes []string
}

// SSOSession represents a protocol-level SSO session. The field tags match
// pkg/session.Session so that records written by session.Manager (during
// login) are directly readable by the protocol resolver.
type SSOSession struct {
	ID        string    `json:"id"`
	UserID    int64     `json:"user_id"`
	TenantID  int64     `json:"tenant_id"`
	AuthType  string    `json:"auth_type"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TenantResolver looks up tenant metadata for use in subject strategies
// (e.g. username_suffixed needs tenant.code to build the suffix).
type TenantResolver interface {
	// GetTenantCode returns the tenant.code by ID. Empty when not found.
	// Implementations should cache aggressively — called on every token.
	GetTenantCode(ctx context.Context, id int64) (string, error)
}

// AppResolver loads application configuration for protocol handlers.
type AppResolver interface {
	GetApp(ctx context.Context, identifier string) (*AppConfig, error)
	GetAppByID(ctx context.Context, appID int64) (*AppConfig, error)
	GetAppByClientID(ctx context.Context, clientID string) (*AppConfig, error)
	GetCert(ctx context.Context, appID int64, certType string) (*CertConfig, error)
	ListCerts(ctx context.Context, appID int64) ([]*CertConfig, error)
	// ListAllActiveSigningCerts returns the active + rotating signing
	// certs across every enabled OIDC application. Used by the IdP-level
	// JWKS endpoint to advertise the full key set so RPs can verify
	// id_tokens from any app via a single fetch.
	ListAllActiveSigningCerts(ctx context.Context) ([]*CertConfig, error)
	// MintSigningCert generates a fresh signing keypair for an app and
	// persists it. Used by SAML metadata handlers as a lazy bootstrap for
	// apps created before auto-mint existed, and by /admin "rotate cert"
	// surfaces. Returns the new cert config.
	MintSigningCert(ctx context.Context, appID int64) (*CertConfig, error)
}

// IdentityResolver resolves user identity for protocol claims.
type IdentityResolver interface {
	ResolveUser(ctx context.Context, userID int64) (*IdentityInfo, error)
	ResolveClaims(ctx context.Context, userID int64, scopes []string) (map[string]any, error)
}

// SessionResolver manages protocol-level SSO sessions.
type SessionResolver interface {
	// GetSSOSession resolves a session id, checking the protocol namespace
	// first then falling back to the portal namespace (IdP-initiated logins
	// that only hold a portal session). Use this for "is the user logged in".
	GetSSOSession(ctx context.Context, sessionID string) (*SSOSession, error)
	// GetProtocolSSOSession resolves a session id ONLY within the protocol
	// namespace (no portal fallback). Use this when the caller must be certain
	// the id is a genuine protocol-namespace session — e.g. before emitting it
	// as the OIDC id_token `sid`, which back-channel logout keys on the
	// protocol namespace and must never be a portal session id.
	GetProtocolSSOSession(ctx context.Context, sessionID string) (*SSOSession, error)
	CreateSSOSession(ctx context.Context, userID, tenantID int64, authType, ip, userAgent string) (*SSOSession, error)
	DeleteSSOSession(ctx context.Context, sessionID string) error
}
