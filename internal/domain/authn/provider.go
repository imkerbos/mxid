package authn

import (
	"context"
	"time"
)

// AuthStatus represents the result status of an authentication attempt.
type AuthStatus int

const (
	AuthSuccess AuthStatus = iota
	AuthMFARequired
	AuthLocked
	AuthFailed
	// AuthDisabled marks a correct-credentials login against a disabled
	// account (e.g. an offboarded user). Distinguished from AuthFailed ONLY
	// after the password is verified, so an attacker guessing usernames can't
	// read account-state off the response — a wrong password is always
	// AuthFailed regardless of account status.
	AuthDisabled
)

// Provider defines a pluggable authentication strategy.
type Provider interface {
	Type() string
	Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error)
}

// accountResolver is the optional capability a Provider exposes when a login
// identifier can be mapped to an account BEFORE the credential is evaluated.
// The engine needs it for the per-account login throttle: the account a guess
// is aimed at has to be known while refusing the guess is still cheap. A
// provider that cannot resolve one (an external IdP) simply isn't throttled on
// the account dimension.
type accountResolver interface {
	ResolveAccount(ctx context.Context, tenantID int64, identifier string) (*UserAuth, error)
}

// AuthRequest carries the credentials and metadata for an authentication attempt.
type AuthRequest struct {
	TenantID    int64
	AuthType    string
	Credentials map[string]string
	ClientIP    string
	UserAgent   string
}

// AuthResult carries the outcome of an authentication attempt.
type AuthResult struct {
	UserID      int64
	Username    string
	DisplayName string
	Status      AuthStatus
	MFARequired bool
	MFATypes    []string
	Metadata    map[string]any
}

// UserQuerier is the minimal interface the Engine needs for user lookups and updates.
// The user.Repository satisfies this via an adapter (see register.go).
type UserQuerier interface {
	GetByID(ctx context.Context, id int64) (*UserInfo, error)
	UpdateLastLogin(ctx context.Context, id int64, ip string) error
	UpdateStatus(ctx context.Context, id int64, status int) error
}

// UserInfo is a lightweight representation of a user, used to avoid importing the user package.
type UserInfo struct {
	ID          int64
	Username    string
	DisplayName string
	Avatar      string
	Status      int
	// IsBuiltin mirrors mxid_user.is_builtin: the platform-seeded break-glass
	// admin. Server-side state only — never anything a request may claim.
	IsBuiltin bool
}

// UserAuthQuerier is the interface the local provider needs for credential verification.
type UserAuthQuerier interface {
	GetByUsername(ctx context.Context, tenantID int64, username string) (*UserAuth, error)
	// GetByEmail resolves a user by email so password login can accept an email
	// address as the identifier (Okta/Auth0-style). Implementations that don't
	// support email login may return an error — the provider then falls back to
	// a uniform auth failure.
	GetByEmail(ctx context.Context, tenantID int64, email string) (*UserAuth, error)
}

// UserAuth carries the fields needed for local password authentication.
type UserAuth struct {
	ID                int64
	Username          string
	DisplayName       string
	PasswordHash      string
	Status            int
	PasswordChangedAt *time.Time
}
