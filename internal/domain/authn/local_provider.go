package authn

import (
	"context"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
)

const LocalProviderType = "local"

// User status constants, mirrored to avoid importing the user package.
const (
	statusActive   = 1
	statusLocked   = 2
	statusDisabled = 3
)

// LocalProvider authenticates users via username and password stored locally.
type LocalProvider struct {
	userRepo       UserAuthQuerier
	passwordExpiry int // days; 0 means no expiry
}

// NewLocalProvider creates a local authentication provider.
func NewLocalProvider(userRepo UserAuthQuerier, passwordExpiryDays int) *LocalProvider {
	return &LocalProvider{
		userRepo:       userRepo,
		passwordExpiry: passwordExpiryDays,
	}
}

// Type returns the provider identifier.
func (p *LocalProvider) Type() string {
	return LocalProviderType
}

// Authenticate verifies a username/password credential pair.
func (p *LocalProvider) Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	username := req.Credentials["username"]
	password := req.Credentials["password"]
	if username == "" || password == "" {
		return &AuthResult{Status: AuthFailed}, nil
	}

	u, err := p.userRepo.GetByUsername(ctx, req.TenantID, username)
	if err != nil {
		return &AuthResult{Status: AuthFailed}, nil
	}

	// Check account status
	switch u.Status {
	case statusLocked:
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthLocked,
		}, nil
	case statusDisabled:
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthFailed,
		}, nil
	case statusActive:
		// proceed
	default:
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthFailed,
		}, nil
	}

	// Verify password
	if !crypto.CheckPassword(password, u.PasswordHash) {
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthFailed,
		}, nil
	}

	// Check password expiry
	if p.passwordExpiry > 0 && u.PasswordChangedAt != nil {
		expiry := u.PasswordChangedAt.Add(time.Duration(p.passwordExpiry) * 24 * time.Hour)
		if time.Now().After(expiry) {
			return &AuthResult{
				UserID:      u.ID,
				Username:    u.Username,
				DisplayName: u.DisplayName,
				Status:      AuthPasswordExpired,
			}, nil
		}
	}

	return &AuthResult{
		UserID:      u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Status:      AuthSuccess,
	}, nil
}

// Ensure LocalProvider implements Provider at compile time.
var _ Provider = (*LocalProvider)(nil)

// authQuerierAdapter adapts a function into a UserAuthQuerier.
type authQuerierAdapter struct {
	fn func(ctx context.Context, tenantID int64, username string) (*UserAuth, error)
}

func (a *authQuerierAdapter) GetByUsername(ctx context.Context, tenantID int64, username string) (*UserAuth, error) {
	return a.fn(ctx, tenantID, username)
}

var _ UserAuthQuerier = (*authQuerierAdapter)(nil)

// userQuerierAdapter wraps functions into a UserQuerier.
type userQuerierAdapter struct {
	getByIDFn         func(ctx context.Context, id int64) (*UserInfo, error)
	updateLastLoginFn func(ctx context.Context, id int64, ip string) error
	updateStatusFn    func(ctx context.Context, id int64, status int) error
}

func (a *userQuerierAdapter) GetByID(ctx context.Context, id int64) (*UserInfo, error) {
	return a.getByIDFn(ctx, id)
}

func (a *userQuerierAdapter) UpdateLastLogin(ctx context.Context, id int64, ip string) error {
	return a.updateLastLoginFn(ctx, id, ip)
}

func (a *userQuerierAdapter) UpdateStatus(ctx context.Context, id int64, status int) error {
	return a.updateStatusFn(ctx, id, status)
}

var _ UserQuerier = (*userQuerierAdapter)(nil)

// BuildAuthQuerier creates a UserAuthQuerier from a function.
func BuildAuthQuerier(fn func(ctx context.Context, tenantID int64, username string) (*UserAuth, error)) UserAuthQuerier {
	return &authQuerierAdapter{fn: fn}
}

// BuildUserQuerier creates a UserQuerier from functions.
func BuildUserQuerier(
	getByID func(ctx context.Context, id int64) (*UserInfo, error),
	updateLastLogin func(ctx context.Context, id int64, ip string) error,
	updateStatus func(ctx context.Context, id int64, status int) error,
) UserQuerier {
	return &userQuerierAdapter{
		getByIDFn:         getByID,
		updateLastLoginFn: updateLastLogin,
		updateStatusFn:    updateStatus,
	}
}
