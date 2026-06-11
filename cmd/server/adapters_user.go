package main

// User-domain adapters used by authn / external IdP wiring and the
// dbTenantResolver helper used by all protocol modules.

import (
	"context"
	"os"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/externalidp"
	"github.com/imkerbos/mxid/internal/domain/user"
	"go.uber.org/zap"
)

// envDefault returns the OS env value for `key` or `fallback` when unset/empty.
func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type userExternalResolver struct{ userModule *user.Module }

func newUserExternalResolver(userModule *user.Module) *userExternalResolver {
	return &userExternalResolver{userModule: userModule}
}

func (a *userExternalResolver) Resolve(ctx context.Context, in *externalidp.ResolverInput) (int64, string, error) {
	u, err := a.userModule.Service.ResolveExternalLogin(ctx, &user.ExternalLoginInput{
		TenantID: in.TenantID, ProviderType: in.ProviderType, ProviderID: in.ProviderID,
		ExternalID: in.ExternalID, Username: in.Username, DisplayName: in.DisplayName,
		Email: in.Email, Phone: in.Phone, Avatar: in.Avatar, Raw: in.Raw,
		AutoCreate: in.AutoCreate, DefaultOrgID: in.DefaultOrgID,
	})
	if err != nil {
		return 0, "", err
	}
	return u.ID, u.Username, nil
}

type dbTenantResolver struct{ app *bootstrap.App }

func newDBTenantResolver(a *bootstrap.App) *dbTenantResolver { return &dbTenantResolver{app: a} }

func (r *dbTenantResolver) GetTenantCode(ctx context.Context, id int64) (string, error) {
	var code string
	err := r.app.DB.WithContext(ctx).Table("mxid_tenant").Where("id = ? AND deleted_at IS NULL", id).Pluck("code", &code).Error
	return code, err
}

type userMFAVerifierAdapter struct{ userModule *user.Module }

func newUserMFAVerifierAdapter(userModule *user.Module) *userMFAVerifierAdapter {
	return &userMFAVerifierAdapter{userModule: userModule}
}

func (a *userMFAVerifierAdapter) HasVerifiedTOTP(ctx context.Context, userID int64) (bool, error) {
	return a.userModule.Service.HasVerifiedTOTP(ctx, userID)
}

func (a *userMFAVerifierAdapter) VerifyTOTP(ctx context.Context, userID int64, code string) error {
	return a.userModule.Service.VerifyTOTP(ctx, userID, code)
}

func (a *userMFAVerifierAdapter) ConsumeBackupCode(ctx context.Context, userID int64, code string) error {
	return a.userModule.Service.ConsumeBackupCode(ctx, userID, code)
}

type userLoginRecorderAdapter struct {
	userModule *user.Module
	logger     *zap.Logger
}

func newUserLoginRecorderAdapter(userModule *user.Module, logger *zap.Logger) *userLoginRecorderAdapter {
	return &userLoginRecorderAdapter{userModule: userModule, logger: logger}
}

func (a *userLoginRecorderAdapter) RecordAttempt(ctx context.Context, attempt authn.LoginAttempt) {
	rec := &user.LoginRecord{
		TenantID: attempt.TenantID, Success: attempt.Success,
		Stage: attempt.Stage, AuthType: attempt.AuthType,
	}
	if attempt.UserID != 0 {
		uid := attempt.UserID
		rec.UserID = &uid
	}
	if attempt.Username != "" {
		un := attempt.Username
		rec.Username = &un
	}
	if attempt.Reason != "" {
		r := attempt.Reason
		rec.Reason = &r
	}
	if attempt.IP != "" {
		ip := attempt.IP
		rec.IP = &ip
	}
	if attempt.UserAgent != "" {
		ua := attempt.UserAgent
		rec.UserAgent = &ua
	}
	if err := a.userModule.Service.RecordLogin(ctx, rec); err != nil {
		a.logger.Warn("record login attempt failed", zap.Error(err))
	}
}
