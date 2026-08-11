package app

// User-domain adapters used by authn / external IdP wiring and the
// dbTenantResolver helper used by all protocol modules.

import (
	"context"
	"errors"
	"fmt"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/ee/registry"
	"go.uber.org/zap"
)

type userExternalResolver struct{ userModule *user.Module }

func newUserExternalResolver(userModule *user.Module) *userExternalResolver {
	return &userExternalResolver{userModule: userModule}
}

func (a *userExternalResolver) Resolve(ctx context.Context, in *registry.ResolverInput) (int64, string, error) {
	u, err := a.userModule.Service.ResolveExternalLogin(ctx, &user.ExternalLoginInput{
		TenantID: in.TenantID, ProviderType: in.ProviderType, ProviderID: in.ProviderID,
		ExternalID: in.ExternalID, Username: in.Username, DisplayName: in.DisplayName,
		Email: in.Email, Phone: in.Phone, Avatar: in.Avatar, Raw: in.Raw,
		AutoCreate: in.AutoCreate, DefaultOrgID: in.DefaultOrgID,
	})
	if err != nil {
		return 0, "", translateSeamErr(err)
	}
	return u.ID, u.Username, nil
}

// bindIdentityAdapter maps the neutral EE seam type onto the CE user service.
func bindIdentityAdapter(svc *user.Service) registry.BindIdentityFunc {
	return func(ctx context.Context, in *registry.BindIdentityInput) error {
		err := svc.BindExternalIdentity(ctx, &user.BindIdentityInput{
			TenantID:     in.TenantID,
			UserID:       in.UserID,
			ProviderType: in.ProviderType,
			ProviderID:   in.ProviderID,
			ExternalID:   in.ExternalID,
			DisplayName:  in.DisplayName,
			Raw:          in.Raw,
		})
		return translateSeamErr(err)
	}
}

// translateSeamErr maps a CE user-domain error onto the registry's stable,
// EE-importable sentinel (see registry.ErrExternalIDTaken's doc comment for
// why this exists) so an EE caller can react to a known identity-rebind
// conflict via errors.Is without ever seeing — or forwarding — the
// underlying message. Anything else passes through unchanged: the EE side
// treats an unrecognized error as opaque and must not put ITS text anywhere
// user-visible either, but that is enforced on the EE side of the seam, not
// here.
func translateSeamErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, user.ErrExternalIDTaken):
		return registry.ErrExternalIDTaken
	case errors.Is(err, user.ErrIdentityAlreadyBound):
		return registry.ErrIdentityAlreadyBound
	case errors.Is(err, user.ErrExternalUserDeleted):
		return registry.ErrExternalUserDeleted
	default:
		return err
	}
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

// VerifyTOTP translates the one failure the caller must tell apart from a plain
// wrong code: a code that was correct but already consumed this window (the
// replay guard). "Your code is wrong" is actively misleading there — the user
// typed the right digits — and it is the common case whenever two prompts land
// inside the same 30s step, e.g. finishing enrollment and then being asked to
// step up. authn cannot import the user package, so the sentinel is remapped
// here, at the seam that already exists to keep them apart.
func (a *userMFAVerifierAdapter) VerifyTOTP(ctx context.Context, userID int64, code string) error {
	err := a.userModule.Service.VerifyTOTP(ctx, userID, code)
	if errors.Is(err, user.ErrMFACodeReused) {
		return fmt.Errorf("%w: %w", authn.ErrMFACodeReused, err)
	}
	return err
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
