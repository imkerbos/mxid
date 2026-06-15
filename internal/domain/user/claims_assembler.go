package user

import (
	"context"
	"fmt"

	"github.com/imkerbos/mxid/internal/domain/group"
	"gorm.io/gorm"
)

// ClaimsAssembler projects a User record (and related associations) into the
// OIDC claims map filtered by the scopes requested at /authorize time.
//
// Scope → claim mapping follows OIDC Core 1.0 §5.4:
//
//	openid  → sub                                       (mandatory, always present)
//	profile → name, preferred_username, picture,
//	          locale, updated_at
//	email   → email, email_verified
//	phone   → phone_number, phone_number_verified
//	groups  → groups[]                                  (MXID extension; matches Keycloak / Auth0)
//
// Claims are emitted only when (a) the scope was requested AND (b) the user
// record actually carries a value. Missing values are omitted rather than
// emitted as `null` per OIDC best practice.
type ClaimsAssembler struct {
	db       *gorm.DB
	userRepo Repository
}

// NewClaimsAssembler wires the assembler.
func NewClaimsAssembler(db *gorm.DB, userRepo Repository) *ClaimsAssembler {
	return &ClaimsAssembler{db: db, userRepo: userRepo}
}

// Assemble returns a claim map suitable for inlining into an ID token or
// returning from /userinfo. The `sub` claim is always populated even when
// `openid` is omitted by a buggy caller (defensive — OIDC mandates it).
func (a *ClaimsAssembler) Assemble(ctx context.Context, userID int64, scopes []string) (map[string]any, error) {
	usr, err := a.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}
	has := func(s string) bool { _, ok := scopeSet[s]; return ok }

	claims := map[string]any{
		"sub": fmt.Sprintf("%d", usr.ID),
	}

	if has("profile") {
		if usr.DisplayName != nil && *usr.DisplayName != "" {
			claims["name"] = *usr.DisplayName
		}
		claims["preferred_username"] = usr.Username
		if usr.Avatar != nil && *usr.Avatar != "" {
			claims["picture"] = *usr.Avatar
		}
		// Locale not yet persisted on User; emit zh-CN default for A milestone.
		claims["locale"] = "zh-CN"
		claims["updated_at"] = usr.UpdatedAt.Unix()
	}

	if has("email") {
		if usr.Email != nil && *usr.Email != "" {
			claims["email"] = *usr.Email
			// A milestone trusts admin-provisioned emails; explicit verification
			// flow lands in B and will source this from a dedicated column.
			claims["email_verified"] = true
		}
	}

	if has("phone") {
		if usr.Phone != nil && *usr.Phone != "" {
			claims["phone_number"] = *usr.Phone
			claims["phone_number_verified"] = true
		}
	}

	if has("groups") {
		groups, err := a.listGroupNames(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("list groups: %w", err)
		}
		claims["groups"] = groups
	}

	return claims, nil
}

func (a *ClaimsAssembler) listGroupNames(ctx context.Context, userID int64) ([]string, error) {
	var names []string
	err := a.db.WithContext(ctx).
		Table("mxid_user_group_member m").
		Select("g.name").
		Joins("INNER JOIN mxid_user_group g ON g.id = m.group_id AND g.deleted_at IS NULL").
		Where("m.user_id = ?", userID).
		Pluck("g.name", &names).Error
	if err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// silence unused import linter when group package consumers move
var _ = group.UserGroup{}
