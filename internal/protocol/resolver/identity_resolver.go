package resolver

import (
	"context"
	"fmt"
)

// userGetByID fetches user info by ID.
type userGetByID func(ctx context.Context, userID int64) (*IdentityInfo, error)

// userGetIdentityBindings fetches the user's external identity bindings as
// provider type → {field: value}.
type userGetIdentityBindings func(ctx context.Context, userID int64) (map[string]map[string]string, error)

// identityResolverImpl implements IdentityResolver using injected functions.
type identityResolverImpl struct {
	getByID     userGetByID
	getBindings userGetIdentityBindings
}

// NewIdentityResolver creates an IdentityResolver from adapter functions.
// getBindings may be nil: the resolver then reports no external bindings, so a
// deployment that never wires it degrades to "no such claim" rather than to an
// error on every token.
func NewIdentityResolver(getByID userGetByID, getBindings userGetIdentityBindings) IdentityResolver {
	return &identityResolverImpl{getByID: getByID, getBindings: getBindings}
}

// ResolveIdentityBindings implements IdentityBindingResolver.
func (r *identityResolverImpl) ResolveIdentityBindings(ctx context.Context, userID int64) (map[string]map[string]string, error) {
	if r.getBindings == nil {
		return nil, nil
	}
	out, err := r.getBindings(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve identity bindings: %w", err)
	}
	return out, nil
}

func (r *identityResolverImpl) ResolveUser(ctx context.Context, userID int64) (*IdentityInfo, error) {
	info, err := r.getByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve user: %w", err)
	}
	return info, nil
}

// ResolveClaims builds a claims map based on requested OIDC scopes.
func (r *identityResolverImpl) ResolveClaims(ctx context.Context, userID int64, scopes []string) (map[string]any, error) {
	info, err := r.getByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve claims: %w", err)
	}

	claims := map[string]any{
		"sub": fmt.Sprintf("%d", info.ID),
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			if info.DisplayName != "" {
				claims["name"] = info.DisplayName
			}
			claims["preferred_username"] = info.Username
			if info.Avatar != "" {
				claims["picture"] = info.Avatar
			}
			if info.Locale != "" {
				claims["locale"] = info.Locale
			} else {
				claims["locale"] = "zh-CN"
			}
			if info.UpdatedAt > 0 {
				claims["updated_at"] = info.UpdatedAt
			}
		case "email":
			if info.Email != "" {
				claims["email"] = info.Email
				claims["email_verified"] = info.EmailVerified
			}
		case "phone":
			if info.Phone != "" {
				claims["phone_number"] = info.Phone
				claims["phone_number_verified"] = true
			}
		case "groups":
			if info.Groups == nil {
				claims["groups"] = []string{}
			} else {
				claims["groups"] = info.Groups
			}
		}
	}

	return claims, nil
}
