package oidcop

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// ClaimsStore fills OIDC claims from MXID identity. Standard scope-driven claims
// come from the shared IdentityResolver; per-app declarative mappers are layered
// on top (the commercial-IdP "claim mapper" feature).
type ClaimsStore struct {
	identity resolver.IdentityResolver
	apps     resolver.AppResolver
}

var _ ClaimsResolver = (*ClaimsStore)(nil)

// NewClaimsStore wires a ClaimsStore.
func NewClaimsStore(identity resolver.IdentityResolver, apps resolver.AppResolver) *ClaimsStore {
	return &ClaimsStore{identity: identity, apps: apps}
}

// SetUserinfo populates the userinfo response (also feeds the id_token when the
// client asserts userinfo claims). Standard claims + groups + per-app mappers.
func (s *ClaimsStore) SetUserinfo(ctx context.Context, info *oidc.UserInfo, userID, clientID string, scopes []string) error {
	uid, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid subject %q: %w", userID, err)
	}
	claims, err := s.identity.ResolveClaims(ctx, uid, scopes)
	if err != nil {
		return err
	}
	if sub, ok := claims["sub"].(string); ok {
		info.Subject = sub
	}
	for k, v := range claims {
		if k == "sub" {
			continue
		}
		info.AppendClaims(k, v)
	}
	// Per-app declarative mappers.
	identity, mappers := s.identityAndMappers(ctx, uid, clientID)
	for k, v := range applyClaimMappers(nil, mappers, identity, scopes) {
		info.AppendClaims(k, v)
	}
	return nil
}

// PrivateClaims returns the non-standard claims to embed in the id_token (and a
// JWT access token, if used): groups + per-app mapped claims. Standard profile/
// email claims are served from the userinfo endpoint, not duplicated here.
func (s *ClaimsStore) PrivateClaims(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	uid, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid subject %q: %w", userID, err)
	}
	info, mappers := s.identityAndMappers(ctx, uid, clientID)
	out := map[string]any{}
	if slices.Contains(scopes, "groups") && info != nil {
		if info.Groups == nil {
			out["groups"] = []string{}
		} else {
			out["groups"] = info.Groups
		}
	}
	applyClaimMappers(out, mappers, info, scopes)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// identityAndMappers loads the user identity and the client's claim mappers.
// Either may be nil/empty; callers tolerate that.
func (s *ClaimsStore) identityAndMappers(ctx context.Context, uid int64, clientID string) (*resolver.IdentityInfo, []claimMapper) {
	info, err := s.identity.ResolveUser(ctx, uid)
	if err != nil {
		info = nil
	}
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil || app == nil {
		return info, nil
	}
	return info, parseClientConfig(app.ProtocolConfig).ClaimMappers
}

// applyClaimMappers projects per-app mappers into claims. Each mapper's Scope
// (when set and not "*") gates emission against the requested scopes. Path
// resolution walks IdentityInfo by dotted segments only — arbitrary state is not
// addressable (no data-exfil surface).
func applyClaimMappers(claims map[string]any, mappers []claimMapper, info *resolver.IdentityInfo, scopes []string) map[string]any {
	if claims == nil {
		claims = map[string]any{}
	}
	if len(mappers) == 0 || info == nil {
		return claims
	}
	for _, m := range mappers {
		if m.Claim == "" || m.Source == "" {
			continue
		}
		if m.Scope != "" && m.Scope != "*" && !slices.Contains(scopes, m.Scope) {
			continue
		}
		if val, ok := resolveClaimSource(m.Source, info); ok {
			claims[m.Claim] = val
		}
	}
	return claims
}

// resolveClaimSource walks dotted path segments rooted at "user": e.g.
// user.email, user.groups, user.detail.<key>, user.tenant_id.
func resolveClaimSource(path string, info *resolver.IdentityInfo) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) < 2 || parts[0] != "user" {
		return nil, false
	}
	if parts[1] == "detail" {
		if len(parts) != 3 || info.Detail == nil {
			return nil, false
		}
		v, ok := info.Detail[parts[2]]
		return v, ok
	}
	if len(parts) != 2 {
		return nil, false
	}
	switch parts[1] {
	case "id":
		return info.ID, true
	case "tenant_id":
		return info.TenantID, true
	case "username":
		return zeroToNil(info.Username)
	case "email":
		return zeroToNil(info.Email)
	case "phone":
		return zeroToNil(info.Phone)
	case "display_name":
		return zeroToNil(info.DisplayName)
	case "avatar":
		return zeroToNil(info.Avatar)
	case "locale":
		return zeroToNil(info.Locale)
	case "updated_at":
		if info.UpdatedAt == 0 {
			return nil, false
		}
		return info.UpdatedAt, true
	case "status":
		return info.Status, true
	case "groups":
		return info.Groups, true
	}
	return nil, false
}

func zeroToNil(s string) (any, bool) {
	if s == "" {
		return nil, false
	}
	return s, true
}
