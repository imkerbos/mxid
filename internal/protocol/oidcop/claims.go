package oidcop

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// AppRoleResolver returns the role codes a user has for a given app.
// Emitted as the `app_roles` claim in id_token / userinfo so RPs (Grafana,
// Jenkins, …) can map roles from it directly instead of writing JMESPath
// against the raw `groups` claim. Mirrors internal/protocol/oidc.AppRoleResolver
// so the same approle adapter instance (app/adapters_oidc.go's
// oidcAppRolesAdapter) wires into both OIDC engines unchanged.
type AppRoleResolver interface {
	ResolveAppRoles(ctx context.Context, userID, appID, tenantID int64) ([]string, error)
}

// ClaimsStore fills OIDC claims from MXID identity. Standard scope-driven claims
// come from the shared IdentityResolver; per-app declarative mappers are layered
// on top (the commercial-IdP "claim mapper" feature). tenants and appRoles are
// optional (nil-safe): a nil tenants resolver just omits tenant_code, a nil
// appRoles resolver just omits app_roles — mirroring the hand-rolled engine's
// own `if h.appRoles != nil` / `if h.tenantRes != nil` guards
// (internal/protocol/oidc/handler.go:154, 704).
type ClaimsStore struct {
	identity resolver.IdentityResolver
	apps     resolver.AppResolver
	tenants  resolver.TenantResolver
	appRoles AppRoleResolver
}

var _ ClaimsResolver = (*ClaimsStore)(nil)
var _ UserStatusResolver = (*ClaimsStore)(nil)

// userStatusActive mirrors user.StatusActive (1). Duplicated locally — same
// pattern as internal/protocol/oidc/handler.go's own local const — to avoid
// pulling the user domain package into the protocol layer.
const userStatusActive = 1

// NewClaimsStore wires a ClaimsStore. tenants/appRoles may be nil; see the
// ClaimsStore doc comment for what that degrades to.
func NewClaimsStore(identity resolver.IdentityResolver, apps resolver.AppResolver, tenants resolver.TenantResolver, appRoles AppRoleResolver) *ClaimsStore {
	return &ClaimsStore{identity: identity, apps: apps, tenants: tenants, appRoles: appRoles}
}

// IsUserActive implements oidcop.UserStatusResolver for the refresh-token
// disabled-account guard: a disabled/offboarded user's refresh token must
// stop minting new tokens immediately rather than lingering until the
// token's own expiry. Mirrors internal/protocol/oidc/handler.go:838's
// `refreshInfo == nil || refreshInfo.Status != userStatusActive` check —
// including failing closed (deny) when the user can't be resolved at all.
func (s *ClaimsStore) IsUserActive(ctx context.Context, userID string) (bool, error) {
	uid, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid subject %q: %w", userID, err)
	}
	info, err := s.identity.ResolveUser(ctx, uid)
	if err != nil || info == nil {
		return false, nil
	}
	return info.Status == userStatusActive, nil
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
	// Per-app declarative mappers, then the subject-strategy override +
	// tenant_code + preferred_username + app_roles (all keyed off the same
	// (user, app) pair, applied last so they win over the bare identity
	// defaults above — e.g. preferred_username set by the profile scope).
	identity, app, mappers := s.identityAppAndMappers(ctx, uid, clientID)
	for k, v := range applyClaimMappers(nil, mappers, identity, scopes) {
		info.AppendClaims(k, v)
	}
	s.applySubjectAndRoles(ctx, info, uid, app, identity)
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
	info, app, mappers := s.identityAppAndMappers(ctx, uid, clientID)
	out := map[string]any{}
	if slices.Contains(scopes, "groups") && info != nil {
		if info.Groups == nil {
			out["groups"] = []string{}
		} else {
			out["groups"] = info.Groups
		}
	}
	applyClaimMappers(out, mappers, info, scopes)
	if app != nil && info != nil {
		subj := s.resolveSubject(ctx, app, info)
		if subj.TenantCode != "" {
			out["tenant_code"] = subj.TenantCode
		}
		if subj.DisplayUsername != "" {
			out["preferred_username"] = subj.DisplayUsername
		}
		if s.appRoles != nil {
			if roles, err := s.appRoles.ResolveAppRoles(ctx, uid, app.ID, info.TenantID); err == nil && len(roles) > 0 {
				out["app_roles"] = roles
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// sessionCarrier is implemented by authRequest (see authrequest.go). Kept as
// a local interface — rather than depending on the concrete type — since the
// op.IDTokenRequest the library hands SetUserinfoFromRequest may in principle
// be any request shape; only ones carrying a session id contribute `sid`.
type sessionCarrier interface {
	GetSessionID() string
}

// SetUserinfoFromRequest implements op.CanSetUserinfoFromRequest, the optional
// hook pkg/op/token.go's CreateIDToken calls (when implemented by Storage)
// while assembling id_token claims, receiving the full request instead of
// just scopes.
//
// It delegates to ClaimsStore.SetUserinfo using request.GetSubject() (the raw
// internal user id — see authRequest.GetSubject()) and request.GetClientID(),
// the SAME two inputs SetUserinfoFromToken uses for /userinfo and
// SetIntrospectionFromToken uses for introspection. That shared code path is
// what guarantees `sub` (after the subject-strategy override), `app_roles`,
// `tenant_code` and `preferred_username` are identical across id_token,
// userinfo, and introspection for a given (app, user) — see
// ClaimsStore.applySubjectAndRoles. s.claims is nil in a few minimal test
// harnesses (e.g. the WS2 sid-only fixtures); guarded rather than assumed
// non-nil.
//
// It also layers the shared protocol session id — set on the auth request by
// the login bridge (bridge.go) — onto the id_token as `sid`. An empty session
// id (never populated, e.g. a non-interactive grant) emits no `sid` claim
// rather than a fabricated one. This is what makes OIDC back-channel logout
// (WS2) possible: the RP's logout_token must carry the same `sid` its
// id_token did, so the RP can correlate the logout to the right local
// session.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	if s.claims != nil {
		if err := s.claims.SetUserinfo(ctx, userinfo, request.GetSubject(), request.GetClientID(), scopes); err != nil {
			return err
		}
	}
	sc, ok := request.(sessionCarrier)
	if !ok {
		return nil
	}
	if sid := sc.GetSessionID(); sid != "" {
		userinfo.AppendClaims("sid", sid)
	}
	return nil
}

// identityAppAndMappers loads the user identity, the app config, and the
// client's claim mappers. Any of them may be nil/empty; callers tolerate that.
func (s *ClaimsStore) identityAppAndMappers(ctx context.Context, uid int64, clientID string) (*resolver.IdentityInfo, *resolver.AppConfig, []claimMapper) {
	info, err := s.identity.ResolveUser(ctx, uid)
	if err != nil {
		info = nil
	}
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil || app == nil {
		return info, nil, nil
	}
	return info, app, parseClientConfig(app.ProtocolConfig).ClaimMappers
}

// applySubjectAndRoles overrides `sub` per the app's subject_strategy and
// appends tenant_code / preferred_username / app_roles onto the claims being
// assembled for id_token, userinfo, or introspection. Ported from the
// hand-rolled engine's resolveSubject + AppRoleResolver call sites
// (internal/protocol/oidc/handler.go:149-174, 692-708, 1021-1029). No-op when
// the app or the user identity can't be resolved — mirrors the hand-rolled
// engine falling back to the un-overridden claims map on the same condition.
func (s *ClaimsStore) applySubjectAndRoles(ctx context.Context, info *oidc.UserInfo, uid int64, app *resolver.AppConfig, identity *resolver.IdentityInfo) {
	if app == nil || identity == nil {
		return
	}
	subj := s.resolveSubject(ctx, app, identity)
	if subj.Subject != "" {
		info.Subject = subj.Subject
	}
	if subj.TenantCode != "" {
		info.AppendClaims("tenant_code", subj.TenantCode)
	}
	if subj.DisplayUsername != "" {
		info.AppendClaims("preferred_username", subj.DisplayUsername)
	}
	if s.appRoles != nil {
		// tenantID is the USER's tenant (identity.TenantID), not the app's —
		// shared apps (ScopeShared) serve users from multiple tenants, and
		// role bindings are scoped to the user's own tenant. Matches the
		// hand-rolled engine's ac.TenantID (the authenticated user's tenant
		// captured at /authorize time). Passed explicitly per the WS5
		// constraint: the bridge carries no tenantscope context.
		if roles, err := s.appRoles.ResolveAppRoles(ctx, uid, app.ID, identity.TenantID); err == nil && len(roles) > 0 {
			info.AppendClaims("app_roles", roles)
		}
	}
}

// resolveSubject computes the (sub, display_username, tenant_code) triple for
// the given app + user via the shared cross-protocol resolver.ResolveSubject,
// applying the app's subject_strategy (pairwise / persistent_id / email /
// username_suffixed / username). Ported from
// internal/protocol/oidc/handler.go:149-174. tenantID is passed explicitly to
// the TenantResolver — the oidcop bridge sets no tenantscope context. Falls
// back to the opaque snowflake id on any resolution error, same as the
// hand-rolled engine — claim assembly must never fail purely on a
// subject-strategy lookup.
func (s *ClaimsStore) resolveSubject(ctx context.Context, app *resolver.AppConfig, info *resolver.IdentityInfo) *resolver.SubjectOutput {
	tenantCode := ""
	if s.tenants != nil && info.TenantID > 0 {
		tenantCode, _ = s.tenants.GetTenantCode(ctx, info.TenantID)
	}
	out, err := resolver.ResolveSubject(ctx, app.SubjectStrategy, resolver.SubjectInput{
		UserID:     info.ID,
		Username:   info.Username,
		Email:      info.Email,
		TenantID:   info.TenantID,
		TenantCode: tenantCode,
		ClientID:   app.ClientID,
	})
	if err != nil || out == nil {
		return &resolver.SubjectOutput{
			Subject:         strconv.FormatInt(info.ID, 10),
			DisplayUsername: info.Username,
			TenantCode:      tenantCode,
		}
	}
	return out
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
