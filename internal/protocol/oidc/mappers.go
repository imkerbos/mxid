package oidc

import (
	"strings"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// applyClaimMappers projects per-app declarative claim mappers into the
// claims map. Mutates `claims` in place and returns it for caller chaining.
//
// Each mapper's Scope (when set and not "*") gates emission against the
// scopes the RP requested at /authorize time. Path resolution walks
// IdentityInfo by dotted segments — only paths reachable from the user
// object are exposed; arbitrary application state is intentionally not
// addressable (no SSRF / data-exfil surface).
func applyClaimMappers(claims map[string]any, mappers []ClaimMapperConfig, info *resolver.IdentityInfo, requestedScopes []string) map[string]any {
	if len(mappers) == 0 || info == nil {
		return claims
	}
	scopeSet := make(map[string]struct{}, len(requestedScopes))
	for _, s := range requestedScopes {
		scopeSet[s] = struct{}{}
	}
	for _, m := range mappers {
		if m.Claim == "" || m.Source == "" {
			continue
		}
		if m.Scope != "" && m.Scope != "*" {
			if _, ok := scopeSet[m.Scope]; !ok {
				continue
			}
		}
		if val, ok := resolveClaimSource(m.Source, info); ok {
			claims[m.Claim] = val
		}
	}
	return claims
}

// resolveClaimSource walks dotted path segments rooted at IdentityInfo.
//
// Supported roots:
//
//	user.{username, email, phone, display_name, avatar, locale, status, updated_at}
//	user.id
//	user.groups               -> []string
//	user.detail.<key>         -> dynamic map (employee_no, department, …)
//	user.tenant_id
//
// Returns (value, true) when the path resolves to a non-nil value.
func resolveClaimSource(path string, info *resolver.IdentityInfo) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) < 2 || parts[0] != "user" {
		return nil, false
	}
	if parts[1] == "detail" {
		if len(parts) != 3 {
			return nil, false
		}
		if info.Detail == nil {
			return nil, false
		}
		v, ok := info.Detail[parts[2]]
		if !ok {
			return nil, false
		}
		return v, true
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
