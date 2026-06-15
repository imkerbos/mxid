// Subject identity resolver shared by OIDC / SAML / CAS.
//
// Each protocol asks ResolveSubject for the user identifier to embed in the
// outgoing token / NameID / principal. The answer depends on the app's
// configured subject_strategy and the caller's tenant context.
//
// Why centralised: shared apps (ScopeShared) can serve users from multiple
// tenants in the same client connection. Without a unifying rule each
// protocol would have to re-implement the "username collision across
// tenants" mitigation. Doing it here ensures OIDC/SAML/CAS behave identically.
package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// SubjectStrategy mirrors internal/domain/app/model.go constants. Duplicated
// here as plain strings to avoid an import cycle (app -> resolver -> app).
const (
	StrategyUsername         = "username"
	StrategyUsernameSuffixed = "username_suffixed"
	StrategyEmail            = "email"
	StrategyPersistentID     = "persistent_id"
	StrategyPairwise         = "pairwise"
)

// SubjectInput is what every protocol hands to ResolveSubject.
type SubjectInput struct {
	UserID     int64  // canonical snowflake — always present
	Username   string // local username within the user's tenant
	Email      string // optional, may be empty
	TenantID   int64  // user's owning tenant; 0 for legacy/global accounts
	TenantCode string // tenant.code — used by *_suffixed strategy
	ClientID   string // OIDC client_id — used only by Pairwise strategy
}

// SubjectOutput is the normalised triple a protocol embeds in its token.
//
//   - Subject is what goes into OIDC sub / SAML NameID / CAS principal.
//     Apps that authenticate users by this field are guaranteed no
//     cross-tenant collision when MXID picks a strategy other than
//     StrategyUsername for a shared app.
//   - DisplayUsername is the "human readable" form. OIDC puts it in
//     preferred_username; SAML/CAS expose it as an attribute called
//     "username".
//   - TenantCode is always populated when known so apps can prefix
//     internal records.
type SubjectOutput struct {
	Subject         string
	DisplayUsername string
	TenantCode      string
}

// ResolveSubject computes (subject, display_username) for the given strategy.
// Returns an error only when inputs are inconsistent (e.g. pairwise without
// client_id) — never returns silently-mismatched fields.
func ResolveSubject(_ context.Context, strategy string, in SubjectInput) (*SubjectOutput, error) {
	out := &SubjectOutput{TenantCode: in.TenantCode, DisplayUsername: in.Username}

	switch strategy {
	case StrategyUsername, "":
		// Bare username; only safe inside a single tenant. Caller (app
		// service) ensures shared apps never reach here.
		out.Subject = in.Username

	case StrategyUsernameSuffixed:
		// kerbos@matrixplus — disambiguates cross-tenant username collisions.
		if in.TenantCode != "" {
			out.Subject = in.Username + "@" + in.TenantCode
			out.DisplayUsername = out.Subject
		} else {
			out.Subject = in.Username
		}

	case StrategyEmail:
		if in.Email == "" {
			return nil, fmt.Errorf("subject_strategy=email but user has no email")
		}
		out.Subject = in.Email

	case StrategyPersistentID:
		// Opaque snowflake string — globally unique across tenants by design.
		out.Subject = strconv.FormatInt(in.UserID, 10)

	case StrategyPairwise:
		if in.ClientID == "" {
			return nil, fmt.Errorf("subject_strategy=pairwise requires client_id")
		}
		out.Subject = pairwiseSubject(in.ClientID, in.UserID)

	default:
		return nil, fmt.Errorf("unknown subject_strategy: %s", strategy)
	}

	return out, nil
}

// pairwiseSubject derives an opaque per-(client,user) identifier. Stable,
// non-reversible, and matches the spirit of OIDC §8.1 pairwise pseudonymous
// identifiers (without needing a separate per-sector_identifier_uri).
func pairwiseSubject(clientID string, userID int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", clientID, userID)))
	return hex.EncodeToString(h[:16]) // 32 hex chars — plenty of entropy
}
