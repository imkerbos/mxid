package oidclogout

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// backchannelLogoutEventClaim is the OIDC back-channel logout event marker
// (spec: https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation).
const backchannelLogoutEventClaim = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenClaims carries the per-RP values needed to build a `logout+jwt`
// logout_token. Issuer/Audience/Subject/SID map directly onto the JWT
// iss/aud/sub/sid claims; the events marker, iat and jti are filled in by the
// Signer.
type LogoutTokenClaims struct {
	Issuer   string
	Audience string // client_id
	Subject  string // userID, string form
	// SID is emitted as the `sid` claim only when non-empty — callers should
	// leave it blank unless the target app requires
	// backchannel_logout_session_required.
	SID string
}

// Signer signs a logout_token for back-channel logout delivery.
type Signer interface {
	SignLogoutToken(ctx context.Context, claims LogoutTokenClaims) (string, error)
}

// KeySource loads the active provider signing key. Implemented by
// *oidckey.Service; narrowed to an interface here so this package stays
// engine-independent and testable without a database.
type KeySource interface {
	LoadActiveSigningKey(ctx context.Context) (*rsa.PrivateKey, string, string, error)
}

// ProviderKeysetSigner signs logout_tokens with the SAME provider keyset the
// zitadel engine uses to sign id_tokens (RS256, kid = active key id) — NOT a
// per-app cert, so the RP validates the logout_token against the JWKS it
// already trusts for id_token verification.
type ProviderKeysetSigner struct {
	keys KeySource
}

// NewProviderKeysetSigner wires a ProviderKeysetSigner over the given
// KeySource (typically *oidckey.Service).
func NewProviderKeysetSigner(keys KeySource) *ProviderKeysetSigner {
	return &ProviderKeysetSigner{keys: keys}
}

// SignLogoutToken builds and signs a logout_token per the OIDC back-channel
// logout spec: typ=logout+jwt header, kid from the active provider key, and
// claims iss/aud/sub/iat/jti/events (+ sid when requested).
func (s *ProviderKeysetSigner) SignLogoutToken(ctx context.Context, claims LogoutTokenClaims) (string, error) {
	priv, kid, _, err := s.keys.LoadActiveSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("load active signing key: %w", err)
	}

	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss": claims.Issuer,
		"aud": claims.Audience,
		"sub": claims.Subject,
		"iat": now.Unix(),
		"jti": fmt.Sprintf("logout-%s-%d", claims.Audience, now.UnixNano()),
		"events": map[string]any{
			backchannelLogoutEventClaim: map[string]any{},
		},
	}
	if claims.SID != "" {
		mapClaims["sid"] = claims.SID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "logout+jwt"

	signed, err := token.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("sign logout token: %w", err)
	}
	return signed, nil
}
