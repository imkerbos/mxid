package oidcop

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// NewProvider builds the zitadel OpenID Provider. issuer is the full external
// base (e.g. https://host/protocol/oidc); cryptoKey (32 bytes) encrypts op's
// internal state/cookies. The provider IS an http.Handler serving authorize/
// token/userinfo/keys/discovery/end_session.
func NewProvider(issuer string, storage op.Storage, cryptoKey [32]byte, allowInsecure bool) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey:                cryptoKey,
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true, // PKCE S256
		AuthMethodPost:           true, // client_secret_post
		AuthMethodPrivateKeyJWT:  true, // private_key_jwt client auth
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedScopes: []string{
			"openid", "profile", "email", "phone", "address", "groups", "offline_access",
		},
		SupportedUILocales: []language.Tag{language.English, language.SimplifiedChinese},
	}
	// Mirror the hand-rolled engine's endpoint paths so existing clients
	// (Grafana et al.) need no reconfiguration when switching engines — only
	// the issuer/iss value changes. op's own defaults differ (/oauth/token,
	// /keys, /end_session, /oauth/introspect).
	opts := []op.Option{
		op.WithCustomTokenEndpoint(op.NewEndpoint("token")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("jwks")),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint("end-session")),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("introspect")),
	}
	if allowInsecure {
		// We terminate TLS at nginx; the internal issuer is http. Allow it.
		opts = append(opts, op.WithAllowInsecure())
	}
	return op.NewProvider(config, storage, op.StaticIssuer(issuer), opts...)
}

// CallbackURL returns the builder for the authorize-callback URL op resumes at
// once the login bridge marks an auth request done (issuer/authorize/callback?id=).
func CallbackURL(provider op.OpenIDProvider) func(context.Context, string) string {
	return op.AuthCallbackURL(provider)
}

// Mount attaches the provider's handlers under group at the "/oidc/*" subtree.
// stripPrefix is the issuer path (e.g. /protocol/oidc) that must be stripped so
// op's root-relative routes (/authorize, /.well-known/...) match.
func Mount(group *gin.RouterGroup, stripPrefix string, provider http.Handler) {
	wrapped := gin.WrapH(http.StripPrefix(stripPrefix, provider))
	group.Any("/oidc/*any", wrapped)
}
