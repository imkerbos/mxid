package app

// Wiring for the zitadel/oidc-based OIDC provider (engine=zitadel), the
// replacement for the hand-rolled internal/protocol/oidc. Kept out of main.go
// so the god-file wiring stays a single gated call.

import (
	"context"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/oidckey"
	"github.com/imkerbos/mxid/internal/protocol/oidcop"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/dlock"
)

// wireOIDCOP builds and mounts the zitadel OpenID Provider plus the BFF login
// bridge, and starts provider-keyset rotation. issuer is the full external base
// (e.g. https://host/protocol/oidc).
func wireOIDCOP(
	workerCtx context.Context,
	a *bootstrap.App,
	issuer string,
	appResolver resolver.AppResolver,
	idResolver resolver.IdentityResolver,
	sessResolver resolver.SessionResolver,
	consent oidcop.ConsentChecker,
) error {
	// Provider keyset + auto-rotation (90d default). EnsureActive mints the
	// first signing key on startup. Rotation runs under the leader lock so
	// only one replica drives it — without this, N pods could concurrently
	// rotate and disagree on which key is active (see migration 000053's
	// partial unique index, the last-resort DB guard against that).
	keySvc := oidckey.NewService(a.DB, a.IDGen, a.MasterKey)
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyOIDCRotation, a.Logger, func(ctx context.Context) {
		keySvc.RunRotation(ctx, oidckey.DefaultRotationEvery, func(err error) {
			a.Logger.Error("oidc keyset rotation", zap.Error(err))
		})
	})

	// The OIDC issuer is the discovery base, which per spec equals the path the
	// endpoints live under. The hand-rolled engine advertised issuer=host-root
	// (non-standard, issuer != endpoint base); op requires them aligned, so the
	// op issuer is host + /protocol/oidc. id_token `iss` becomes this value.
	opIssuer := strings.TrimSuffix(issuer, "/") + "/protocol/oidc"
	issURL, err := url.Parse(opIssuer)
	if err != nil {
		return err
	}
	issuerPath := issURL.Path // /protocol/oidc

	// loginURL is the login-bridge path for an authRequestID. op redirects
	// unauthenticated users here, and it doubles as the post-login/post-consent
	// return_to target. RELATIVE on purpose: the browser resolves it against
	// whatever host it accessed (nginx :3500, be it localhost or a LAN IP), so
	// the flow never hard-codes a host/port. Sibling path to the op "/oidc/*"
	// subtree to avoid the wildcard.
	loginURL := func(id string) string {
		return issuerPath + "-login?authRequestID=" + url.QueryEscape(id)
	}

	clients := oidcop.NewClientStore(appResolver, loginURL)
	claims := oidcop.NewClaimsStore(idResolver, appResolver)
	storage := oidcop.NewStorage(a.Redis, keySvc, clients, claims, oidcop.DefaultConfig())

	cryptoKey := a.MasterKey.Derive("oidc-op-crypto-v1")
	provider, err := oidcop.NewProvider(opIssuer, storage, cryptoKey, true)
	if err != nil {
		return err
	}

	// op endpoints under the issuer path; login bridge at the sibling path.
	oidcop.Mount(a.ProtocolGroup, issuerPath, provider)

	// op.AuthCallbackURL returns an op-root-relative path (/authorize/callback?id=…)
	// because op is mounted under a stripped prefix. Prepend only the issuer PATH
	// (not the host) so it stays relative — same host-agnostic reasoning as
	// loginURL above.
	opCallback := oidcop.CallbackURL(provider)
	callbackURL := func(ctx context.Context, id string) string {
		return issuerPath + opCallback(ctx, id)
	}
	// portalURL "" → the bridge redirects to relative /login and /consent, which
	// the browser resolves against the nginx host it is already on.
	bridge := oidcop.NewLoginBridge(
		storage, appResolver, sessResolver, consent,
		callbackURL, loginURL, "",
	)
	a.ProtocolGroup.GET("/oidc-login", bridge.Handle)

	a.Logger.Info("OIDC engine: zitadel/oidc", zap.String("issuer", opIssuer))
	return nil
}
