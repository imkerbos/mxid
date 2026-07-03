package access

import (
	"context"

	"github.com/imkerbos/mxid/internal/domain/app"
	"go.uber.org/zap"
)

// ProtocolResolver maps an app id to its SSO protocol ("oidc" | "saml" | "cas").
// Implemented in app/run.go over the app domain service so the composite
// terminator can pick the right downstream-logout handler per app.
type ProtocolResolver interface {
	ProtocolForApp(ctx context.Context, appID int64) (string, error)
}

// CompositeTerminator implements DownstreamTerminator by resolving the target
// app's protocol and dispatching to the matching per-protocol logout func
// (built in the OIDC/SAML/CAS handlers). It is best-effort: resolve failures
// and unknown protocols are logged and skipped, never surfaced — JIT grant
// expiry/revoke must not block on downstream session teardown.
type CompositeTerminator struct {
	resolver ProtocolResolver
	oidc     func(context.Context, int64, int64)
	saml     func(context.Context, int64, int64)
	cas      func(context.Context, int64, int64)
	logger   *zap.Logger
}

// NewCompositeTerminator builds a CompositeTerminator. oidc/saml/cas are the
// per-protocol dispatchers, each of shape func(ctx, userID, appID).
func NewCompositeTerminator(
	resolver ProtocolResolver,
	oidc, saml, cas func(context.Context, int64, int64),
	logger *zap.Logger,
) *CompositeTerminator {
	return &CompositeTerminator{
		resolver: resolver,
		oidc:     oidc,
		saml:     saml,
		cas:      cas,
		logger:   logger,
	}
}

// TerminateAppSession resolves the app's protocol and dispatches to the matching
// downstream-logout func. It implements DownstreamTerminator.
func (c *CompositeTerminator) TerminateAppSession(ctx context.Context, tenantID, userID, appID int64) {
	proto, err := c.resolver.ProtocolForApp(ctx, appID)
	if err != nil {
		c.warn("terminator: resolve protocol failed",
			zap.Int64("tenant_id", tenantID), zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	switch proto {
	case app.ProtocolOIDC:
		if c.oidc != nil {
			c.oidc(ctx, userID, appID)
		}
	case app.ProtocolSAML:
		if c.saml != nil {
			c.saml(ctx, userID, appID)
		}
	case app.ProtocolCAS:
		if c.cas != nil {
			c.cas(ctx, userID, appID)
		}
	default:
		c.warn("terminator: unsupported protocol",
			zap.String("protocol", proto), zap.Int64("app_id", appID))
	}
}

func (c *CompositeTerminator) warn(msg string, fields ...zap.Field) {
	if c.logger != nil {
		c.logger.Warn(msg, fields...)
	}
}
