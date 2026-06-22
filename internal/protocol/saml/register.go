package saml

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// Module holds the wired SAML components.
type Module struct {
	Handler *Handler
}

// Register wires up the SAML protocol module and registers routes.
func Register(
	rg *gin.RouterGroup,
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	sessionIdx *SessionIndexStore,
	logger *zap.Logger,
) *Module {
	handler := NewHandler(issuer, portalURL, appRes, idRes, sessRes, tenantRes, sessionIdx, logger)
	handler.RegisterRoutes(rg)
	return &Module{Handler: handler}
}
