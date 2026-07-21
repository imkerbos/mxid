package cas

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/ssoflow"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Module holds the wired CAS components.
type Module struct {
	Handler         *Handler
	Store           *TicketStore
	ServiceRegistry *ServiceRegistry
}

// Register wires up the CAS protocol module and registers routes.
func Register(
	rg *gin.RouterGroup,
	issuer string,
	portalURL string,
	rdb *redis.Client,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	appRoles AppRoleResolver,
	logger *zap.Logger,
) *Module {
	store := NewTicketStore(rdb)
	serviceRegistry := NewServiceRegistry(rdb)
	handler := NewHandler(issuer, portalURL, appRes, idRes, sessRes, tenantRes, store, serviceRegistry, logger)
	handler.confirm = ssoflow.NewConfirmStore(rdb)
	handler.appRoles = appRoles
	handler.RegisterRoutes(rg)
	return &Module{
		Handler:         handler,
		Store:           store,
		ServiceRegistry: serviceRegistry,
	}
}
