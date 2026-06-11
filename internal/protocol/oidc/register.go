package oidc

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/redis/go-redis/v9"
)

// Module holds the wired OIDC components.
type Module struct {
	Handler *Handler
	Store   *Store
}

// Register wires up the OIDC protocol module and registers routes.
func Register(
	rg *gin.RouterGroup,
	issuer string,
	portalURL string,
	rdb *redis.Client,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	consentChecker ConsentChecker,
	accessChecker AccessChecker,
	appRolesResolver AppRoleResolver,
	sessionMgr *session.Manager,
	eventBus *event.Bus,
) *Module {
	store := NewStore(rdb)
	handler := NewHandler(issuer, portalURL, appRes, idRes, sessRes, tenantRes, consentChecker, accessChecker, appRolesResolver, sessionMgr, store, eventBus)
	handler.RegisterRoutes(rg)

	return &Module{
		Handler: handler,
		Store:   store,
	}
}
