package externalidp

import (
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/session"
)

// Module bundles the externalidp wiring for cross-domain consumers.
type Module struct {
	Repo    Repository
	Service *Service
}

// Register builds the externalidp module WITHOUT registering routes — the
// caller decides where (console vs portal) and with which middleware chain
// they live, because the public portal routes must skip auth while the
// admin routes go behind the authz middleware.
func Register(app *bootstrap.App) *Module {
	repo := NewRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.Redis, DefaultRegistry)
	return &Module{Repo: repo, Service: svc}
}

// MountAdminRoutes attaches the console-side admin CRUD endpoints.
func (m *Module) MountAdminRoutes(app *bootstrap.App, tenantID int64) {
	NewAdminHandler(m.Service, tenantID).RegisterRoutes(app.ConsoleGroup)
}

// MountPortalRoutes attaches the public-facing portal endpoints DIRECTLY on
// the gin engine (NOT under app.PortalGroup, which is auth-gated) so the
// OAuth redirect handshake works for unauthenticated visitors.
func (m *Module) MountPortalRoutes(app *bootstrap.App, opts PortalHandlerOpts) {
	opts.Svc = m.Service
	publicGroup := app.Router.Group("/api/v1/portal")
	NewPortalHandler(opts).RegisterRoutes(publicGroup)
}

var _ = session.NamespacePortal
