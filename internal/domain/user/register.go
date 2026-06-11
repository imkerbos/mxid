package user

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module holds the wired user components for use by other modules.
//
// The handler is created up-front so cross-module wiring (authn adapters,
// MFA verifier) can build against the service while route registration
// stays deferred until the console group has its full middleware chain
// (auth + authz) in place.
type Module struct {
	Repo    Repository
	Service *Service
	Handler *Handler
}

// Register builds the module WITHOUT registering routes. Call
// (*Module).RegisterRoutes(app) once the protected route group's
// middleware (auth + authz) has been mounted — otherwise the per-route
// authz.Require closures fail to resolve their service from gin.Context.
func Register(app *bootstrap.App) *Module {
	repo := NewGormRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.EventBus, &app.Config.Security, app.MasterKey, "MXID")
	svc.SetBackupCodeRepository(NewBackupCodeRepository(app.DB))
	h := NewHandler(svc)
	return &Module{
		Repo:    repo,
		Service: svc,
		Handler: h,
	}
}

// RegisterRoutes mounts the user HTTP routes on the console group. Must be
// called after the console group's middleware chain is finalised.
func (m *Module) RegisterRoutes(app *bootstrap.App) {
	m.Handler.RegisterRoutes(app.ConsoleGroup)
}
