package tenant

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module bundles wiring for cross-domain consumers.
type Module struct {
	Repo    Repository
	Service *Service
	Handler *Handler
}

// Register builds the module and mounts routes on the console group.
func Register(app *bootstrap.App) *Module {
	repo := NewRepository(app.DB)
	svc := NewService(repo, app.IDGen)
	handler := NewHandler(svc)
	handler.RegisterRoutes(app.ConsoleGroup)
	return &Module{Repo: repo, Service: svc, Handler: handler}
}
