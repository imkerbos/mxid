package dashboard

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module exposes the dashboard service so main can wire the live-session
// counter (backed by redis) after the session manager is constructed.
type Module struct {
	Service *Service
}

// Register wires the dashboard domain module and mounts its routes on the
// console group.
func Register(app *bootstrap.App) *Module {
	svc := NewService(app.DB)
	h := NewHandler(svc, app.Config.Tenant.DefaultID)
	h.RegisterRoutes(app.ConsoleGroup)
	return &Module{Service: svc}
}
