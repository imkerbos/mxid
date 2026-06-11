package apitoken

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module holds the wired API token components.
type Module struct {
	Service *Service
	Repo    Repository
}

// Register builds the module — does NOT register HTTP routes.
// Self-service CRUD routes mount via cmd/server/main.go onto the console
// security group; bearer middleware mounts onto /openapi/v1.
func Register(app *bootstrap.App) *Module {
	r := NewRepository(app.DB)
	s := NewService(r, app.IDGen)
	return &Module{Service: s, Repo: r}
}
