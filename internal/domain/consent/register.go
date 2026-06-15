package consent

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module holds the wired consent components for use by other modules.
type Module struct {
	Service *Service
}

// Register wires up the consent domain module.
//
// No HTTP routes are mounted here — the OIDC protocol handler and the portal
// gateway are the two consumers; both reach in through Module.Service.
func Register(a *bootstrap.App) *Module {
	return &Module{
		Service: NewService(a.DB, a.IDGen),
	}
}
