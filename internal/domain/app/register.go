package app

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module holds the wired app components for use by other modules.
type Module struct {
	Repo       Repository
	Service    *Service
	KeyService *KeyService
	FavRepo    FavoriteRepository
}

// Register wires up the app domain module and registers routes.
//
// Master key is loaded from bootstrap config (crypto.key_encryption_key) and
// fatal-fails inside bootstrap before reaching here when invalid or missing.
func Register(a *bootstrap.App) *Module {
	repo := NewGormRepository(a.DB)
	svc := NewService(repo, a.IDGen, a.EventBus)

	keySvc := NewKeyService(repo, a.DB, a.IDGen, a.MasterKey)
	svc.SetKeyService(keySvc)

	h := NewHandler(svc, a.Config.Tenant.DefaultID)
	h.RegisterRoutes(a.ConsoleGroup)

	return &Module{
		Repo:       repo,
		Service:    svc,
		KeyService: keySvc,
		FavRepo:    NewFavoriteRepository(a.DB),
	}
}
