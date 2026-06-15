package registry

import (
	"context"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/session"
)

// This file is the dependency-injection seam used by heavier EE features (e.g.
// external IdP) that need more than a console route group: they require the
// bootstrap App (DB/Redis/router/groups), plus a handful of CE-domain hooks the
// EE module cannot construct itself (account linking lives in the CE user
// domain; tenant-code resolution and console authorization live in CE too).
//
// An EE feature registers an Initializer from its init(); app/run.go calls
// RunInit once at startup with a populated InitContext. CE imports no EE feature
// package, so no Initializer is registered and RunInit is a no-op.

// ResolverInput is the neutral account-linking contract between an external IdP
// callback (EE) and the CE user domain. It mirrors user.ExternalLoginInput but
// lives here so neither side imports the other: CE's adapter and the EE handler
// both reference this type. Carries every field needed to link an existing user
// or auto-provision a new one.
type ResolverInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any
	AutoCreate   bool
	DefaultOrgID *int64
}

// ExternalLoginFunc resolves an external identity to a local user, returning the
// user id and username. Implemented by the CE user domain.
type ExternalLoginFunc func(ctx context.Context, in *ResolverInput) (userID int64, username string, err error)

// TenantByCodeFunc maps a tenant code to its id (0 when unknown). Implemented by
// the CE tenant domain.
type TenantByCodeFunc func(ctx context.Context, code string) int64

// ConsoleGateFunc authorizes an external identity for console login: it must
// reject break-glass built-in accounts and users without any console
// permission. Implemented in CE (authz + user repo).
type ConsoleGateFunc func(ctx context.Context, tenantID, userID int64) error

// ExternalURLsFunc returns the externally-reachable issuer (the OAuth callback
// target), portal, and console URLs for a tenant — read at REQUEST time from the
// CE settings store so external-IdP callbacks use the admin-configured URLs
// rather than a boot-time env default. Any empty return value means "fall back
// to the boot-time env value". Implemented in CE over settings.ExternalURLs (it
// injects the tenant scope itself, since external-IdP start runs pre-login
// without one). Unifies external URL config across CE protocols and EE IdP.
type ExternalURLsFunc func(ctx context.Context, tenantID int64) (issuer, portal, console string)

// InitContext carries everything an EE feature needs from CE at startup. App
// exposes DB/Redis/router/route-groups/config; the func hooks bridge to CE
// domains the EE module must not import.
type InitContext struct {
	App          *bootstrap.App
	SessionMgr   *session.Manager
	ExternalLogin ExternalLoginFunc
	TenantByCode TenantByCodeFunc
	ConsoleGate  ConsoleGateFunc
	ExternalURLs ExternalURLsFunc
}

// Initializer wires one EE feature. Returning an error aborts startup.
type Initializer func(*InitContext) error

var initializers []Initializer

// RegisterInit adds an EE feature initializer. Called from an EE package init().
func RegisterInit(i Initializer) {
	if i != nil {
		initializers = append(initializers, i)
	}
}

// RunInit invokes every registered EE initializer with the given context. No EE
// module imported (CE) → no initializers → no-op.
func RunInit(ic *InitContext) error {
	for _, i := range initializers {
		if err := i(ic); err != nil {
			return err
		}
	}
	return nil
}
