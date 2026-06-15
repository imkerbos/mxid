package resolver

import (
	"context"
	"encoding/json"
	"fmt"
)

// appGetByCode fetches an app by its code within a tenant.
type appGetByCode func(ctx context.Context, tenantID int64, code string) (*AppConfig, error)

// appGetByClientID fetches an app by its OAuth client_id.
type appGetByClientID func(ctx context.Context, clientID string) (*AppConfig, error)

// appGetByID fetches an app by its primary key.
type appGetByID func(ctx context.Context, appID int64) (*AppConfig, error)

// appGetCert fetches the active cert for an app by type.
type appGetCert func(ctx context.Context, appID int64, certType string) (*CertConfig, error)

// appListCerts lists all certs for an app.
type appListCerts func(ctx context.Context, appID int64) ([]*CertConfig, error)

// appListAllActiveSigningCerts lists active+rotating signing certs across all enabled apps.
type appListAllActiveSigningCerts func(ctx context.Context) ([]*CertConfig, error)

// appMintSigningCert mints a fresh signing keypair for an app and persists it.
type appMintSigningCert func(ctx context.Context, appID int64) (*CertConfig, error)

// appResolverImpl implements AppResolver using injected functions.
type appResolverImpl struct {
	getByCode            appGetByCode
	getByID              appGetByID
	getByClientID        appGetByClientID
	getCert              appGetCert
	listCerts            appListCerts
	listAllActiveSigning appListAllActiveSigningCerts
	mintSigningCert      appMintSigningCert
}

// NewAppResolver creates an AppResolver from adapter functions.
func NewAppResolver(
	getByCode appGetByCode,
	getByID appGetByID,
	getByClientID appGetByClientID,
	getCert appGetCert,
	listCerts appListCerts,
	listAllActiveSigning appListAllActiveSigningCerts,
	mintSigningCert appMintSigningCert,
) AppResolver {
	return &appResolverImpl{
		getByCode:            getByCode,
		getByID:              getByID,
		getByClientID:        getByClientID,
		getCert:              getCert,
		listCerts:            listCerts,
		listAllActiveSigning: listAllActiveSigning,
		mintSigningCert:      mintSigningCert,
	}
}

func (r *appResolverImpl) GetAppByID(ctx context.Context, appID int64) (*AppConfig, error) {
	app, err := r.getByID(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("resolve app by id: %w", err)
	}
	return app, nil
}

func (r *appResolverImpl) GetApp(ctx context.Context, identifier string) (*AppConfig, error) {
	// identifier is app code; tenantID defaults to 1 for now (single-tenant MVP)
	app, err := r.getByCode(ctx, 1, identifier)
	if err != nil {
		return nil, fmt.Errorf("resolve app by code: %w", err)
	}
	return app, nil
}

func (r *appResolverImpl) GetAppByClientID(ctx context.Context, clientID string) (*AppConfig, error) {
	app, err := r.getByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("resolve app by client_id: %w", err)
	}
	return app, nil
}

func (r *appResolverImpl) GetCert(ctx context.Context, appID int64, certType string) (*CertConfig, error) {
	cert, err := r.getCert(ctx, appID, certType)
	if err != nil {
		return nil, fmt.Errorf("resolve cert: %w", err)
	}
	return cert, nil
}

func (r *appResolverImpl) ListCerts(ctx context.Context, appID int64) ([]*CertConfig, error) {
	certs, err := r.listCerts(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	return certs, nil
}

func (r *appResolverImpl) ListAllActiveSigningCerts(ctx context.Context) ([]*CertConfig, error) {
	certs, err := r.listAllActiveSigning(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all active signing certs: %w", err)
	}
	return certs, nil
}

func (r *appResolverImpl) MintSigningCert(ctx context.Context, appID int64) (*CertConfig, error) {
	if r.mintSigningCert == nil {
		return nil, fmt.Errorf("mint signing cert: not configured")
	}
	cert, err := r.mintSigningCert(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("mint signing cert: %w", err)
	}
	return cert, nil
}

// ParseRedirectURIs extracts redirect_uris from a JSON array.
func ParseRedirectURIs(raw json.RawMessage) []string {
	var uris []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &uris)
	}
	return uris
}
