package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// KeyService manages per-application signing key material.
//
// Lifecycle:
//
//   - GenerateForApp issues a fresh RSA-2048 keypair, encrypts the private key
//     with the configured master key, and persists a new mxid_app_cert row
//     in CertStatusActive state.
//   - LoadSigningKey returns the currently active signing key for an app,
//     decrypting it on the fly. Cached in-memory by the caller (token issuer)
//     is fine; this service does not cache.
//   - ListActiveSigningCerts feeds the IdP-level JWKS endpoint.
type KeyService struct {
	repo      Repository
	db        *gorm.DB
	idGen     *snowflake.Generator
	masterKey *crypto.MasterKey
}

// NewKeyService wires a KeyService.
func NewKeyService(repo Repository, db *gorm.DB, idGen *snowflake.Generator, masterKey *crypto.MasterKey) *KeyService {
	return &KeyService{repo: repo, db: db, idGen: idGen, masterKey: masterKey}
}

// Errors.
var (
	ErrKeyNotFound        = errors.New("signing key not found")
	ErrMasterKeyMissing   = errors.New("master key not configured")
	ErrUnsupportedAlgo    = errors.New("unsupported signing algorithm")
)

// SigningKeyTTL is the default validity window for an OIDC signing key.
const SigningKeyTTL = 365 * 24 * time.Hour

// GenerateForApp generates an RSA-2048 keypair, encrypts the private PEM with
// the master key, and inserts a new active mxid_app_cert row.
func (s *KeyService) GenerateForApp(ctx context.Context, appID int64) (*AppCert, error) {
	if s.masterKey == nil {
		return nil, ErrMasterKeyMissing
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Produce a self-signed X.509 certificate that wraps the RSA public key.
	//
	// Why X.509 (not bare PUBLIC KEY): SAML metadata requires a real X.509
	// certificate inside <ds:X509Certificate>, not a PKIX pubkey. Keycloak /
	// Auth0 / Okta all ship self-signed certs in their IdP metadata, even
	// for OIDC (the cert wraps the same RSA key the JWKS exposes).
	//
	// OIDC JWKS keeps working: jwks.parseRSAPublicKey now accepts CERTIFICATE
	// PEM blocks and unwraps the RSA key out of the cert.
	now := time.Now()
	expiresAt := now.Add(SigningKeyTTL)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("mxid-app-%d", appID),
			Organization: []string{"MXID"},
		},
		NotBefore:             now,
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed cert: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	encryptedPriv, err := s.masterKey.Encrypt(privPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	kid := newKID()

	cert := &AppCert{
		ID:         s.idGen.Generate(),
		AppID:      appID,
		CertType:   CertTypeSigning,
		Algorithm:  "RS256",
		PublicKey:  string(pubPEM),
		PrivateKey: encryptedPriv,
		KID:        &kid,
		NotBefore:  now,
		ExpiresAt:  &expiresAt,
		Encrypted:  true,
		Status:     CertStatusActive,
		CreatedAt:  now,
	}
	if err := s.repo.CreateCert(ctx, cert); err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	return cert, nil
}

// RotateForApp performs a soft signing-key rotation:
//
//  1. Mint a new keypair in CertStatusActive.
//  2. Demote the previous CertStatusActive (if any) to CertStatusRotating.
//
// JWKS continues to expose both keys during the overlap window so RPs that
// cached the prior public key can still verify existing id_tokens until
// they expire. A future job (or the next rotate call) will retire the
// rotating cert once it has aged past id_token_lifetime + grace.
//
// Returns the freshly minted cert. On any error the operation is aborted
// without leaving the app in a half-rotated state — the previous active key
// is only demoted after the new one is successfully persisted.
func (s *KeyService) RotateForApp(ctx context.Context, appID int64) (*AppCert, error) {
	if s.masterKey == nil {
		return nil, ErrMasterKeyMissing
	}

	newCert, err := s.GenerateForApp(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("rotate: mint new key: %w", err)
	}

	// Demote previous active(s) — guard against multiple actives sneaking in
	// via concurrent rotations: SQL filter excludes the newly inserted row.
	res := s.db.WithContext(ctx).
		Model(&AppCert{}).
		Where("app_id = ? AND cert_type = ? AND status = ? AND id <> ?",
			appID, CertTypeSigning, CertStatusActive, newCert.ID).
		Update("status", CertStatusRotating)
	if res.Error != nil {
		// Best-effort rollback of the new key so we don't end up with two
		// active certs. Failure here is logged at the caller; not fatal.
		_ = s.db.WithContext(ctx).Delete(&AppCert{}, newCert.ID).Error
		return nil, fmt.Errorf("rotate: demote previous active: %w", res.Error)
	}

	return newCert, nil
}

// RetireExpiredRotating sweeps signing certs that have lingered in
// CertStatusRotating past their expires_at and marks them retired. Safe to
// call on a cron; idempotent.
func (s *KeyService) RetireExpiredRotating(ctx context.Context) error {
	res := s.db.WithContext(ctx).
		Model(&AppCert{}).
		Where("cert_type = ? AND status = ? AND expires_at IS NOT NULL AND expires_at < NOW()",
			CertTypeSigning, CertStatusRotating).
		Update("status", CertStatusRetired)
	return res.Error
}

// LoadSigningKey returns the currently active signing key for an app along
// with its kid. Returns ErrKeyNotFound when no active signing cert exists.
func (s *KeyService) LoadSigningKey(ctx context.Context, appID int64) (*rsa.PrivateKey, string, error) {
	if s.masterKey == nil {
		return nil, "", ErrMasterKeyMissing
	}
	certs, err := s.repo.ListCertsByApp(ctx, appID)
	if err != nil {
		return nil, "", fmt.Errorf("list certs: %w", err)
	}
	var active *AppCert
	for _, c := range certs {
		if c.CertType != CertTypeSigning {
			continue
		}
		if c.Status != CertStatusActive {
			continue
		}
		active = c
		break
	}
	if active == nil {
		return nil, "", ErrKeyNotFound
	}

	privPEM, err := s.decryptPrivate(active)
	if err != nil {
		return nil, "", err
	}
	priv, err := parseRSAPrivateKeyPEM(privPEM)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}
	kid := ""
	if active.KID != nil {
		kid = *active.KID
	}
	return priv, kid, nil
}

// ListActiveSigningCerts returns active + rotating signing certs across all
// enabled apps. Feed for the IdP-level JWKS endpoint.
func (s *KeyService) ListActiveSigningCerts(ctx context.Context) ([]*AppCert, error) {
	var certs []*AppCert
	err := s.db.WithContext(ctx).
		Model(&AppCert{}).
		Joins("INNER JOIN mxid_app ON mxid_app.id = mxid_app_cert.app_id AND mxid_app.deleted_at IS NULL AND mxid_app.status = ?", StatusEnabled).
		Where("mxid_app_cert.cert_type = ? AND mxid_app_cert.status IN ?", CertTypeSigning, []int{CertStatusActive, CertStatusRotating}).
		Find(&certs).Error
	if err != nil {
		return nil, fmt.Errorf("list active signing certs: %w", err)
	}
	return certs, nil
}

func (s *KeyService) decryptPrivate(cert *AppCert) ([]byte, error) {
	if !cert.Encrypted {
		// Legacy plaintext record (pre-migration); return raw bytes for backward compat.
		return []byte(cert.PrivateKey), nil
	}
	plain, err := s.masterKey.Decrypt(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	return plain, nil
}

func parseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return priv, nil
}

// newKID produces a short opaque key identifier (16 base62 chars).
func newKID() string {
	kid, err := crypto.GenerateBase62(16)
	if err != nil {
		// Fall back to a timestamp-derived id; collision-resistant for our
		// volumes and avoids panic in the hot path.
		return fmt.Sprintf("k%d", time.Now().UnixNano())
	}
	return kid
}
