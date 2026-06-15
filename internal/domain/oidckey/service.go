package oidckey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Tunables.
const (
	// SigningTTL is how long a minted key stays valid (its expires_at). A
	// rotating key is retired once aged past this.
	SigningTTL = 365 * 24 * time.Hour
	// DefaultRotationEvery is the default auto-rotation cadence. The active key
	// is rotated once it is older than this. Operator-overridable.
	DefaultRotationEvery = 90 * 24 * time.Hour
	rsaKeyBits           = 2048
)

var (
	ErrMasterKeyMissing = errors.New("master key not configured")
	ErrNoActiveKey      = errors.New("no active oidc signing key")
)

// Service manages the provider OIDC keyset lifecycle: mint, rotate, retire, and
// load for signing/verification. Mirrors app.KeyService but issuer-scoped (no
// app_id) — one keyset for the whole OIDC provider.
type Service struct {
	db        *gorm.DB
	idGen     *snowflake.Generator
	masterKey *crypto.MasterKey
}

// NewService wires a Service.
func NewService(db *gorm.DB, idGen *snowflake.Generator, masterKey *crypto.MasterKey) *Service {
	return &Service{db: db, idGen: idGen, masterKey: masterKey}
}

// VerificationKey is a public key published in the JWKS.
type VerificationKey struct {
	KID       string
	Algorithm string
	Public    *rsa.PublicKey
}

// Generate mints a fresh RSA keypair, encrypts the private PEM with the KEK, and
// inserts a new ACTIVE keyset row.
func (s *Service) Generate(ctx context.Context) (*ProviderKey, error) {
	if s.masterKey == nil {
		return nil, ErrMasterKeyMissing
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	encryptedPriv, err := s.masterKey.Encrypt(privPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	kid, err := crypto.GenerateBase62(16)
	if err != nil {
		return nil, fmt.Errorf("generate kid: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(SigningTTL)
	key := &ProviderKey{
		ID:         s.idGen.Generate(),
		KID:        kid,
		Algorithm:  "RS256",
		PublicKey:  string(pubPEM),
		PrivateKey: encryptedPriv,
		Status:     StatusActive,
		NotBefore:  now,
		ExpiresAt:  &expiresAt,
		CreatedAt:  now,
	}
	if err := s.db.WithContext(ctx).Create(key).Error; err != nil {
		return nil, fmt.Errorf("insert keyset row: %w", err)
	}
	return key, nil
}

// EnsureActive returns the current active key, minting the first one if the
// keyset is empty. Safe to call on startup.
func (s *Service) EnsureActive(ctx context.Context) (*ProviderKey, error) {
	active, err := s.activeKey(ctx)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, ErrNoActiveKey) {
		return nil, err
	}
	return s.Generate(ctx)
}

// Rotate mints a new active key and demotes the previous active to ROTATING so
// its public key stays in the JWKS until tokens it signed expire. Aborts cleanly
// on error (the new key is removed) so the keyset never ends up with two actives.
func (s *Service) Rotate(ctx context.Context) (*ProviderKey, error) {
	if s.masterKey == nil {
		return nil, ErrMasterKeyMissing
	}
	newKey, err := s.Generate(ctx)
	if err != nil {
		return nil, fmt.Errorf("rotate: mint new key: %w", err)
	}
	res := s.db.WithContext(ctx).
		Model(&ProviderKey{}).
		Where("status = ? AND id <> ?", StatusActive, newKey.ID).
		Update("status", StatusRotating)
	if res.Error != nil {
		_ = s.db.WithContext(ctx).Delete(&ProviderKey{}, newKey.ID).Error
		return nil, fmt.Errorf("rotate: demote previous active: %w", res.Error)
	}
	return newKey, nil
}

// MaybeRotate rotates only if the active key is older than every. Idempotent;
// drives the background auto-rotation ticker.
func (s *Service) MaybeRotate(ctx context.Context, every time.Duration) (bool, error) {
	active, err := s.activeKey(ctx)
	if err != nil {
		return false, err
	}
	if time.Since(active.CreatedAt) < every {
		return false, nil
	}
	if _, err := s.Rotate(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// RetireExpired marks ROTATING keys past their expires_at as RETIRED, dropping
// them from the JWKS. Safe to call on a cron; idempotent.
func (s *Service) RetireExpired(ctx context.Context) error {
	return s.db.WithContext(ctx).
		Model(&ProviderKey{}).
		Where("status = ? AND expires_at IS NOT NULL AND expires_at < NOW()", StatusRotating).
		Update("status", StatusRetired).Error
}

// LoadActiveSigningKey returns the active private key, its kid and algorithm.
func (s *Service) LoadActiveSigningKey(ctx context.Context) (*rsa.PrivateKey, string, string, error) {
	if s.masterKey == nil {
		return nil, "", "", ErrMasterKeyMissing
	}
	active, err := s.activeKey(ctx)
	if err != nil {
		return nil, "", "", err
	}
	plain, err := s.masterKey.Decrypt(active.PrivateKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("decrypt private key: %w", err)
	}
	priv, err := parseRSAPrivateKeyPEM(plain)
	if err != nil {
		return nil, "", "", err
	}
	return priv, active.KID, active.Algorithm, nil
}

// ListVerificationKeys returns the public keys to publish in the JWKS: every
// ACTIVE and ROTATING key. Malformed rows are skipped, not fatal.
func (s *Service) ListVerificationKeys(ctx context.Context) ([]VerificationKey, error) {
	var rows []ProviderKey
	err := s.db.WithContext(ctx).
		Where("status IN ?", []int{StatusActive, StatusRotating}).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list verification keys: %w", err)
	}
	out := make([]VerificationKey, 0, len(rows))
	for i := range rows {
		pub, err := parseRSAPublicKeyPEM([]byte(rows[i].PublicKey))
		if err != nil {
			continue
		}
		out = append(out, VerificationKey{KID: rows[i].KID, Algorithm: rows[i].Algorithm, Public: pub})
	}
	return out, nil
}

// activeKey loads the single active keyset row.
func (s *Service) activeKey(ctx context.Context) (*ProviderKey, error) {
	var key ProviderKey
	err := s.db.WithContext(ctx).
		Where("status = ?", StatusActive).
		Order("created_at DESC").
		First(&key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNoActiveKey
	}
	if err != nil {
		return nil, fmt.Errorf("load active key: %w", err)
	}
	return &key, nil
}

func parseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return priv, nil
}

func parseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pub, nil
}
