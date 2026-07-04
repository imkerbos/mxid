package apitoken

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	// TokenPrefix marks every PAT plaintext. Secret scanners (GitHub,
	// GitGuardian, etc) pattern-match this without false positives.
	TokenPrefix = "mxidpat_"
	// 32 random bytes → 26 base32 chars. We use the full 26 chars after
	// the prefix so the token has ~130 bits of entropy.
	tokenSecretBytes = 16 // 16 raw bytes → 26 base32 chars (≈128 bits)
	// Indexed prefix used for fast lookup. NOT secret; equals the first
	// 8 chars of the SECRET part of the token (after TokenPrefix).
	lookupPrefixLen = 8
)

// Errors
var (
	ErrNotFound = errors.New("api token not found")
	ErrInvalid  = errors.New("invalid api token")
	ErrExpired  = errors.New("api token expired")
	ErrRevoked  = errors.New("api token revoked")
)

// Repository abstracts persistence.
type Repository interface {
	Create(ctx context.Context, t *Token) error
	ListByUser(ctx context.Context, userID int64) ([]*Token, error)
	GetByID(ctx context.Context, id int64) (*Token, error)
	GetByPrefix(ctx context.Context, prefix string) ([]*Token, error)
	Revoke(ctx context.Context, id int64, when time.Time) error
	TouchLastUsed(ctx context.Context, id int64, when time.Time) error
}

type repo struct{ db *gorm.DB }

// NewRepository builds a gorm-backed token repo.
func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

func (r *repo) Create(ctx context.Context, t *Token) error {
	return r.db.WithContext(ctx).Create(t).Error
}

func (r *repo) ListByUser(ctx context.Context, userID int64) ([]*Token, error) {
	var rows []*Token
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) GetByID(ctx context.Context, id int64) (*Token, error) {
	var t Token
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&t).Error
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

func (r *repo) GetByPrefix(ctx context.Context, prefix string) ([]*Token, error) {
	var rows []*Token
	err := r.db.WithContext(ctx).
		Where("prefix = ? AND revoked_at IS NULL", prefix).
		Find(&rows).Error
	return rows, err
}

func (r *repo) Revoke(ctx context.Context, id int64, when time.Time) error {
	return r.db.WithContext(ctx).
		Model(&Token{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", when).Error
}

func (r *repo) TouchLastUsed(ctx context.Context, id int64, when time.Time) error {
	return r.db.WithContext(ctx).
		Model(&Token{}).
		Where("id = ?", id).
		Update("last_used_at", when).Error
}

// Service is the public surface for handlers + the bearer middleware.
type Service struct {
	repo  Repository
	idGen *snowflake.Generator
}

// NewService builds a Service.
func NewService(repo Repository, idGen *snowflake.Generator) *Service {
	return &Service{repo: repo, idGen: idGen}
}

// CreateInput specifies a new token's metadata.
type CreateInput struct {
	UserID    int64
	TenantID  int64
	Name      string
	Scopes    []string
	ExpiresIn time.Duration // 0 = no expiry
}

// CreateResult bundles the persisted row with the one-shot plaintext.
type CreateResult struct {
	Token     *Token
	Plaintext string
}

// Create mints a fresh token. Plaintext is returned ONCE; callers must
// surface it to the user before the response is dropped.
func (s *Service) Create(ctx context.Context, in CreateInput) (*CreateResult, error) {
	plain, secret, err := newPlaintext()
	if err != nil {
		return nil, fmt.Errorf("generate plaintext: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash token: %w", err)
	}
	scopesJSON, err := json.Marshal(normalizeScopes(in.Scopes))
	if err != nil {
		return nil, fmt.Errorf("marshal scopes: %w", err)
	}
	now := time.Now()
	t := &Token{
		ID:        s.idGen.Generate(),
		TenantID:  in.TenantID,
		UserID:    in.UserID,
		Name:      strings.TrimSpace(in.Name),
		Prefix:    secret[:lookupPrefixLen],
		TokenHash: string(hash),
		Scopes:    datatypes.JSON(scopesJSON),
		CreatedAt: now,
	}
	if in.ExpiresIn > 0 {
		exp := now.Add(in.ExpiresIn)
		t.ExpiresAt = &exp
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("persist token: %w", err)
	}
	return &CreateResult{Token: t, Plaintext: plain}, nil
}

// ListByUser returns the user's tokens (active + revoked, ordered desc).
func (s *Service) ListByUser(ctx context.Context, userID int64) ([]*Token, error) {
	return s.repo.ListByUser(ctx, userID)
}

// Revoke marks the token revoked. Idempotent.
func (s *Service) Revoke(ctx context.Context, userID, tokenID int64) error {
	t, err := s.repo.GetByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if t.UserID != userID {
		return ErrNotFound // tenant/user scoping enforced; don't leak existence
	}
	if t.RevokedAt != nil {
		return nil
	}
	return s.repo.Revoke(ctx, tokenID, time.Now())
}

// Authenticate parses a plaintext token (with or without "Bearer " prefix),
// looks it up, validates expiry + revocation, and returns the row. The
// token's LastUsedAt is bumped on success; failures don't touch the DB so
// brute-force attempts don't generate log noise.
func (s *Service) Authenticate(ctx context.Context, plaintext string) (*Token, error) {
	plaintext = strings.TrimSpace(plaintext)
	plaintext = strings.TrimPrefix(plaintext, "Bearer ")
	plaintext = strings.TrimPrefix(plaintext, "bearer ")
	if !strings.HasPrefix(plaintext, TokenPrefix) {
		return nil, ErrInvalid
	}
	secret := plaintext[len(TokenPrefix):]
	if len(secret) < lookupPrefixLen {
		return nil, ErrInvalid
	}
	prefix := secret[:lookupPrefixLen]
	// The PAT is identified by a globally-unique prefix with no tenant known
	// yet — the token row YIELDS the tenant. So the lookup + last-used touch
	// run as an explicit cross-tenant read (the middleware then pins the
	// resolved tenant for the rest of the request).
	ctx = tenantscope.WithCrossTenant(ctx)
	candidates, err := s.repo.GetByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for _, t := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(t.TokenHash), []byte(secret)) == nil {
			now := time.Now()
			if !t.IsActive(now) {
				if t.RevokedAt != nil {
					return nil, ErrRevoked
				}
				return nil, ErrExpired
			}
			_ = s.repo.TouchLastUsed(ctx, t.ID, now)
			return t, nil
		}
	}
	return nil, ErrInvalid
}

// ScopesOf decodes the JSON scope array out of the row. Always returns a
// non-nil slice so callers iterate without nil checks.
func ScopesOf(t *Token) []string {
	if len(t.Scopes) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(t.Scopes, &out); err != nil {
		return []string{}
	}
	return out
}

// newPlaintext returns ("mxidpat_<base32>", "<base32>", nil). The secret
// half (returned separately) is what we hash + index by prefix.
func newPlaintext() (full, secret string, err error) {
	b := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return TokenPrefix + secret, secret, nil
}

// normalizeScopes dedupes + sorts so the JSON column stays canonical.
func normalizeScopes(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
