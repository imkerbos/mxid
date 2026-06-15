package setting

import (
	"context"
	"strings"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Repository provides raw DB access for mxid_setting.
type Repository interface {
	Get(ctx context.Context, key string, tenantID int64) (*Setting, error)
	Upsert(ctx context.Context, s *Setting) error
	List(ctx context.Context, tenantID int64) ([]*Setting, error)
	Delete(ctx context.Context, key string, tenantID int64) error
}

type repo struct {
	db    *gorm.DB
	idGen *snowflake.Generator
}

// NewRepository builds the repo. idGen may be nil for read-only callers
// (e.g. tests); Upsert lazily creates one if missing.
func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

// NewRepositoryWithIDGen lets callers reuse the app-wide snowflake gen so
// new setting rows get globally unique IDs.
func NewRepositoryWithIDGen(db *gorm.DB, idGen *snowflake.Generator) Repository {
	return &repo{db: db, idGen: idGen}
}

func (r *repo) Get(ctx context.Context, key string, tenantID int64) (*Setting, error) {
	var s Setting
	err := r.db.WithContext(ctx).
		Where("key = ? AND tenant_id = ?", key, tenantID).
		First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *repo) Upsert(ctx context.Context, s *Setting) error {
	// Derive category from the key prefix ("security.policy" → "security")
	// because the schema's NOT NULL category column was never wired
	// through the typed accessors. Snowflake ID lazily generated when
	// not provided.
	category := s.Key
	if i := strings.IndexByte(s.Key, '.'); i > 0 {
		category = s.Key[:i]
	}
	var id int64
	if r.idGen != nil {
		id = r.idGen.Generate()
	} else {
		// Repo built without an idGen — derive deterministically so
		// the row maps 1:1 to (key, tenant) and re-upserts keep the
		// same PK rather than spawning duplicates.
		id = stableID(s.Key, s.TenantID)
	}
	return r.db.WithContext(ctx).Exec(`
		INSERT INTO mxid_setting (id, tenant_id, category, key, value, updated_at)
		VALUES (?, ?, ?, ?, ?, NOW())
		ON CONFLICT (tenant_id, category, key) DO UPDATE
		SET value = EXCLUDED.value, updated_at = NOW()
	`, id, s.TenantID, category, s.Key, s.Value).Error
}

// stableID returns a deterministic int64 so repos built without an idGen
// (tests) can still write. Avoids `id=0` PK collisions while keeping
// idempotency: same (key, tenant) → same id every call.
func stableID(key string, tenantID int64) int64 {
	var h uint64 = 14695981039346656037 // FNV-1a 64-bit offset basis
	for _, b := range []byte(key) {
		h ^= uint64(b)
		h *= 1099511628211 // FNV prime
	}
	h ^= uint64(tenantID)
	out := int64(h >> 1) // strip sign bit
	if out == 0 {
		out = 1
	}
	return out
}

func (r *repo) List(ctx context.Context, tenantID int64) ([]*Setting, error) {
	var settings []*Setting
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("key").
		Find(&settings).Error
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func (r *repo) Delete(ctx context.Context, key string, tenantID int64) error {
	return r.db.WithContext(ctx).
		Where("key = ? AND tenant_id = ?", key, tenantID).
		Delete(&Setting{}).Error
}
