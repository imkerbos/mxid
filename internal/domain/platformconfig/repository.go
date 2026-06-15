package platformconfig

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrNotFound is returned when a key has no row.
var ErrNotFound = errors.New("platformconfig: not found")

// Repository is the raw KV store. Deliberately context-passing but tenant-free:
// the table is not tenant-scoped, so these queries never touch the tenantscope
// plugin and work at boot with a bare context.
type Repository interface {
	Get(ctx context.Context, key string) (*PlatformConfig, error)
	Upsert(ctx context.Context, key string, value []byte) error
}

type repo struct{ db *gorm.DB }

// NewRepository wires the platform-config store onto the shared gorm handle.
func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

func (r *repo) Get(ctx context.Context, key string) (*PlatformConfig, error) {
	var c PlatformConfig
	err := r.db.WithContext(ctx).Where("key = ?", key).First(&c).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (r *repo) Upsert(ctx context.Context, key string, value []byte) error {
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{
			"value":      value,
			"updated_at": gorm.Expr("now()"),
		}),
	}).Create(&PlatformConfig{Key: key, Value: value}).Error
}
