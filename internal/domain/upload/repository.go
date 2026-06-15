package upload

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// ErrNotFound is returned when an id has no row.
var ErrNotFound = errors.New("upload: not found")

// Repository persists uploaded binary assets. Tenant-free like the table (see
// the package doc): serve is a pre-auth path with no tenant scope, and fetch is
// by non-enumerable Snowflake id.
type Repository interface {
	Save(ctx context.Context, u *Upload) error
	// Get returns the row including its bytes — used by the serve path.
	Get(ctx context.Context, id int64) (*Upload, error)
}

type repo struct{ db *gorm.DB }

// NewRepository wires the upload store onto the shared gorm handle.
func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

func (r *repo) Save(ctx context.Context, u *Upload) error {
	return r.db.WithContext(ctx).Create(u).Error
}

func (r *repo) Get(ctx context.Context, id int64) (*Upload, error) {
	var u Upload
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&u).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}
