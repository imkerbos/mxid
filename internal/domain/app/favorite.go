package app

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserAppFavorite represents one pinned app on a portal user's home page.
// Sort order is user-driven via drag-and-drop; created_at breaks ties so
// new pins land at the bottom of the same-sort group.
type UserAppFavorite struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	TenantID  int64     `gorm:"column:tenant_id;not null" json:"tenant_id"`
	UserID    int64     `gorm:"column:user_id;not null" json:"user_id"`
	AppID     int64     `gorm:"column:app_id;not null" json:"app_id"`
	SortOrder int       `gorm:"column:sort_order;not null;default:0" json:"sort_order"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the favorite table name.
func (UserAppFavorite) TableName() string {
	return "mxid_user_app_favorite"
}

// FavoriteRepository abstracts the per-user pinned-app storage.
type FavoriteRepository interface {
	Add(ctx context.Context, fav *UserAppFavorite) error
	Remove(ctx context.Context, userID, appID int64) error
	ListAppIDs(ctx context.Context, userID int64) ([]int64, error)
	// Reorder rewrites sort_order so favorites display in the given app_id
	// order. App IDs not currently favorited are skipped silently — the UI
	// may submit a stale list racing with concurrent (un)favorites and we
	// don't want a 500 in that case. Returns the number of rows updated.
	Reorder(ctx context.Context, userID int64, orderedAppIDs []int64) (int, error)
}

type favoriteRepo struct {
	db *gorm.DB
}

// NewFavoriteRepository builds a gorm-backed favorite repository.
func NewFavoriteRepository(db *gorm.DB) FavoriteRepository {
	return &favoriteRepo{db: db}
}

// Add inserts a favorite. Conflict on (user_id, app_id) is a no-op so the
// caller can fire-and-forget without checking existence first.
func (r *favoriteRepo) Add(ctx context.Context, fav *UserAppFavorite) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "user_id"}, {Name: "app_id"}}, DoNothing: true}).
		Create(fav).Error
}

// Remove deletes a single (user, app) favorite row. Missing row = nil.
func (r *favoriteRepo) Remove(ctx context.Context, userID, appID int64) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND app_id = ?", userID, appID).
		Delete(&UserAppFavorite{}).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}

// ListAppIDs returns the user's favorite app IDs ordered for portal display.
func (r *favoriteRepo) ListAppIDs(ctx context.Context, userID int64) ([]int64, error) {
	var ids []int64
	err := r.db.WithContext(ctx).
		Model(&UserAppFavorite{}).
		Where("user_id = ?", userID).
		Order("sort_order ASC, created_at ASC").
		Pluck("app_id", &ids).Error
	return ids, err
}

// Reorder bulk-updates sort_order so the favorites render in the supplied
// app-id order. Runs as a single transaction with one UPDATE per app — N
// is small (~tens) so we don't bother with a single VALUES batch.
func (r *favoriteRepo) Reorder(ctx context.Context, userID int64, orderedAppIDs []int64) (int, error) {
	if len(orderedAppIDs) == 0 {
		return 0, nil
	}
	updated := 0
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i, appID := range orderedAppIDs {
			res := tx.Model(&UserAppFavorite{}).
				Where("user_id = ? AND app_id = ?", userID, appID).
				Update("sort_order", i)
			if res.Error != nil {
				return res.Error
			}
			updated += int(res.RowsAffected)
		}
		return nil
	})
	return updated, err
}
