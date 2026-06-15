package conditionalaccess

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type gormDeviceRepo struct{ db *gorm.DB }

// NewGormDeviceRepo is the production DeviceRepo backed by GORM.
func NewGormDeviceRepo(db *gorm.DB) DeviceRepo { return &gormDeviceRepo{db: db} }

func (r *gormDeviceRepo) Get(ctx context.Context, userID int64, deviceID string) (*KnownDevice, error) {
	var d KnownDevice
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND device_id = ?", userID, deviceID).
		First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *gormDeviceRepo) Insert(ctx context.Context, d *KnownDevice) error {
	return r.db.WithContext(ctx).Create(d).Error
}

func (r *gormDeviceRepo) TouchLastSeen(ctx context.Context, id int64, at time.Time) error {
	return r.db.WithContext(ctx).
		Model(&KnownDevice{}).
		Where("id = ?", id).
		Update("last_seen_at", at).Error
}
