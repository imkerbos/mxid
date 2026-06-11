package externalidp

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// Repository persists ExternalIDP rows.
type Repository interface {
	Create(ctx context.Context, idp *ExternalIDP) error
	GetByID(ctx context.Context, id int64) (*ExternalIDP, error)
	GetByCode(ctx context.Context, tenantID int64, code string) (*ExternalIDP, error)
	Update(ctx context.Context, idp *ExternalIDP) error
	Delete(ctx context.Context, id int64) error
	// List returns the IdPs for a tenant, optionally filtered to enabled only.
	List(ctx context.Context, tenantID int64, enabledOnly bool) ([]*ExternalIDP, error)
}

type repository struct{ db *gorm.DB }

// NewRepository builds a Repository backed by gorm.
func NewRepository(db *gorm.DB) Repository { return &repository{db: db} }

func (r *repository) Create(ctx context.Context, idp *ExternalIDP) error {
	if err := r.db.WithContext(ctx).Create(idp).Error; err != nil {
		return fmt.Errorf("create idp: %w", err)
	}
	return nil
}

func (r *repository) GetByID(ctx context.Context, id int64) (*ExternalIDP, error) {
	var idp ExternalIDP
	if err := r.db.WithContext(ctx).First(&idp, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &idp, nil
}

func (r *repository) GetByCode(ctx context.Context, tenantID int64, code string) (*ExternalIDP, error) {
	var idp ExternalIDP
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&idp).Error; err != nil {
		return nil, err
	}
	return &idp, nil
}

func (r *repository) Update(ctx context.Context, idp *ExternalIDP) error {
	if err := r.db.WithContext(ctx).Save(idp).Error; err != nil {
		return fmt.Errorf("update idp: %w", err)
	}
	return nil
}

func (r *repository) Delete(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Delete(&ExternalIDP{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("delete idp: %w", err)
	}
	return nil
}

func (r *repository) List(ctx context.Context, tenantID int64, enabledOnly bool) ([]*ExternalIDP, error) {
	q := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)
	if enabledOnly {
		q = q.Where("status = ?", StatusEnabled)
	}
	out := make([]*ExternalIDP, 0)
	if err := q.Order("sort_order ASC, created_at ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list idp: %w", err)
	}
	return out, nil
}
