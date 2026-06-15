package tenant

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// Repository persists Tenant rows.
type Repository interface {
	Create(ctx context.Context, t *Tenant) error
	GetByID(ctx context.Context, id int64) (*Tenant, error)
	GetByCode(ctx context.Context, code string) (*Tenant, error)
	Update(ctx context.Context, t *Tenant) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context) ([]*Tenant, error)
}

type repository struct{ db *gorm.DB }

// NewRepository builds a gorm-backed Repository.
func NewRepository(db *gorm.DB) Repository { return &repository{db: db} }

func (r *repository) Create(ctx context.Context, t *Tenant) error {
	if err := r.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	return nil
}

func (r *repository) GetByID(ctx context.Context, id int64) (*Tenant, error) {
	var t Tenant
	if err := r.db.WithContext(ctx).First(&t, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *repository) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	var t Tenant
	if err := r.db.WithContext(ctx).Where("code = ?", code).First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *repository) Update(ctx context.Context, t *Tenant) error {
	if err := r.db.WithContext(ctx).Save(t).Error; err != nil {
		return fmt.Errorf("update tenant: %w", err)
	}
	return nil
}

func (r *repository) Delete(ctx context.Context, id int64) error {
	if id == 1 {
		// Default tenant is the platform anchor — never delete.
		return fmt.Errorf("default tenant (id=1) cannot be deleted")
	}
	if err := r.db.WithContext(ctx).Delete(&Tenant{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	return nil
}

func (r *repository) List(ctx context.Context) ([]*Tenant, error) {
	out := make([]*Tenant, 0)
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return out, nil
}
