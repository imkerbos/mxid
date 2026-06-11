package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

var (
	ErrTenantNotFound       = errors.New("tenant not found")
	ErrTenantCodeExists     = errors.New("tenant code already exists")
	ErrLicenseQuotaExceeded = errors.New("license tenant quota exceeded")
)

// LicenseQuotaCheck returns ErrLicenseQuotaExceeded when creating one more
// tenant would exceed the active license. nil = no quota.
type LicenseQuotaCheck func(ctx context.Context) error

// Service handles tenant CRUD.
type Service struct {
	repo         Repository
	idGen        *snowflake.Generator
	licenseQuota LicenseQuotaCheck
}

// NewService wires the service.
func NewService(repo Repository, idGen *snowflake.Generator) *Service {
	return &Service{repo: repo, idGen: idGen}
}

// SetLicenseQuotaCheck wires the runtime tenant-quota lookup.
func (s *Service) SetLicenseQuotaCheck(c LicenseQuotaCheck) { s.licenseQuota = c }

// CreateRequest is the request body for POST /tenants.
type CreateRequest struct {
	Name   string         `json:"name" binding:"required,max=128"`
	Code   string         `json:"code" binding:"required,max=64"`
	Status *int           `json:"status" binding:"omitempty,oneof=1 2"`
	Config map[string]any `json:"config"`
}

// UpdateRequest is the request body for PUT /tenants/:id.
type UpdateRequest struct {
	Name   *string        `json:"name" binding:"omitempty,max=128"`
	Status *int           `json:"status" binding:"omitempty,oneof=1 2"`
	Config map[string]any `json:"config"`
}

// Create persists a new tenant. Code must be globally unique.
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*Tenant, error) {
	if s.licenseQuota != nil {
		if err := s.licenseQuota(ctx); err != nil {
			return nil, err
		}
	}
	if _, err := s.repo.GetByCode(ctx, req.Code); err == nil {
		return nil, ErrTenantCodeExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("check code: %w", err)
	}

	cfg := datatypes.JSON([]byte("{}"))
	if req.Config != nil {
		raw, err := json.Marshal(req.Config)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		cfg = datatypes.JSON(raw)
	}
	status := StatusEnabled
	if req.Status != nil {
		status = *req.Status
	}
	t := &Tenant{
		ID:     s.idGen.Generate(),
		Name:   req.Name,
		Code:   req.Code,
		Status: status,
		Config: cfg,
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// Get returns a tenant by ID.
func (s *Service) Get(ctx context.Context, id int64) (*Tenant, error) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	return t, nil
}

// GetByCode returns a tenant by code (used by portal `?tenant=` lookup).
func (s *Service) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t, err := s.repo.GetByCode(ctx, code)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	return t, nil
}

// Update patches a tenant. Code is immutable.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateRequest) (*Tenant, error) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	if req.Name != nil {
		t.Name = *req.Name
	}
	if req.Status != nil {
		t.Status = *req.Status
	}
	if req.Config != nil {
		raw, err := json.Marshal(req.Config)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		t.Config = datatypes.JSON(raw)
	}
	if err := s.repo.Update(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// Delete removes a tenant. id=1 (default) is protected at the repo layer.
func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

// List returns every tenant. super_admin only.
func (s *Service) List(ctx context.Context) ([]*Tenant, error) {
	return s.repo.List(ctx)
}
