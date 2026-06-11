package approle

import (
	"context"
	"errors"
	"fmt"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

const EventAppRoleChanged = "app_role.changed"

type Service struct {
	repo     Repository
	idGen    *snowflake.Generator
	eventBus *event.Bus
}

func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{repo: repo, idGen: idGen, eventBus: eventBus}
}

/* ──────────────── Role CRUD ──────────────── */

type CreateRoleRequest struct {
	AppID       *int64
	AppGroupID  *int64
	TenantID    int64
	Code        string
	Name        string
	Description string
	IsDefault   bool
	SortOrder   int
	CreatedBy   *int64
}

func (s *Service) CreateRole(ctx context.Context, req CreateRoleRequest) (*AppRole, error) {
	if (req.AppID == nil) == (req.AppGroupID == nil) {
		return nil, errors.New("exactly one of app_id / app_group_id must be set")
	}
	if req.Code == "" {
		return nil, errors.New("code required")
	}
	if req.Name == "" {
		return nil, errors.New("name required")
	}
	r := &AppRole{
		ID:         s.idGen.Generate(),
		AppID:      req.AppID,
		AppGroupID: req.AppGroupID,
		TenantID:   req.TenantID,
		Code:       req.Code,
		Name:       req.Name,
		IsDefault:  req.IsDefault,
		SortOrder:  req.SortOrder,
		CreatedBy:  req.CreatedBy,
	}
	if req.Description != "" {
		r.Description = &req.Description
	}
	if err := s.repo.CreateRole(ctx, r); err != nil {
		return nil, err
	}
	s.publish(req.TenantID)
	return r, nil
}

type UpdateRoleRequest struct {
	ID          int64
	TenantID    int64
	Name        *string
	Description *string
	IsDefault   *bool
	SortOrder   *int
}

func (s *Service) UpdateRole(ctx context.Context, req UpdateRoleRequest) (*AppRole, error) {
	role, err := s.repo.GetRoleByID(ctx, req.ID, req.TenantID)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		desc := *req.Description
		role.Description = &desc
	}
	if req.IsDefault != nil {
		role.IsDefault = *req.IsDefault
	}
	if req.SortOrder != nil {
		role.SortOrder = *req.SortOrder
	}
	if err := s.repo.UpdateRole(ctx, role); err != nil {
		return nil, err
	}
	s.publish(role.TenantID)
	return role, nil
}

func (s *Service) DeleteRole(ctx context.Context, id, tenantID int64) error {
	if err := s.repo.DeleteRole(ctx, id, tenantID); err != nil {
		return err
	}
	s.publish(tenantID)
	return nil
}

func (s *Service) ListRoles(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*AppRole, error) {
	return s.repo.ListRoles(ctx, owner, ownerID, tenantID)
}

/* ──────────────── Bindings ──────────────── */

type AddBindingRequest struct {
	AppID       *int64
	AppGroupID  *int64
	TenantID    int64
	AppRoleID   int64
	SubjectType string
	SubjectID   int64
	CreatedBy   *int64
}

func (s *Service) AddBinding(ctx context.Context, req AddBindingRequest) (*Binding, error) {
	if (req.AppID == nil) == (req.AppGroupID == nil) {
		return nil, errors.New("exactly one of app_id / app_group_id must be set")
	}
	if !validSubject(req.SubjectType) {
		return nil, fmt.Errorf("invalid subject_type: %s", req.SubjectType)
	}
	if req.SubjectID == 0 {
		return nil, errors.New("subject_id required")
	}
	b := &Binding{
		ID:          s.idGen.Generate(),
		AppID:       req.AppID,
		AppGroupID:  req.AppGroupID,
		TenantID:    req.TenantID,
		AppRoleID:   req.AppRoleID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.repo.CreateBinding(ctx, b); err != nil {
		return nil, err
	}
	s.publish(req.TenantID)
	return b, nil
}

func (s *Service) DeleteBinding(ctx context.Context, id, tenantID int64) error {
	if err := s.repo.DeleteBinding(ctx, id, tenantID); err != nil {
		return err
	}
	s.publish(tenantID)
	return nil
}

func (s *Service) ListBindings(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*Binding, error) {
	return s.repo.ListBindings(ctx, owner, ownerID, tenantID)
}

// ListBindingsBySubject — used by user-group page reverse view.
func (s *Service) ListBindingsBySubject(ctx context.Context, subjectType string, subjectID, tenantID int64) ([]*Binding, error) {
	return s.repo.ListBindingsBySubject(ctx, subjectType, subjectID, tenantID)
}

/* ──────────────── Resolve for OIDC claim ──────────────── */

func (s *Service) ResolveCodes(ctx context.Context, userID, appID, tenantID int64) ([]string, error) {
	return s.repo.ResolveCodesForUser(ctx, userID, appID, tenantID)
}

// GetRole exposes the single-row fetch for handlers that need to
// enrich responses (e.g. reverse view rendering role name+code).
func (s *Service) GetRole(ctx context.Context, id, tenantID int64) (*AppRole, error) {
	return s.repo.GetRoleByID(ctx, id, tenantID)
}

// MemberAppIDs is a pass-through used by the app-group aggregation
// handler (group → list of member app ids).
func (s *Service) MemberAppIDs(ctx context.Context, groupID int64) ([]int64, error) {
	return s.repo.MemberAppIDs(ctx, groupID)
}

func (s *Service) publish(tenantID int64) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(context.Background(), event.Event{
		Type:    EventAppRoleChanged,
		Payload: map[string]any{"tenant_id": tenantID},
	})
}

func validSubject(s string) bool {
	switch s {
	case SubjectUser, SubjectGroup, SubjectOrg, SubjectRole:
		return true
	}
	return false
}
