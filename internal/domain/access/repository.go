package access

import (
	"context"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Repository is the raw storage layer for JIT access eligibility and requests.
type Repository interface {
	// Eligibility CRUD.
	CreateEligibility(ctx context.Context, e *Eligibility) error
	GetEligibility(ctx context.Context, id, tenantID int64) (*Eligibility, error)
	ListEligibility(ctx context.Context, tenantID int64) ([]*Eligibility, error)
	DeleteEligibility(ctx context.Context, id, tenantID int64) error

	// Request CRUD.
	CreateRequest(ctx context.Context, r *Request) error
	GetRequest(ctx context.Context, id, tenantID int64) (*Request, error)
	ListRequestsByStatus(ctx context.Context, tenantID int64, status string) ([]*Request, error)
	ListRequestsByRequester(ctx context.Context, requesterID, tenantID int64) ([]*Request, error)

	// ApproveAndGrant atomically: inserts a time-bound binding row into the
	// correct table (branching on req.TargetKind) and marks the request
	// approved with binding_id/expires_at set. Returns error if either step
	// fails (full rollback).
	ApproveAndGrant(ctx context.Context, req *Request, approverID int64, expiresAt time.Time, newBindingID int64) error

	// UpdateRequestStatus is a lightweight status transition for reject/cancel
	// flows that do not touch a binding.
	UpdateRequestStatus(ctx context.Context, id, tenantID int64, status, reason string, approverID *int64) error

	// EndGrant atomically hard-deletes the binding row from the correct table
	// and transitions the request to finalStatus (revoked or expired).
	EndGrant(ctx context.Context, req *Request, finalStatus string, bindingStatus int) error

	// ListDueGrants returns approved requests whose expires_at <= NOW().
	// The sweeper uses this list to call EndGrant on each entry.
	ListDueGrants(ctx context.Context) ([]*Request, error)
}

type repo struct {
	db    *gorm.DB
	idGen *snowflake.Generator
}

// NewRepository constructs a Repository backed by db.
func NewRepository(db *gorm.DB, idGen *snowflake.Generator) Repository {
	return &repo{db: db, idGen: idGen}
}

// ─── Eligibility ──────────────────────────────────────────────────────────────

func (r *repo) CreateEligibility(ctx context.Context, e *Eligibility) error {
	return r.db.WithContext(ctx).Create(e).Error
}

func (r *repo) GetEligibility(ctx context.Context, id, tenantID int64) (*Eligibility, error) {
	var e Eligibility
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&e).Error
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *repo) ListEligibility(ctx context.Context, tenantID int64) ([]*Eligibility, error) {
	var rows []*Eligibility
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) DeleteEligibility(ctx context.Context, id, tenantID int64) error {
	return r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		Delete(&Eligibility{}).Error
}

// ─── Request ──────────────────────────────────────────────────────────────────

func (r *repo) CreateRequest(ctx context.Context, req *Request) error {
	return r.db.WithContext(ctx).Create(req).Error
}

func (r *repo) GetRequest(ctx context.Context, id, tenantID int64) (*Request, error) {
	var req Request
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&req).Error
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func (r *repo) ListRequestsByStatus(ctx context.Context, tenantID int64, status string) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND status = ?", tenantID, status).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) ListRequestsByRequester(ctx context.Context, requesterID, tenantID int64) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("requester_id = ? AND tenant_id = ?", requesterID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

// ─── Grant operations ─────────────────────────────────────────────────────────

// bindingTable returns the backing table name for the given target kind.
func (r *repo) bindingTable(kind string) string {
	if kind == TargetApp {
		return "mxid_app_role_binding"
	}
	return "mxid_role_binding"
}

// insertBindingTx inserts the time-bound binding inside tx.
//
// mxid_role_binding columns (verified, migration 000006 + 000016 + 000045):
//
//	id, role_id, subject_type, subject_id, scope_type, scope_id,
//	grant_id, expires_at, status, created_at
//
// mxid_app_role_binding columns (verified, migration 000026 + 000027 + 000045):
//
//	id, app_id, tenant_id, app_role_id, subject_type, subject_id,
//	app_group_id (nullable), grant_id, expires_at, status, created_at, created_by
//
// For the app binding we omit app_group_id so the CHECK constraint
// (app_id IS NOT NULL AND app_group_id IS NULL) is satisfied.
func (r *repo) insertBindingTx(tx *gorm.DB, req *Request, bindingID int64, expiresAt time.Time) error {
	switch req.TargetKind {
	case TargetConsole:
		return tx.Exec(`
INSERT INTO mxid_role_binding
    (id, role_id, subject_type, subject_id, scope_type, scope_id, grant_id, expires_at, status, created_at)
VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?, NOW())`,
			bindingID,
			req.RoleID,
			req.RequesterID,
			req.ScopeType,
			req.ScopeID,
			req.ID,
			expiresAt,
			BindingActive,
		).Error

	case TargetApp:
		if req.AppID == nil {
			return fmt.Errorf("access: app_id is required for TargetApp grant")
		}
		return tx.Exec(`
INSERT INTO mxid_app_role_binding
    (id, app_id, app_role_id, subject_type, subject_id, tenant_id, grant_id, expires_at, status, created_at)
VALUES (?, ?, ?, 'user', ?, ?, ?, ?, ?, NOW())`,
			bindingID,
			*req.AppID,
			req.RoleID,
			req.RequesterID,
			req.TenantID,
			req.ID,
			expiresAt,
			BindingActive,
		).Error

	default:
		return fmt.Errorf("access: unknown target_kind %q", req.TargetKind)
	}
}

// ApproveAndGrant runs in ONE transaction:
//  1. INSERT the time-bound binding row.
//  2. UPDATE the request to approved with binding_id/expires_at/activated_at/decided_at.
func (r *repo) ApproveAndGrant(ctx context.Context, req *Request, approverID int64, expiresAt time.Time, newBindingID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := r.insertBindingTx(tx, req, newBindingID, expiresAt); err != nil {
			return err
		}
		return tx.Exec(`
UPDATE mxid_access_request
SET status = ?, approver_id = ?, decided_at = ?, activated_at = ?, expires_at = ?, binding_id = ?, updated_at = NOW()
WHERE id = ? AND tenant_id = ? AND status = ?`,
			StatusApproved,
			approverID,
			now,
			now,
			expiresAt,
			newBindingID,
			req.ID,
			req.TenantID,
			StatusPending,
		).Error
	})
}

// UpdateRequestStatus is a lightweight transition for reject/cancel flows that
// do not involve a binding (no tx needed).
func (r *repo) UpdateRequestStatus(ctx context.Context, id, tenantID int64, status, reason string, approverID *int64) error {
	return r.db.WithContext(ctx).Exec(`
UPDATE mxid_access_request
SET status = ?, decision_reason = ?, approver_id = COALESCE(?, approver_id), decided_at = NOW(), updated_at = NOW()
WHERE id = ? AND tenant_id = ?`,
		status, reason, approverID, id, tenantID,
	).Error
}

// EndGrant runs in ONE transaction:
//  1. Hard-DELETE the binding row from the correct table.
//  2. UPDATE the request to finalStatus.
func (r *repo) EndGrant(ctx context.Context, req *Request, finalStatus string, _ int) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if req.BindingID != nil {
			table := r.bindingTable(req.TargetKind)
			// Use Sprintf for table name — safe because bindingTable only ever
			// returns one of two hard-coded strings; no user input reaches here.
			if err := tx.Exec(
				fmt.Sprintf("DELETE FROM %s WHERE id = ?", table), //nolint:gosec
				*req.BindingID,
			).Error; err != nil {
				return err
			}
		}
		return tx.Exec(`
UPDATE mxid_access_request SET status = ?, updated_at = NOW()
WHERE id = ? AND tenant_id = ?`,
			finalStatus, req.ID, req.TenantID,
		).Error
	})
}

// ListDueGrants returns approved requests whose expires_at <= NOW().
// The sweeper calls EndGrant on each.
func (r *repo) ListDueGrants(ctx context.Context) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("status = ? AND expires_at IS NOT NULL AND expires_at <= NOW()", StatusApproved).
		Find(&rows).Error
	return rows, err
}
