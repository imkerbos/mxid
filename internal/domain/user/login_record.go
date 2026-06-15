package user

import (
	"context"
	"fmt"
	"time"
)

// LoginRecord captures one login attempt (success or failure). One row is
// written per /auth/login or /auth/mfa/verify call so admins can answer
// "did this user log in?", "from where?", "did their MFA work?".
//
// Stage values:
//   - "password" — first-factor result (LocalProvider.Authenticate)
//   - "mfa"      — second-factor result (Engine.VerifyMFAChallenge)
type LoginRecord struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID  int64     `gorm:"column:tenant_id;not null" json:"tenant_id,string"`
	UserID    *int64    `gorm:"column:user_id" json:"user_id,omitempty,string"`
	Username  *string   `gorm:"column:username;size:128" json:"username,omitempty"`
	Success   bool      `gorm:"column:success;not null" json:"success"`
	Stage     string    `gorm:"column:stage;not null;size:16;default:password" json:"stage"`
	AuthType  string    `gorm:"column:auth_type;not null;size:32" json:"auth_type"`
	Reason    *string   `gorm:"column:reason;size:256" json:"reason,omitempty"`
	IP        *string   `gorm:"column:ip;size:64" json:"ip,omitempty"`
	UserAgent *string   `gorm:"column:user_agent;size:512" json:"user_agent,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the postgres table name.
func (LoginRecord) TableName() string {
	return "mxid_login_record"
}

// TenantScoped marks mxid_login_record for automatic tenant isolation.
func (LoginRecord) TenantScoped() {}

// RecordLogin persists a single login attempt. Errors are returned but the
// caller (authn engine) treats them as non-fatal — losing one audit row must
// not block a legitimate login.
func (s *Service) RecordLogin(ctx context.Context, rec *LoginRecord) error {
	if rec.ID == 0 {
		rec.ID = s.idGen.Generate()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	if rec.Stage == "" {
		rec.Stage = "password"
	}
	return s.repo.CreateLoginRecord(ctx, rec)
}

// ListLoginRecords returns paginated login attempts for a user, newest first.
func (s *Service) ListLoginRecords(ctx context.Context, userID int64, page, pageSize int) ([]*LoginRecord, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	rows, total, err := s.repo.ListLoginRecords(ctx, userID, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list login records: %w", err)
	}
	if rows == nil {
		rows = []*LoginRecord{}
	}
	return rows, total, nil
}
