package oidckey

// Locks the "at most one ACTIVE key" invariant across EnsureActive and Rotate
// on sqlite (fast, driver-agnostic). This guards the transactional refactor of
// Rotate below: the happy path must never leave two committed-active rows, or
// the partial unique index added in migration 000053 would reject it on real
// Postgres. See rotation_pg_e2e_test.go for the concurrent-rotator version
// that actually exercises the Postgres index.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

func newTestOIDCKeyService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&ProviderKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mk, err := crypto.NewMasterKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("id gen: %v", err)
	}
	return NewService(db, idGen, mk)
}

func countActive(t *testing.T, s *Service) int64 {
	t.Helper()
	var n int64
	if err := s.db.Model(&ProviderKey{}).Where("status = ?", StatusActive).Count(&n).Error; err != nil {
		t.Fatalf("count active: %v", err)
	}
	return n
}

func TestRotate_AtMostOneActiveInvariant(t *testing.T) {
	ctx := context.Background()
	svc := newTestOIDCKeyService(t)

	first, err := svc.EnsureActive(ctx)
	if err != nil {
		t.Fatalf("ensure active: %v", err)
	}
	if got := countActive(t, svc); got != 1 {
		t.Fatalf("after EnsureActive: want 1 active, got %d", got)
	}

	second, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("rotate returned the same key as before")
	}

	if got := countActive(t, svc); got != 1 {
		t.Fatalf("after Rotate: want exactly 1 active, got %d", got)
	}

	// The new active must be `second`; the previous active must now be ROTATING.
	var reloadedSecond ProviderKey
	if err := svc.db.First(&reloadedSecond, second.ID).Error; err != nil {
		t.Fatalf("reload second: %v", err)
	}
	if reloadedSecond.Status != StatusActive {
		t.Fatalf("new key status = %d, want StatusActive", reloadedSecond.Status)
	}

	var reloadedFirst ProviderKey
	if err := svc.db.First(&reloadedFirst, first.ID).Error; err != nil {
		t.Fatalf("reload first: %v", err)
	}
	if reloadedFirst.Status != StatusRotating {
		t.Fatalf("previous active status = %d, want StatusRotating", reloadedFirst.Status)
	}

	// A second rotation must preserve the same invariant.
	third, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if third.ID == second.ID {
		t.Fatalf("second rotate returned the same key as before")
	}
	if got := countActive(t, svc); got != 1 {
		t.Fatalf("after second Rotate: want exactly 1 active, got %d", got)
	}
}
