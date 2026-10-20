package user

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// Stage says which step of a login the row describes ("password", "mfa", or
// "login" for a federated sign-in that has no separate steps). A caller that
// forgets to set it must produce a visibly empty value, not a plausible one:
// the field carried a `default:password` gorm tag, and GORM drops a field
// holding the zero value from the INSERT when it has a default, so an unset
// Stage would have been filed as a local password login. Nothing about such a
// row looks wrong, which is what makes it worse than a missing value.
func TestCreateLoginRecord_DoesNotInventAStage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&LoginRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	repo := NewGormRepository(db)
	rec := &LoginRecord{
		ID: 1, TenantID: 1, Success: true, AuthType: "teams",
		CreatedAt: time.Now().UTC(),
		// Stage deliberately left unset.
	}
	if err := repo.CreateLoginRecord(context.Background(), rec); err != nil {
		t.Fatalf("create: %v", err)
	}

	var got LoginRecord
	if err := db.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Stage != "" {
		t.Fatalf("stage stored as %q for a record that set none — an unlabelled login was filed as that stage", got.Stage)
	}
}

// The ordinary case: a stage that IS supplied survives verbatim.
func TestCreateLoginRecord_KeepsFederatedStage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&LoginRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	repo := NewGormRepository(db)
	rec := &LoginRecord{
		ID: 2, TenantID: 1, Success: true, AuthType: "teams", Stage: "login",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateLoginRecord(context.Background(), rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	var got LoginRecord
	if err := db.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Stage != "login" {
		t.Fatalf("stage = %q, want %q", got.Stage, "login")
	}
}
