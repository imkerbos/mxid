package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// is_first_party records whether the organization owns the application. The
// flag has no reader yet, so storing it wrong changes no decision today — it
// changes what every existing row says on the day one is added, which is the
// kind of defect that is only ever found afterwards.
//
// The model carried a `default:true` gorm tag, and GORM treats a field holding
// the Go zero value as "not supplied" when it has a default: the column was
// dropped from the INSERT and the database default won. Same root cause as the
// external-IdP auto_create defect, where the flag DOES decide something.
//
// Written against GORM rather than the struct tag, because the tag is not the
// behaviour — what reaches the table is.
func TestCreateApp_PersistsIsFirstPartyFalse(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&App{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	repo := NewGormRepository(db)
	tenantID := int64(1)
	a := &App{
		ID: 1, TenantID: &tenantID, Name: "Third party", Code: "third-party",
		Protocol: "oidc", Status: 1, ProtocolConfig: json.RawMessage(`{}`), RedirectURIs: json.RawMessage(`[]`),
		IsFirstParty: false,
	}
	if err := repo.Create(context.Background(), a); err != nil {
		t.Fatalf("create: %v", err)
	}

	var got App
	if err := db.First(&got, a.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.IsFirstParty {
		t.Fatal("is_first_party stored as true although the app was registered as third-party — the administrator's choice did not reach the table")
	}
}
