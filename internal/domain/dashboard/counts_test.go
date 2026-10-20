package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// countsDB builds the handful of tables fillCounts reads. Raw DDL rather than
// AutoMigrate: these queries go through .Table(), so what matters is the shape
// of the table, and the models live in packages this one must not import.
func countsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE mxid_user (id INTEGER PRIMARY KEY, tenant_id INTEGER, status INTEGER, created_at DATETIME, deleted_at DATETIME)`,
		`CREATE TABLE mxid_user_mfa (id INTEGER PRIMARY KEY, user_id INTEGER, verified BOOLEAN)`,
		`CREATE TABLE mxid_app (id INTEGER PRIMARY KEY, tenant_id INTEGER, protocol TEXT, deleted_at DATETIME)`,
		`CREATE TABLE mxid_organization (id INTEGER PRIMARY KEY, tenant_id INTEGER, deleted_at DATETIME)`,
		`CREATE TABLE mxid_user_group (id INTEGER PRIMARY KEY, tenant_id INTEGER, deleted_at DATETIME)`,
		`CREATE TABLE mxid_external_idp (id INTEGER PRIMARY KEY, tenant_id INTEGER, deleted_at DATETIME)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("ddl: %v", err)
		}
	}
	return db
}

// MFA coverage is "of the people who could sign in, how many hold a second
// factor". The numerator counted every non-deleted user with a factor while
// the denominator counted only ACTIVE ones, so a disabled account that had
// enrolled padded the numerator alone and the dashboard reported over 100% —
// a figure that is not merely wrong but visibly impossible.
func TestFillCounts_MFACoverageCannotExceedOne(t *testing.T) {
	db := countsDB(t)
	now := time.Now().UTC()
	// Two active users, one of them enrolled.
	db.Exec(`INSERT INTO mxid_user (id, tenant_id, status, created_at) VALUES (1,1,1,?),(2,1,1,?)`, now, now)
	// A disabled user who is also enrolled: countable, but cannot sign in.
	db.Exec(`INSERT INTO mxid_user (id, tenant_id, status, created_at) VALUES (3,1,3,?)`, now)
	db.Exec(`INSERT INTO mxid_user_mfa (id, user_id, verified) VALUES (1,1,true),(2,3,true)`)

	var c Counts
	s := NewService(db)
	if err := s.fillCounts(context.Background(), 1, now.Add(-24*time.Hour), &c); err != nil {
		t.Fatalf("fillCounts: %v", err)
	}

	if c.UsersActive != 2 {
		t.Fatalf("UsersActive = %d, want 2", c.UsersActive)
	}
	if c.MFAEnrolled != 1 {
		t.Errorf("MFAEnrolled = %d, want 1 — a disabled account was counted as covered", c.MFAEnrolled)
	}
	if c.MFACoverage > 1 {
		t.Errorf("MFACoverage = %.3f, which is impossible: the numerator counts people the denominator does not", c.MFACoverage)
	}
	if c.MFACoverage != 0.5 {
		t.Errorf("MFACoverage = %.3f, want 0.5", c.MFACoverage)
	}
}

// Apps, organizations, groups and identity sources are soft-deleted, and these
// are .Table() lookups — GORM's soft-delete scope keys off the model type, so
// it does not apply and a deleted row keeps counting until excluded by hand.
// An operator reading "3 identity sources" after deleting two of them has no
// way to tell the figure is stale.
func TestFillCounts_ExcludesSoftDeletedEntities(t *testing.T) {
	db := countsDB(t)
	now := time.Now().UTC()
	gone := now.Add(-time.Hour)

	db.Exec(`INSERT INTO mxid_app (id, tenant_id, protocol, deleted_at) VALUES (1,1,'oidc',NULL),(2,1,'saml',?)`, gone)
	db.Exec(`INSERT INTO mxid_organization (id, tenant_id, deleted_at) VALUES (1,1,NULL),(2,1,?)`, gone)
	db.Exec(`INSERT INTO mxid_user_group (id, tenant_id, deleted_at) VALUES (1,1,NULL),(2,1,?)`, gone)
	db.Exec(`INSERT INTO mxid_external_idp (id, tenant_id, deleted_at) VALUES (1,1,NULL),(2,1,?),(3,1,?)`, gone, gone)

	var c Counts
	s := NewService(db)
	if err := s.fillCounts(context.Background(), 1, now.Add(-24*time.Hour), &c); err != nil {
		t.Fatalf("fillCounts: %v", err)
	}

	for _, tc := range []struct {
		name string
		got  int64
	}{
		{"Apps", c.Apps},
		{"Orgs", c.Orgs},
		{"Groups", c.Groups},
		{"IdentitySources", c.IdentitySources},
	} {
		if tc.got != 1 {
			t.Errorf("%s = %d, want 1 — soft-deleted rows are still being counted", tc.name, tc.got)
		}
	}

	// The per-protocol breakdown reads the same table and needs the same filter,
	// or the chart disagrees with the total beside it.
	if len(c.AppsByProtocol) != 1 || c.AppsByProtocol[0].Name != "oidc" {
		t.Errorf("AppsByProtocol = %+v, want only the live oidc app", c.AppsByProtocol)
	}
}
