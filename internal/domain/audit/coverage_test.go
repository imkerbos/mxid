package audit

// Coverage of the ORM capture plugin.
//
// Adding AuditResource() to a model is what puts its mutations into the ledger,
// and getting it wrong is silent: the write still succeeds, it simply leaves no
// tamper-evident trace. Compilation proves nothing here, so these assert that a
// write to each newly-covered table actually lands in mxid_audit_pending — and
// that a table deliberately left out still does not.

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Stand-ins for the real domain models. The plugin dispatches purely on the
// Audited interface and TableName, so these exercise the same code path without
// dragging the domain packages (and their import cycles) into this test.
type covOrg struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name"`
}

func (covOrg) TableName() string     { return "mxid_organization" }
func (covOrg) AuditResource() string { return "org" }

type covGroup struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name"`
}

func (covGroup) TableName() string     { return "mxid_user_group" }
func (covGroup) AuditResource() string { return "group" }

type covGroupMember struct {
	ID      int64 `gorm:"column:id;primaryKey"`
	GroupID int64 `gorm:"column:group_id"`
	UserID  int64 `gorm:"column:user_id"`
}

func (covGroupMember) TableName() string     { return "mxid_user_group_member" }
func (covGroupMember) AuditResource() string { return "group_member" }

// Not audited: proves the plugin is selective rather than capturing everything.
type covUnaudited struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name"`
}

func (covUnaudited) TableName() string { return "cov_unaudited" }

func newCoverageDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&covOrg{}, &covGroup{}, &covGroupMember{}, &covUnaudited{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	if err := db.Use(NewCapturePlugin(NewCapturer(gen))); err != nil {
		t.Fatalf("install plugin: %v", err)
	}
	return db
}

func coverageCtx() context.Context {
	return auditctx.With(context.Background(), auditctx.Actor{
		ActorID: 9, ActorType: "user", ActorName: "Admin", TenantID: 1,
	})
}

func pendingFor(t *testing.T, db *gorm.DB, resource string) []AuditPending {
	t.Helper()
	var rows []AuditPending
	if err := db.Where("resource_type = ?", resource).Find(&rows).Error; err != nil {
		t.Fatalf("load pending for %s: %v", resource, err)
	}
	return rows
}

func TestAccessGrantingTablesReachTheLedger(t *testing.T) {
	db := newCoverageDB(t)
	ctx := coverageCtx()

	// Each of these changes who can reach what, and each used to leave a trace
	// only in the retention-purged audit log.
	if err := db.WithContext(ctx).Create(&covOrg{ID: 1, Name: "Engineering"}).Error; err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := db.WithContext(ctx).Create(&covGroup{ID: 2, Name: "sre"}).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.WithContext(ctx).Create(&covGroupMember{ID: 3, GroupID: 2, UserID: 42}).Error; err != nil {
		t.Fatalf("add member: %v", err)
	}

	for _, resource := range []string{"org", "group", "group_member"} {
		rows := pendingFor(t, db, resource)
		if len(rows) != 1 {
			t.Fatalf("resource %q produced %d chain rows, want 1", resource, len(rows))
		}
		if rows[0].ActorName == nil || *rows[0].ActorName != "Admin" {
			t.Fatalf("resource %q lost the actor name", resource)
		}
	}
}

func TestUnauditedTableProducesNoChainRow(t *testing.T) {
	db := newCoverageDB(t)
	if err := db.WithContext(coverageCtx()).Create(&covUnaudited{ID: 1, Name: "x"}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	var n int64
	if err := db.Model(&AuditPending{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a model without AuditResource must not be captured, got %d rows", n)
	}
}

// Membership removal is the revocation half, and matters as much as the grant.
func TestMembershipRemovalIsCaptured(t *testing.T) {
	db := newCoverageDB(t)
	ctx := coverageCtx()

	m := &covGroupMember{ID: 7, GroupID: 2, UserID: 42}
	if err := db.WithContext(ctx).Create(m).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.WithContext(ctx).Delete(m).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	rows := pendingFor(t, db, "group_member")
	if len(rows) != 2 {
		t.Fatalf("expected a row for the grant and one for the revocation, got %d", len(rows))
	}
	// The delete must carry the prior state, or the record cannot say what was
	// revoked.
	del := rows[1]
	if len(del.Before) == 0 || string(del.Before) == "null" {
		t.Fatalf("deletion captured no before-image: %s", del.Before)
	}
	if del.OccurredAt.IsZero() || time.Since(del.OccurredAt) > time.Minute {
		t.Fatalf("implausible occurred_at: %v", del.OccurredAt)
	}
}
