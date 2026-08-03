package permission

// EffectiveRolesForUser had no test at all, which is a large part of why it
// stayed an N+1 for so long: nothing described what it was supposed to return,
// so nothing objected to how it got there.
//
// These pin the contract rather than the implementation — provenance is
// preserved, duplicates across paths are kept, a membership-lookup failure
// degrades instead of blanking, and a binding to a deleted role is skipped.

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

func newEffectiveService(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&Role{}, &RoleBinding{}, &Permission{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return NewService(NewGormRepository(db), gen, nil, 1), db
}

func seedEffRole(t *testing.T, db *gorm.DB, id int64, code string) {
	t.Helper()
	if err := db.Create(&Role{ID: id, TenantID: 1, Code: code, Name: code}).Error; err != nil {
		t.Fatalf("seed role %s: %v", code, err)
	}
}

func seedEffBinding(t *testing.T, db *gorm.DB, id, roleID int64, subjectType string, subjectID int64) {
	t.Helper()
	b := &RoleBinding{ID: id, RoleID: roleID, SubjectType: subjectType, SubjectID: subjectID}
	if err := db.Create(b).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}
}

type stubGroups struct {
	ids []int64
	err error
}

func (s stubGroups) GroupIDsForUser(context.Context, int64, int64) ([]int64, error) {
	return s.ids, s.err
}

type stubOrgs struct {
	ids []int64
	err error
}

func (s stubOrgs) AncestorIDsForUser(context.Context, int64, int64) ([]int64, error) {
	return s.ids, s.err
}

func TestEffectiveRolesResolvesAllThreePathsWithProvenance(t *testing.T) {
	svc, db := newEffectiveService(t)
	seedEffRole(t, db, 100, "admin")
	seedEffRole(t, db, 200, "viewer")
	seedEffRole(t, db, 300, "auditor")

	seedEffBinding(t, db, 1, 100, "user", 42)
	seedEffBinding(t, db, 2, 200, "group", 7)
	seedEffBinding(t, db, 3, 300, "org", 9)

	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42,
		stubGroups{ids: []int64{7}}, stubOrgs{ids: []int64{9}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d roles, want 3", len(got))
	}

	// Provenance is the whole point of the endpoint: the console renders which
	// path granted the role, so source and source_id must survive batching.
	bySource := map[EffectiveRoleSource]*EffectiveRoleResponse{}
	for _, r := range got {
		bySource[r.Source] = r
	}
	if d := bySource[SourceDirect]; d == nil || d.SourceID != 42 || d.Role.Code != "admin" {
		t.Fatalf("direct binding wrong: %+v", d)
	}
	if g := bySource[SourceGroup]; g == nil || g.SourceID != 7 || g.Role.Code != "viewer" {
		t.Fatalf("group binding wrong: %+v", g)
	}
	if o := bySource[SourceOrg]; o == nil || o.SourceID != 9 || o.Role.Code != "auditor" {
		t.Fatalf("org binding wrong: %+v", o)
	}
}

// The same role reachable by two paths must appear twice, each attributed —
// deduplicating here would hide that revoking one path leaves the other.
func TestEffectiveRolesKeepsDuplicatesFromDifferentSources(t *testing.T) {
	svc, db := newEffectiveService(t)
	seedEffRole(t, db, 100, "admin")
	seedEffBinding(t, db, 1, 100, "user", 42)
	seedEffBinding(t, db, 2, 100, "group", 7)

	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42, stubGroups{ids: []int64{7}}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want the same role from both paths", len(got))
	}
}

// Group bindings must be attributed to the group that carries them, not to
// whichever group happened to be looked up first — the batch query returns
// bindings for several subjects at once, so this is the case a naive rewrite
// gets wrong.
func TestEffectiveRolesAttributesEachGroupCorrectly(t *testing.T) {
	svc, db := newEffectiveService(t)
	seedEffRole(t, db, 100, "alpha")
	seedEffRole(t, db, 200, "beta")
	seedEffBinding(t, db, 1, 100, "group", 7)
	seedEffBinding(t, db, 2, 200, "group", 8)

	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42,
		stubGroups{ids: []int64{7, 8}}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d roles, want 2", len(got))
	}
	for _, r := range got {
		switch r.Role.Code {
		case "alpha":
			if r.SourceID != 7 {
				t.Fatalf("alpha attributed to group %d, want 7", r.SourceID)
			}
		case "beta":
			if r.SourceID != 8 {
				t.Fatalf("beta attributed to group %d, want 8", r.SourceID)
			}
		default:
			t.Fatalf("unexpected role %q", r.Role.Code)
		}
	}
}

// A membership-lookup blip must not read as "this user has no permissions".
func TestEffectiveRolesDegradesWhenMembershipLookupFails(t *testing.T) {
	svc, db := newEffectiveService(t)
	seedEffRole(t, db, 100, "admin")
	seedEffBinding(t, db, 1, 100, "user", 42)

	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42,
		stubGroups{err: errors.New("registry down")},
		stubOrgs{err: errors.New("registry down")})
	if err != nil {
		t.Fatalf("a membership lookup failure must not fail the request: %v", err)
	}
	if len(got) != 1 || got[0].Source != SourceDirect {
		t.Fatalf("direct bindings must survive a lookup failure, got %+v", got)
	}
}

func TestEffectiveRolesSkipsBindingToDeletedRole(t *testing.T) {
	svc, db := newEffectiveService(t)
	seedEffRole(t, db, 100, "admin")
	seedEffBinding(t, db, 1, 100, "user", 42)
	seedEffBinding(t, db, 2, 999, "user", 42) // role 999 never existed

	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42, nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0].Role.Code != "admin" {
		t.Fatalf("a binding to a missing role should be skipped, got %+v", got)
	}
}

func TestEffectiveRolesEmptyForUserWithNoBindings(t *testing.T) {
	svc, _ := newEffectiveService(t)
	got, err := svc.EffectiveRolesForUser(context.Background(), 1, 42, stubGroups{}, stubOrgs{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no roles, got %d", len(got))
	}
}
