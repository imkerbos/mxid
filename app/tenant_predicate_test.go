package app

// The .Table() label lookups in adapters_oidc.go cannot use the tenantscope
// plugin, so they spell their tenant predicate out. Two of those spellings must
// stay in step with something else, and neither would fail loudly on its own:
//
//   - mxid_app is not plainly tenant-owned. A globally-shared app has
//     tenant_id NULL, so a plain `tenant_id = ?` hides every shared app and the
//     access-policy view renders "(未知)" again — the exact bug the scan structs
//     in that file were introduced to fix.
//   - the correct spelling lives in appdomain.App.TenantScopePredicate, which
//     the plugin uses for model-typed queries. If that changes and the copy here
//     does not, the two paths disagree silently.

import (
	"strings"
	"testing"

	appdomain "github.com/imkerbos/mxid/internal/domain/app"
)

func TestSharedAppPredicateMatchesTheDomainModel(t *testing.T) {
	want, scoped := appdomain.App{}.TenantScopePredicate()
	if !scoped {
		t.Fatal("appdomain.App no longer declares a custom tenant predicate; " +
			"ownedByTenantOrShared in adapters_oidc.go is now describing a rule that does not exist")
	}
	if ownedByTenantOrShared != want {
		t.Fatalf("ownedByTenantOrShared = %q, but appdomain.App.TenantScopePredicate = %q.\n"+
			"The .Table() label lookup for mxid_app must scope apps the same way the "+
			"plugin does, or shared apps resolve to an empty name.", ownedByTenantOrShared, want)
	}
}

// The shared-app case is the whole reason the two constants differ, so assert
// they actually do — a copy-paste that made them identical would reintroduce
// the bug while leaving the code looking deliberate.
func TestTenantPredicatesDiffer(t *testing.T) {
	if ownedByTenant == ownedByTenantOrShared {
		t.Fatal("ownedByTenant and ownedByTenantOrShared are identical; " +
			"one of them no longer means what its name says")
	}
	if !strings.Contains(ownedByTenantOrShared, "IS NULL") {
		t.Fatalf("ownedByTenantOrShared = %q does not admit NULL tenant_id, "+
			"so globally-shared apps would be filtered out", ownedByTenantOrShared)
	}
	if strings.Contains(ownedByTenant, "IS NULL") {
		t.Fatalf("ownedByTenant = %q admits NULL tenant_id; the tables it is used "+
			"for declare tenant_id NOT NULL, so this can only widen the scope by accident",
			ownedByTenant)
	}
}

// Only mxid_app dropped the NOT NULL (migration 000018). If another table ever
// does, its label lookup needs the shared spelling too — this records which
// tables the plain predicate is currently safe for.
func TestPlainPredicateTablesAreDocumented(t *testing.T) {
	plain := []string{"mxid_app_group", "mxid_user", "mxid_user_group", "mxid_organization", "mxid_role"}
	for _, tbl := range plain {
		if tbl == "mxid_app" {
			t.Fatalf("%s must use ownedByTenantOrShared", tbl)
		}
	}
}
