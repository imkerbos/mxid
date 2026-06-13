package authz

import (
	"context"
	"fmt"
	"testing"
)

// This is the deliverable's proof: the legacy decision logic (in-binding
// permission set) and the new Casbin-backed logic must agree on EVERY
// (subject, permission-in-catalog, scope-target) combination over a seeded
// fixture that exercises the builtin roles at global, org, and group scope.
//
// Both engines share the same EffectiveBindingsForUser stub (so subject→role
// and org-ancestry resolution is identical) and the same Go scopeCovers; the
// ONLY thing that differs is the role→permission decision — legacy reads
// EffectiveBinding.Permissions, Casbin calls Enforce(roleSubject, dom, perm).
// Any divergence is a bug in the Casbin model/sync and fails this test.

// ---- fixture -------------------------------------------------------------

const fixtureTenant int64 = 1

// builtin role ids for the fixture.
const (
	roleSuperAdmin  int64 = 0 // synthesized: RoleID 0 + "*" perm
	roleDeptAdmin   int64 = 10
	roleUserManager int64 = 11
	roleAuditor     int64 = 12
	roleMember      int64 = 13
)

// permission catalog (the codes the engine must answer for). Mirrors the
// documented catalog incl. the seeded-but-unenforced app.* / *.assign codes.
var permCatalog = []string{
	"user.create", "user.read", "user.update", "user.delete",
	"user.lock", "user.unlock", "user.reset_password",
	"user.identity.manage", "user.mfa.manage", "user.login_history.read",
	"user.super_admin.manage", "user.org.assign", "user.group.assign",
	"user.session.manage",
	"org.create", "org.read", "org.update", "org.delete",
	"org.member.add", "org.member.remove",
	"group.create", "group.read", "group.update", "group.delete",
	"group.member.manage", "group.rule.manage",
	"role.create", "role.read", "role.update", "role.delete",
	"role.assign", "role.permission.manage",
	"tenant.manage", "tenant.read",
	"app.create", "app.read", "app.update", "app.delete",
	"app.cert.manage", "app.access.manage",
}

// rolePerms is the role→permission catalog the sync layer would load from
// mxid_role_permission. super_admin is expressed as the "*" wildcard.
var rolePerms = map[int64][]string{
	roleDeptAdmin: {
		"user.read", "user.create", "user.update", "user.lock", "user.unlock",
		"org.read", "org.update", "org.member.add", "org.member.remove",
		"group.read", "group.member.manage",
	},
	roleUserManager: {
		"user.read", "user.create", "user.update", "user.delete",
		"user.reset_password", "user.mfa.manage", "user.identity.manage",
	},
	roleAuditor: {
		"user.read", "user.login_history.read", "org.read", "group.read",
		"role.read", "app.read",
	},
	roleMember: {
		"user.read",
	},
}

// org ltree: org 100 (root) -> 110 -> 120; plus unrelated 200.
var fixtureAncestry = map[int64][]int64{
	100: {100},
	110: {100, 110},
	120: {100, 110, 120},
	200: {200},
}

// subjects: each maps to a fixed effective-binding set. The bindings carry
// both the RoleID (for Casbin) AND the inlined Permissions (for legacy), kept
// in lockstep from rolePerms so the two engines see the same ground truth.
type subject struct {
	name     string
	bindings []EffectiveBinding
}

func bindingFor(roleID int64, scope ScopeKind, scopeID int64) EffectiveBinding {
	perms := map[string]struct{}{}
	for _, p := range rolePerms[roleID] {
		perms[p] = struct{}{}
	}
	return EffectiveBinding{
		RoleID:      roleID,
		Permissions: perms,
		Source:      "direct",
		ScopeType:   scope,
		ScopeID:     scopeID,
	}
}

func superAdminBinding() EffectiveBinding {
	return EffectiveBinding{
		RoleID:      0,
		Permissions: map[string]struct{}{"*": {}},
		Source:      "super_admin",
		ScopeType:   ScopeGlobal,
	}
}

func fixtureSubjects() []subject {
	return []subject{
		{"super_admin", []EffectiveBinding{superAdminBinding()}},
		{"global_user_manager", []EffectiveBinding{
			bindingFor(roleUserManager, ScopeGlobal, 0),
		}},
		{"dept_admin_on_110", []EffectiveBinding{
			bindingFor(roleDeptAdmin, ScopeOrg, 110),
		}},
		{"auditor_global", []EffectiveBinding{
			bindingFor(roleAuditor, ScopeGlobal, 0),
		}},
		{"member_group_7", []EffectiveBinding{
			bindingFor(roleMember, ScopeGroup, 7),
		}},
		// multi-binding: org-scoped dept_admin + global member (union test)
		{"mixed", []EffectiveBinding{
			bindingFor(roleDeptAdmin, ScopeOrg, 110),
			bindingFor(roleMember, ScopeGlobal, 0),
		}},
		// empty: no bindings → deny everything
		{"nobody", nil},
		// group-scoped dept_admin (org perms must NOT leak to group target,
		// group perms must NOT leak to org target — scopeCovers job, same for both)
		{"dept_admin_group_9", []EffectiveBinding{
			bindingFor(roleDeptAdmin, ScopeGroup, 9),
		}},
	}
}

// scope targets to sweep: nil, several orgs (in/out of subtree), groups.
func fixtureTargets() []*ScopeTarget {
	return []*ScopeTarget{
		nil,
		TargetOrg(100), TargetOrg(110), TargetOrg(120), TargetOrg(200),
		TargetGroup(7), TargetGroup(9), TargetGroup(8),
	}
}

// ---- engines -------------------------------------------------------------

// legacyService builds the OLD engine (no Casbin → in-binding perm matching).
func legacyService(binds []EffectiveBinding) *Service {
	return NewService(&stubProvider{bindings: binds}, &stubAncestry{ancestors: fixtureAncestry})
}

// casbinService builds the NEW engine wired to a Casbin enforcer loaded from
// the same rolePerms catalog + super_admin wildcard for the fixture tenant.
func casbinService(t *testing.T, binds []EffectiveBinding) *Service {
	t.Helper()
	engine, err := NewCasbinEngine()
	if err != nil {
		t.Fatalf("new casbin engine: %v", err)
	}
	var policies []RolePolicy
	for roleID, perms := range rolePerms {
		for _, p := range perms {
			policies = append(policies, RolePolicy{TenantID: fixtureTenant, RoleID: roleID, Permission: p})
		}
	}
	if err := engine.ReplacePolicies(policies, []int64{fixtureTenant}); err != nil {
		t.Fatalf("load casbin policies: %v", err)
	}
	return NewService(&stubProvider{bindings: binds}, &stubAncestry{ancestors: fixtureAncestry}).WithCasbin(engine)
}

// ---- the differential gate ----------------------------------------------

func TestDifferential_LegacyVsCasbin(t *testing.T) {
	ctx := context.Background()
	targets := fixtureTargets()

	var combos, divergences int
	for _, subj := range fixtureSubjects() {
		legacy := legacyService(subj.bindings)
		casbin := casbinService(t, subj.bindings)

		for _, perm := range permCatalog {
			for _, target := range targets {
				combos++
				gotLegacy, errL := legacy.Check(ctx, fixtureTenant, 1, perm, target)
				gotCasbin, errC := casbin.Check(ctx, fixtureTenant, 1, perm, target)
				if (errL == nil) != (errC == nil) {
					divergences++
					t.Errorf("err mismatch subj=%s perm=%s target=%s: legacyErr=%v casbinErr=%v",
						subj.name, perm, targetStr(target), errL, errC)
					continue
				}
				if gotLegacy != gotCasbin {
					divergences++
					t.Errorf("DECISION DIVERGENCE subj=%s perm=%s target=%s: legacy=%v casbin=%v",
						subj.name, perm, targetStr(target), gotLegacy, gotCasbin)
				}
			}
		}
	}
	if divergences != 0 {
		t.Fatalf("%d/%d combos diverged between legacy and Casbin engines", divergences, combos)
	}
	t.Logf("differential OK: %d combos, 0 divergences", combos)
}

// TestDifferential_CrossTenantIsolation proves the Casbin domain dimension
// denies a role's perms when queried under a different tenant domain, matching
// the legacy engine where EffectiveBindingsForUser is tenant-scoped at the SQL
// join (here simulated by querying tenant 2 with tenant-1 policies loaded).
func TestDifferential_CrossTenantIsolation(t *testing.T) {
	engine, err := NewCasbinEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.ReplacePolicies(
		[]RolePolicy{{TenantID: 1, RoleID: roleUserManager, Permission: "user.delete"}},
		nil,
	); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !engine.RoleHasPermission(1, roleSubject(roleUserManager), "user.delete") {
		t.Errorf("role must hold user.delete in its own tenant domain")
	}
	if engine.RoleHasPermission(2, roleSubject(roleUserManager), "user.delete") {
		t.Errorf("role must NOT hold perm in a foreign tenant domain")
	}
	if engine.RoleHasPermission(1, roleSubject(roleUserManager), "user.read") {
		t.Errorf("exact match: role must NOT hold an ungranted perm")
	}
}

func targetStr(t *ScopeTarget) string {
	if t == nil {
		return "nil"
	}
	return fmt.Sprintf("%s:%d", t.Kind, t.ID)
}
