package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubProvider lets each test fully script the binding set returned by the
// engine. Errors are surfaced so we can exercise the fail-closed path.
type stubProvider struct {
	bindings []EffectiveBinding
	err      error
}

func (s *stubProvider) EffectiveBindingsForUser(_ context.Context, _, _ int64) ([]EffectiveBinding, error) {
	return s.bindings, s.err
}

// stubAncestry mimics the org ltree. A descendant is "in" an ancestor when
// the ancestor appears in its registered ancestor list (root → leaf path).
type stubAncestry struct {
	ancestors map[int64][]int64 // descendant -> ancestor IDs (inclusive)
	err       error
}

func (s *stubAncestry) IsAncestorOrSelf(_ context.Context, ancestor, descendant int64) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	for _, id := range s.ancestors[descendant] {
		if id == ancestor {
			return true, nil
		}
	}
	return false, nil
}

func newSvc(bindings []EffectiveBinding, ancestry map[int64][]int64) *Service {
	return NewService(
		&stubProvider{bindings: bindings},
		&stubAncestry{ancestors: ancestry},
	)
}

func TestCheck_EmptyPermissionErrors(t *testing.T) {
	svc := newSvc(nil, nil)
	if _, err := svc.Check(context.Background(), 1, 1, "", nil); err == nil {
		t.Errorf("expected error for empty permission")
	}
}

func TestCheck_SuperAdminWildcard(t *testing.T) {
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"*": {}},
		ScopeType:   ScopeGlobal,
	}}, nil)

	cases := []*ScopeTarget{nil, TargetOrg(123), TargetGroup(7)}
	for _, target := range cases {
		ok, err := svc.Check(context.Background(), 1, 1, "anything.do", target)
		if err != nil || !ok {
			t.Errorf("super_admin must allow %#v, got ok=%v err=%v", target, ok, err)
		}
	}
}

func TestCheck_GlobalScopeAllowsAnyTarget(t *testing.T) {
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"user.read": {}},
		ScopeType:   ScopeGlobal,
	}}, nil)

	ok, _ := svc.Check(context.Background(), 1, 1, "user.read", TargetOrg(1234))
	if !ok {
		t.Errorf("global binding must cover org target")
	}
}

func TestCheck_OrgScopeMatchesAncestor(t *testing.T) {
	ancestry := map[int64][]int64{
		123: {1, 10, 100, 123}, // 123 sits under 1 → 10 → 100
	}
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"user.read": {}},
		ScopeType:   ScopeOrg,
		ScopeID:     10, // grant on the middle org
	}}, ancestry)

	ok, _ := svc.Check(context.Background(), 1, 1, "user.read", TargetOrg(123))
	if !ok {
		t.Errorf("scope_org=10 should cover descendant org 123")
	}
}

func TestCheck_OrgScopeRejectsUnrelatedSubtree(t *testing.T) {
	ancestry := map[int64][]int64{
		200: {200},
	}
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"user.read": {}},
		ScopeType:   ScopeOrg,
		ScopeID:     10,
	}}, ancestry)

	ok, _ := svc.Check(context.Background(), 1, 1, "user.read", TargetOrg(200))
	if ok {
		t.Errorf("scope_org=10 must NOT cover unrelated org 200")
	}
}

func TestCheck_OrgScopeDoesNotCoverGroupTarget(t *testing.T) {
	ancestry := map[int64][]int64{}
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"group.read": {}},
		ScopeType:   ScopeOrg,
		ScopeID:     10,
	}}, ancestry)

	ok, _ := svc.Check(context.Background(), 1, 1, "group.read", TargetGroup(7))
	if ok {
		t.Errorf("org-scoped binding must not implicitly grant on group target")
	}
}

func TestCheck_GroupScopeExactMatch(t *testing.T) {
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"group.update": {}},
		ScopeType:   ScopeGroup,
		ScopeID:     7,
	}}, nil)

	if ok, _ := svc.Check(context.Background(), 1, 1, "group.update", TargetGroup(7)); !ok {
		t.Errorf("group scope must match exact ID")
	}
	if ok, _ := svc.Check(context.Background(), 1, 1, "group.update", TargetGroup(8)); ok {
		t.Errorf("group scope must NOT match different ID")
	}
}

func TestCheck_PermissionMissingDenies(t *testing.T) {
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"user.read": {}},
		ScopeType:   ScopeGlobal,
	}}, nil)

	if ok, _ := svc.Check(context.Background(), 1, 1, "user.delete", nil); ok {
		t.Errorf("absent permission must deny")
	}
}

func TestCheck_BindingProviderErrorFailsClosed(t *testing.T) {
	svc := NewService(&stubProvider{err: errors.New("db down")}, &stubAncestry{})
	ok, err := svc.Check(context.Background(), 1, 1, "user.read", nil)
	if ok || err == nil {
		t.Errorf("provider error must deny + bubble, got ok=%v err=%v", ok, err)
	}
}

func TestCheck_AncestryErrorOnSpecificBindingFallsThrough(t *testing.T) {
	// First binding scopes org=10 with a broken ancestry lookup → engine
	// must skip it and continue. Second binding is global → allow.
	svc := NewService(
		&stubProvider{bindings: []EffectiveBinding{
			{Permissions: map[string]struct{}{"user.read": {}}, ScopeType: ScopeOrg, ScopeID: 10},
			{Permissions: map[string]struct{}{"user.read": {}}, ScopeType: ScopeGlobal},
		}},
		&stubAncestry{err: errors.New("tree down")},
	)
	ok, _ := svc.Check(context.Background(), 1, 1, "user.read", TargetOrg(123))
	if !ok {
		t.Errorf("global binding must still allow when org check errors")
	}
}

func TestPermissionsForUser_UnionsAcrossBindings(t *testing.T) {
	svc := newSvc([]EffectiveBinding{
		{Permissions: map[string]struct{}{"user.read": {}}},
		{Permissions: map[string]struct{}{"user.update": {}}},
		{Permissions: map[string]struct{}{"user.read": {}, "org.read": {}}},
	}, nil)

	perms, err := svc.PermissionsForUser(context.Background(), 1, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"user.read", "user.update", "org.read"} {
		if _, ok := perms[want]; !ok {
			t.Errorf("missing permission %q in %v", want, perms)
		}
	}
}

func TestCheck_ExpiredBindingIsNotGranted(t *testing.T) {
	past := time.Now().Add(-1 * time.Minute)
	future := time.Now().Add(1 * time.Hour)

	// Past-expiry binding must be skipped in the decision loop even when the
	// (faked) provider/cache still returns it — this is the final enforcement
	// layer against cache/sweeper lag on JIT temporary grants.
	expired := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"console.read": {}},
		ScopeType:   ScopeGlobal,
		ExpiresAt:   &past,
	}}, nil)
	if ok, err := expired.Check(context.Background(), 1, 1, "console.read", nil); ok || err != nil {
		t.Errorf("expired binding must NOT be granted, got ok=%v err=%v", ok, err)
	}

	// nil ExpiresAt = permanent binding → must still be granted.
	permanent := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"console.read": {}},
		ScopeType:   ScopeGlobal,
		ExpiresAt:   nil,
	}}, nil)
	if ok, err := permanent.Check(context.Background(), 1, 1, "console.read", nil); !ok || err != nil {
		t.Errorf("permanent (nil-expiry) binding must be granted, got ok=%v err=%v", ok, err)
	}

	// Future ExpiresAt = still-valid JIT grant → must be granted.
	valid := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"console.read": {}},
		ScopeType:   ScopeGlobal,
		ExpiresAt:   &future,
	}}, nil)
	if ok, err := valid.Check(context.Background(), 1, 1, "console.read", nil); !ok || err != nil {
		t.Errorf("future-expiry binding must be granted, got ok=%v err=%v", ok, err)
	}
}

func TestCheck_NilTargetSkipsScopeCheck(t *testing.T) {
	svc := newSvc([]EffectiveBinding{{
		Permissions: map[string]struct{}{"role.read": {}},
		ScopeType:   ScopeOrg,
		ScopeID:     99,
	}}, nil)

	if ok, _ := svc.Check(context.Background(), 1, 1, "role.read", nil); !ok {
		t.Errorf("nil target should let any scope satisfy")
	}
}
