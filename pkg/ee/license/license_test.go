package license

import "testing"

// A valid EE license grants EVERY implemented feature — "EE = all" — so a newly
// shipped feature works on binary upgrade with no re-issued license. CE / expired
// (m.valid == false) grants nothing.
func TestHas_EEGrantsAllImplemented(t *testing.T) {
	ee := &Manager{valid: true}

	for _, f := range ImplementedFeatures {
		if !ee.Has(f) {
			t.Errorf("valid EE must grant implemented feature %q", f)
		}
	}

	// form_fill shipped → must be granted (the bug this guards: it was missing
	// from ImplementedFeatures, so a valid EE license silently didn't expose it).
	if !ee.Has(FeatureFormFill) {
		t.Error("valid EE must grant form_fill")
	}

	// multi_tenant is intentionally NOT implemented (product is single-tenant),
	// so even a valid EE license must not grant it.
	if ee.Has(FeatureMultiTenant) {
		t.Error("multi_tenant must not be granted (single-tenant product)")
	}

	// A reserved-but-unbuilt catalog key must never grant.
	if ee.Has(FeatureWebAuthn) {
		t.Error("unbuilt feature webauthn must not be granted")
	}
}

func TestHas_CEAndExpiredGrantNothing(t *testing.T) {
	for _, m := range []*Manager{nil, {valid: false}} {
		if m.Has(FeatureFormFill) || m.Has(FeatureExternalIDP) {
			t.Errorf("CE/expired manager (%v) must grant no features", m)
		}
		if got := m.EnabledFeatures(); got != nil {
			t.Errorf("CE/expired EnabledFeatures = %v, want nil", got)
		}
	}
}

func TestEnabledFeatures_MirrorsImplemented(t *testing.T) {
	ee := &Manager{valid: true}
	got := ee.EnabledFeatures()
	if len(got) != len(ImplementedFeatures) {
		t.Fatalf("EnabledFeatures len = %d, want %d", len(got), len(ImplementedFeatures))
	}
	for i, f := range ImplementedFeatures {
		if got[i] != f {
			t.Errorf("EnabledFeatures[%d] = %q, want %q", i, got[i], f)
		}
	}
}
