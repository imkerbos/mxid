package saml

import (
	"testing"

	crewjam "github.com/crewjam/saml"
)

// findAttr returns the values of the first crewjam Attribute with the given
// name, or nil when absent.
func findAttr(attrs []crewjam.Attribute, name string) []string {
	for _, a := range attrs {
		if a.Name == name {
			vals := make([]string, len(a.Values))
			for i, v := range a.Values {
				vals[i] = v.Value
			}
			return vals
		}
	}
	return nil
}

// GroupAttribute set → buildResponseAttributes emits the group codes as a
// multi-value attribute under that name, AND still emits app_roles. This is the
// exact assembly emitCrewjamResponse writes into the signed assertion.
func TestBuildResponseAttributes_EmitsGroupsWhenConfigured(t *testing.T) {
	cfg := &SAMLConfig{RoleAttribute: "roles", GroupAttribute: "groups"}
	attrs := buildResponseAttributes(cfg, nil, []string{"viewer"}, []string{"eng", "admins"})

	groups := findAttr(attrs, "groups")
	if len(groups) != 2 || groups[0] != "eng" || groups[1] != "admins" {
		t.Fatalf("groups attribute = %v, want [eng admins]", groups)
	}
	if roles := findAttr(attrs, "roles"); len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("app_roles must still emit alongside groups, got %v", roles)
	}
}

// GroupAttribute empty (default) → groups are NOT emitted; app_roles unaffected.
func TestBuildResponseAttributes_OmitsGroupsWhenUnset(t *testing.T) {
	cfg := &SAMLConfig{RoleAttribute: "roles", GroupAttribute: ""}
	attrs := buildResponseAttributes(cfg, nil, []string{"viewer"}, []string{"eng", "admins"})

	if g := findAttr(attrs, "groups"); g != nil {
		t.Fatalf("groups must NOT be emitted when GroupAttribute empty, got %v", g)
	}
	if roles := findAttr(attrs, "roles"); len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("app_roles must emit, got %v", roles)
	}
}

// A custom GroupAttribute name (e.g. an SP that reads memberOf) is honored.
func TestBuildResponseAttributes_CustomGroupAttributeName(t *testing.T) {
	cfg := &SAMLConfig{RoleAttribute: "roles", GroupAttribute: "memberOf"}
	attrs := buildResponseAttributes(cfg, nil, nil, []string{"eng"})

	if g := findAttr(attrs, "memberOf"); len(g) != 1 || g[0] != "eng" {
		t.Fatalf("groups must emit under custom name memberOf, got %v", g)
	}
	if findAttr(attrs, "groups") != nil {
		t.Fatal("no attribute should be emitted under the default name when renamed")
	}
}
