package oidcop

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// bindingIdentity is fakeClaimsIdentity plus the optional
// IdentityBindingResolver capability, counting how many times the binding
// lookup actually ran. The count is the point of half these tests: the lookup
// is an extra query on the path every token takes, and "only when a mapper
// asks" is a promise that a later refactor can quietly break.
type bindingIdentity struct {
	resolver.IdentityResolver
	info     *resolver.IdentityInfo
	bindings map[string]map[string]string
	err      error
	calls    int
}

func (f *bindingIdentity) ResolveUser(_ context.Context, _ int64) (*resolver.IdentityInfo, error) {
	return f.info, nil
}

func (f *bindingIdentity) ResolveClaims(_ context.Context, _ int64, _ []string) (map[string]any, error) {
	return map[string]any{"sub": strconv.FormatInt(f.info.ID, 10)}, nil
}

func (f *bindingIdentity) ResolveIdentityBindings(_ context.Context, _ int64) (map[string]map[string]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.bindings, nil
}

// appWithMappers builds an app config whose protocol_config carries mappers.
func appWithMappers(t *testing.T, mappers ...map[string]string) *resolver.AppConfig {
	t.Helper()
	cfg := map[string]any{"claim_mappers": mappers}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal protocol_config: %v", err)
	}
	return &resolver.AppConfig{ID: 100, ClientID: "app1", ProtocolConfig: raw}
}

func larkBindings() map[string]map[string]string {
	return map[string]map[string]string{
		"lark": {
			"external_id": "ou_open_id_value",
			"user_id":     "ee11aa22",
			"union_id":    "on_union_value",
		},
	}
}

// The whole point of the feature: a Lark user_id reaches the id_token so an SP
// can @-mention the person in a bot message. open_id is what external_id
// holds, and it is per-Lark-app, so user_id is the one that travels.
func TestClaims_IdentitySource_EmitsLarkUserID(t *testing.T) {
	id := &bindingIdentity{
		info:     &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"},
		bindings: larkBindings(),
	}
	store := NewClaimsStore(id, &fakeClaimsApps{app: appWithMappers(t,
		map[string]string{"claim": "lark_user_id", "source": "user.identity.lark.user_id"},
		map[string]string{"claim": "lark_open_id", "source": "user.identity.lark.external_id"},
	)}, nil, nil)

	got, err := store.PrivateClaims(context.Background(), "42", "app1", []string{"openid"})
	if err != nil {
		t.Fatalf("PrivateClaims: %v", err)
	}
	if got["lark_user_id"] != "ee11aa22" {
		t.Fatalf("lark_user_id = %v, want ee11aa22", got["lark_user_id"])
	}
	if got["lark_open_id"] != "ou_open_id_value" {
		t.Fatalf("lark_open_id = %v, want ou_open_id_value", got["lark_open_id"])
	}
	if id.calls != 1 {
		t.Fatalf("binding lookups = %d, want 1", id.calls)
	}
}

// No mapper names user.identity.* -> the lookup must not run at all. Without
// this, the "lazy" in loadIdentityBindings is just a comment.
func TestClaims_IdentitySource_NotLoadedWithoutMapper(t *testing.T) {
	id := &bindingIdentity{
		info:     &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice"},
		bindings: larkBindings(),
	}
	store := NewClaimsStore(id, &fakeClaimsApps{app: appWithMappers(t,
		map[string]string{"claim": "dept", "source": "user.detail.department"},
	)}, nil, nil)

	if _, err := store.PrivateClaims(context.Background(), "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("PrivateClaims: %v", err)
	}
	if id.calls != 0 {
		t.Fatalf("binding lookups = %d, want 0 (no user.identity.* mapper configured)", id.calls)
	}
}

// A user who never linked the provider gets no claim — not an empty string,
// and not an error. Same outcome as a failed lookup, deliberately: an optional
// projection must never fail the token.
func TestClaims_IdentitySource_UnlinkedAndFailureEmitNothing(t *testing.T) {
	mapper := map[string]string{"claim": "lark_user_id", "source": "user.identity.lark.user_id"}

	for _, tc := range []struct {
		name string
		id   *bindingIdentity
	}{
		{"unlinked", &bindingIdentity{
			info:     &resolver.IdentityInfo{ID: 42, Username: "alice"},
			bindings: map[string]map[string]string{},
		}},
		{"lookup failed", &bindingIdentity{
			info: &resolver.IdentityInfo{ID: 42, Username: "alice"},
			err:  errors.New("database is down"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewClaimsStore(tc.id, &fakeClaimsApps{app: appWithMappers(t, mapper)}, nil, nil)
			got, err := store.PrivateClaims(context.Background(), "42", "app1", []string{"openid"})
			if err != nil {
				t.Fatalf("PrivateClaims: %v", err)
			}
			if _, present := got["lark_user_id"]; present {
				t.Fatalf("lark_user_id present (%v); an absent binding must emit no claim", got["lark_user_id"])
			}
		})
	}
}

// The field set is an allow-list built by the adapter, not a passthrough of the
// provider profile. The profile JSON also holds email / mobile / name, and a
// mapper that could address those would make per-app config a data-export
// surface.
func TestClaims_IdentitySource_OnlyAllowListedFields(t *testing.T) {
	id := &bindingIdentity{
		info: &resolver.IdentityInfo{ID: 42, Username: "alice"},
		// What the adapter hands over: ids only. Even if a profile field were
		// smuggled in, the mapper below addresses a key the adapter never sets.
		bindings: larkBindings(),
	}
	store := NewClaimsStore(id, &fakeClaimsApps{app: appWithMappers(t,
		map[string]string{"claim": "leaked", "source": "user.identity.lark.email"},
		map[string]string{"claim": "leaked_mobile", "source": "user.identity.lark.mobile"},
	)}, nil, nil)

	got, err := store.PrivateClaims(context.Background(), "42", "app1", []string{"openid"})
	if err != nil {
		t.Fatalf("PrivateClaims: %v", err)
	}
	for _, k := range []string{"leaked", "leaked_mobile"} {
		if v, present := got[k]; present {
			t.Fatalf("%s present (%v); only id fields are addressable", k, v)
		}
	}
}

// Malformed paths resolve to nothing rather than to a fabricated claim. This
// guard exists because the silence is the hazard: the console's own
// integration guides shipped `user.groups.codes` in six places for months, a
// three-segment path this function has always ignored.
func TestResolveClaimSource_MalformedPathsIgnored(t *testing.T) {
	info := &resolver.IdentityInfo{
		ID:         42,
		Groups:     []string{"eng"},
		Detail:     map[string]any{"department": "platform"},
		Identities: larkBindings(),
	}

	for _, path := range []string{
		"user.groups.codes",            // the one the console guides got wrong
		"user.identity.lark",           // provider without a field
		"user.identity",                // namespace alone
		"user.identity.lark.x.y",       // too many segments
		"user.identity.github.user_id", // provider the user has not linked
		"identity.lark.user_id",        // not rooted at user
		"user",                         // single segment
	} {
		if v, ok := resolveClaimSource(path, info); ok {
			t.Fatalf("resolveClaimSource(%q) = %v, want ignored", path, v)
		}
	}

	// Control: the valid shapes next door still resolve, so the test above is
	// rejecting malformed paths rather than everything.
	for _, path := range []string{"user.groups", "user.detail.department", "user.identity.lark.user_id"} {
		if _, ok := resolveClaimSource(path, info); !ok {
			t.Fatalf("resolveClaimSource(%q) was ignored, want resolved", path)
		}
	}
}

// user.id keeps emitting a JSON number because apps are configured against it;
// user.id_string is the one to use. Both assertions matter: "tidying" them into
// one shape breaks either existing SPs or the reason id_string exists.
func TestResolveClaimSource_IDPrecision(t *testing.T) {
	// A real snowflake, past 2^53 — the value JSON.parse cannot round-trip.
	const snowflake int64 = 386084064030887936
	info := &resolver.IdentityInfo{ID: snowflake}

	v, ok := resolveClaimSource("user.id", info)
	if !ok {
		t.Fatal("user.id was ignored")
	}
	if _, isInt := v.(int64); !isInt {
		t.Fatalf("user.id = %T, want int64 (unchanged legacy shape)", v)
	}

	s, ok := resolveClaimSource("user.id_string", info)
	if !ok {
		t.Fatal("user.id_string was ignored")
	}
	if s != "386084064030887936" {
		t.Fatalf("user.id_string = %v, want the exact decimal digits", s)
	}
	if snowflake <= 1<<53 {
		t.Fatal("test fixture no longer exceeds 2^53; it no longer proves anything")
	}
}

// The claim must reach the id_token, not just the mapper plumbing: that is
// where an RP reading tokens only (and plenty do) will look for it.
func TestClaims_IdentitySource_ReachesUserinfo(t *testing.T) {
	id := &bindingIdentity{
		info:     &resolver.IdentityInfo{ID: 42, Username: "alice"},
		bindings: larkBindings(),
	}
	store := NewClaimsStore(id, &fakeClaimsApps{app: appWithMappers(t,
		map[string]string{"claim": "lark_user_id", "source": "user.identity.lark.user_id"},
	)}, nil, nil)

	info := new(oidc.UserInfo)
	if err := store.SetUserinfo(context.Background(), info, "42", "app1", []string{"openid"}); err != nil {
		t.Fatalf("SetUserinfo: %v", err)
	}
	if info.Claims["lark_user_id"] != "ee11aa22" {
		t.Fatalf("lark_user_id = %v, want ee11aa22", info.Claims["lark_user_id"])
	}
}
