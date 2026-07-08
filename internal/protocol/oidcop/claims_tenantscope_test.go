package oidcop

import (
	"context"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// ctxCapturingIdentity records the context each resolver call receives so the
// tests below can assert the claims path scopes the tenant-scoped user lookup.
type ctxCapturingIdentity struct {
	resolver.IdentityResolver
	info         *resolver.IdentityInfo
	gotUserCtx   context.Context
	gotClaimsCtx context.Context
}

func (f *ctxCapturingIdentity) ResolveUser(ctx context.Context, _ int64) (*resolver.IdentityInfo, error) {
	f.gotUserCtx = ctx
	return f.info, nil
}

func (f *ctxCapturingIdentity) ResolveClaims(ctx context.Context, _ int64, _ []string) (map[string]any, error) {
	f.gotClaimsCtx = ctx
	return map[string]any{"sub": "42"}, nil
}

// Regression guard for the tenantscope fail-closed bug the OIDC e2e caught:
// the token endpoint carries no session tenant, so the claims path MUST resolve
// the globally-unique subject cross-tenant or the fail-closed tenantscope plugin
// rejects the user lookup ("no tenant scope in context"). The WS5 unit tests used
// fakes that ignore ctx and so missed this; these assert the scope explicitly.
func TestClaimsStore_ResolvesUserCrossTenant(t *testing.T) {
	id := &ctxCapturingIdentity{info: &resolver.IdentityInfo{ID: 42, TenantID: 7, Username: "alice", Status: userStatusActive}}
	cs := NewClaimsStore(id, &fakeClaimsApps{app: &resolver.AppConfig{}}, nil, nil)

	t.Run("IsUserActive", func(t *testing.T) {
		if _, err := cs.IsUserActive(context.Background(), "42"); err != nil {
			t.Fatalf("IsUserActive: %v", err)
		}
		sc, ok := tenantscope.From(id.gotUserCtx)
		if !ok || !sc.CrossTenant {
			t.Fatalf("IsUserActive must resolve the subject cross-tenant; got scope=%+v ok=%v", sc, ok)
		}
	})

	t.Run("SetUserinfo", func(t *testing.T) {
		if err := cs.SetUserinfo(context.Background(), new(oidc.UserInfo), "42", "client", []string{"openid"}); err != nil {
			t.Fatalf("SetUserinfo: %v", err)
		}
		sc, ok := tenantscope.From(id.gotClaimsCtx)
		if !ok || !sc.CrossTenant {
			t.Fatalf("SetUserinfo must resolve claims cross-tenant; got scope=%+v ok=%v", sc, ok)
		}
	})
}
