package access

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// fakeResolver is a ProtocolResolver stub that returns a fixed protocol (or err).
type fakeResolver struct {
	proto string
	err   error
}

func (f fakeResolver) ProtocolForApp(context.Context, int64) (string, error) {
	return f.proto, f.err
}

func TestCompositeTerminator_DispatchesByProtocol(t *testing.T) {
	var oidcHit, samlHit, casHit int64
	resolver := fakeResolver{proto: "cas"}
	ct := NewCompositeTerminator(resolver,
		func(context.Context, int64, int64) { oidcHit++ },
		func(context.Context, int64, int64) { samlHit++ },
		func(context.Context, int64, int64) { casHit++ },
		zap.NewNop(),
	)
	ct.TerminateAppSession(context.Background(), 1, 5001, 1001)
	if casHit != 1 || oidcHit != 0 || samlHit != 0 {
		t.Fatalf("expected only CAS dispatched: oidc=%d saml=%d cas=%d", oidcHit, samlHit, casHit)
	}
}

func TestCompositeTerminator_DispatchesOIDCAndSAML(t *testing.T) {
	cases := []struct {
		proto              string
		wantOIDC, wantSAML int64
	}{
		{"oidc", 1, 0},
		{"saml", 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			var oidcHit, samlHit, casHit int64
			ct := NewCompositeTerminator(fakeResolver{proto: tc.proto},
				func(context.Context, int64, int64) { oidcHit++ },
				func(context.Context, int64, int64) { samlHit++ },
				func(context.Context, int64, int64) { casHit++ },
				zap.NewNop(),
			)
			ct.TerminateAppSession(context.Background(), 1, 5001, 1001)
			if oidcHit != tc.wantOIDC || samlHit != tc.wantSAML || casHit != 0 {
				t.Fatalf("proto=%s: oidc=%d saml=%d cas=%d", tc.proto, oidcHit, samlHit, casHit)
			}
		})
	}
}

func TestCompositeTerminator_UnknownProtocolNoDispatch(t *testing.T) {
	var hits int64
	bump := func(context.Context, int64, int64) { hits++ }
	ct := NewCompositeTerminator(fakeResolver{proto: "ldap"}, bump, bump, bump, zap.NewNop())
	ct.TerminateAppSession(context.Background(), 1, 5001, 1001)
	if hits != 0 {
		t.Fatalf("expected no dispatch on unknown protocol, got %d", hits)
	}
}

func TestCompositeTerminator_ResolveErrorNoDispatch(t *testing.T) {
	var hits int64
	bump := func(context.Context, int64, int64) { hits++ }
	ct := NewCompositeTerminator(fakeResolver{err: errors.New("boom")}, bump, bump, bump, zap.NewNop())
	ct.TerminateAppSession(context.Background(), 1, 5001, 1001)
	if hits != 0 {
		t.Fatalf("expected no dispatch on resolve error, got %d", hits)
	}
}
