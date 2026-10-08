package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// EmergencyRevoke is the action an operator reaches for while a client secret
// is known to be leaked, so the properties worth pinning are the ones that are
// wrong-by-default:
//
//  1. ORDER. Rotate the secret BEFORE revoking tokens. The reverse leaves a
//     window where a holder of the old secret presents a refresh token and
//     mints a fresh pair, undoing the revoke with the credential being
//     contained — the refresh grant re-authenticates the client on every call.
//  2. NO ROLLBACK on a failed revoke. The rotation is the half that stops the
//     leaked credential; restoring a secret an attacker holds in order to keep
//     the operation "atomic" would be strictly worse.
//  3. HONEST REPORTING. With no revoker wired the call must not imply tokens
//     were dropped.
//
// Backed by a fake repository: what is under test is sequencing and reporting,
// not SQL.

type fakeRevokeRepo struct {
	Repository
	clientID string
	// updates appends a marker per Update, so ordering against the revoke call
	// is observable.
	trace *[]string
}

func (f *fakeRevokeRepo) GetByID(_ context.Context, id int64) (*App, error) {
	cid := f.clientID
	return &App{ID: id, Protocol: "oidc", ClientType: "web_app", ClientID: &cid}, nil
}

func (f *fakeRevokeRepo) Update(_ context.Context, _ *App) error {
	*f.trace = append(*f.trace, "rotate")
	return nil
}

func newRevokeService(t *testing.T, revoker TokenRevoker) (*Service, *[]string, context.Context) {
	t.Helper()
	trace := &[]string{}
	svc := NewService(&fakeRevokeRepo{clientID: "client_abc", trace: trace}, nil, event.NewBus(zap.NewNop()))
	if revoker != nil {
		svc.SetTokenRevoker(revoker)
	}
	return svc, trace, context.Background()
}

func TestEmergencyRevoke_RotatesBeforeRevoking(t *testing.T) {
	var trace *[]string
	var gotClientID string
	svc, tr, ctx := newRevokeService(t, nil)
	trace = tr
	svc.SetTokenRevoker(func(_ context.Context, clientID string) (int, error) {
		gotClientID = clientID
		*trace = append(*trace, "revoke")
		return 3, nil
	})

	res, err := svc.EmergencyRevoke(ctx, 1)
	if err != nil {
		t.Fatalf("EmergencyRevoke: %v", err)
	}

	if got := strings.Join(*trace, ","); got != "rotate,revoke" {
		t.Fatalf("sequence = %q, want \"rotate,revoke\": revoking first lets a holder of the old secret refresh its way back in", got)
	}
	if gotClientID != "client_abc" {
		t.Errorf("revoker got client_id %q, want client_abc", gotClientID)
	}
	if res.TokensRevoked != 3 {
		t.Errorf("TokensRevoked = %d, want 3", res.TokensRevoked)
	}
	if !res.RevokeSupported {
		t.Error("RevokeSupported = false with a revoker wired")
	}
	if res.ClientSecretPlain == "" {
		t.Error("no new client secret returned; the caller can never reconfigure the RP")
	}
}

func TestEmergencyRevoke_FailedRevokeKeepsTheRotation(t *testing.T) {
	revokeErr := errors.New("redis down")
	svc, trace, ctx := newRevokeService(t, func(_ context.Context, _ string) (int, error) {
		return 1, revokeErr
	})

	res, err := svc.EmergencyRevoke(ctx, 1)
	if !errors.Is(err, revokeErr) {
		t.Fatalf("err = %v, want it to wrap %v", err, revokeErr)
	}
	if res == nil {
		t.Fatal("no result returned on a partial run: the operator cannot tell whether the secret rotated")
	}
	if res.ClientSecretPlain == "" {
		t.Error("the rotated secret was withheld on a failed revoke; it already happened and the RP needs it")
	}
	if res.TokensRevoked != 1 {
		t.Errorf("TokensRevoked = %d, want the partial count 1", res.TokensRevoked)
	}
	if got := strings.Join(*trace, ","); got != "rotate" {
		t.Errorf("trace = %q, want a single rotate with no rollback", got)
	}
}

func TestEmergencyRevoke_NoRevokerSaysSo(t *testing.T) {
	svc, _, ctx := newRevokeService(t, nil)

	res, err := svc.EmergencyRevoke(ctx, 1)
	if err != nil {
		t.Fatalf("EmergencyRevoke: %v", err)
	}
	if res.RevokeSupported {
		t.Error("RevokeSupported = true with no revoker wired")
	}
	if res.TokensRevoked != 0 {
		t.Errorf("TokensRevoked = %d, want 0 when nothing could revoke", res.TokensRevoked)
	}
	if res.ClientSecretPlain == "" {
		t.Error("the secret must still rotate when token revocation is unavailable")
	}
}

// The event is what the audit chain and the alert webhook see. A partial run
// must still produce one, flagged incomplete — an audit trail that omits the
// action because its cleanup half failed is worse than one that records how far
// it got.
func TestEmergencyRevoke_PublishesEventIncludingOnPartialFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		revoker      TokenRevoker
		wantComplete bool
		wantRevoked  int64
	}{
		{"full run", func(context.Context, string) (int, error) { return 2, nil }, true, 2},
		{"partial run", func(context.Context, string) (int, error) { return 1, errors.New("boom") }, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bus := event.NewBus(zap.NewNop())
			got := make(chan event.Event, 2)
			bus.Subscribe(event.AppEmergencyRevoked, func(_ context.Context, e event.Event) { got <- e })

			trace := &[]string{}
			svc := NewService(&fakeRevokeRepo{clientID: "client_abc", trace: trace}, nil, bus)
			svc.SetTokenRevoker(tc.revoker)
			_, _ = svc.EmergencyRevoke(context.Background(), 1)

			e := <-got
			p, ok := e.Payload.(map[string]any)
			if !ok {
				t.Fatalf("payload is %T, want map[string]any", e.Payload)
			}
			if p["client_id"] != "client_abc" {
				t.Errorf("client_id = %v, want client_abc", p["client_id"])
			}
			if p["complete"] != tc.wantComplete {
				t.Errorf("complete = %v, want %v", p["complete"], tc.wantComplete)
			}
			if p["tokens_revoked"] != int(tc.wantRevoked) {
				t.Errorf("tokens_revoked = %v, want %d", p["tokens_revoked"], tc.wantRevoked)
			}
		})
	}
}
