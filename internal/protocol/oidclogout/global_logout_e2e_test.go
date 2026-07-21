package oidclogout

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/session"
)

// End-to-end demo of the OIDC half of global logout: a user has a protocol SSO
// session that authenticated TWO RPs (each a real httptest server). A global
// (portal/console) logout calls LogoutUser(userID); BOTH RPs must receive a
// back-channel logout_token POST at their backchannel_logout_uri.
func TestGlobalLogoutE2E_OIDC_AllUserRPsNotified(t *testing.T) {
	svc, sm, idx, rpA, rpB, appA, appB := setupServiceHarness(t)
	ctx := context.Background()
	const userID, tenantID = int64(6003), int64(1)

	// The user holds one protocol SSO session that both RPs authenticated against.
	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, tenantID, "127.0.0.1", "ua", "password")
	if err != nil {
		t.Fatalf("create proto session: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appA, time.Hour); err != nil {
		t.Fatalf("track appA: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appB, time.Hour); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	// Global logout fans out to every RP the user is signed into.
	svc.LogoutUser(ctx, userID)
	waitAsync()

	if rpA.hits.Load() != 1 || rpB.hits.Load() != 1 {
		t.Fatalf("both RPs must get one back-channel logout POST, rpA=%d rpB=%d",
			rpA.hits.Load(), rpB.hits.Load())
	}

	// The participation set is consumed (destructive List) so a repeat logout
	// is a no-op.
	if left, _ := idx.Peek(ctx, sess.ID); len(left) != 0 {
		t.Fatalf("participation index must drain after logout, got %v", left)
	}
}
