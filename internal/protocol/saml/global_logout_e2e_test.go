package saml

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// End-to-end demo of the SAML half of global logout: a user holds SAML sessions
// to TWO apps. The global-logout orchestrator enumerates them via AppsForUser
// and drives IdPInitiatedLogout per app; the SP SLO endpoint must receive one
// signed LogoutRequest per app, and the per-user index must drain. Real handler
// + real Redis + real signed HTTP-Redirect LogoutRequest to a real httptest SP.
func TestGlobalLogoutE2E_SAML_AllUserAppsNotified(t *testing.T) {
	h, idxStore, sp := setupSAMLLogoutHarness(t)
	ctx := context.Background()
	const userID = int64(6002)

	// User has active SAML sessions to two apps (both resolve to the mock SP
	// SLO endpoint in this harness, so we expect two hits).
	for _, appID := range []int64{2001, 2002} {
		ref := SAMLSessionRef{
			SessionIndex: fmt.Sprintf("idx-%d", appID),
			NameID:       "u@x",
			SPEntityID:   "sp",
			NameIDFormat: NameIDEmail,
		}
		if err := idxStore.Record(ctx, userID, appID, ref, time.Hour); err != nil {
			t.Fatalf("record app %d: %v", appID, err)
		}
	}

	// --- orchestrate exactly as app/run.go's global-logout closure does ---
	apps, err := idxStore.AppsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	slices.Sort(apps)
	if !slices.Equal(apps, []int64{2001, 2002}) {
		t.Fatalf("AppsForUser = %v, want [2001 2002]", apps)
	}
	for _, appID := range apps {
		h.IdPInitiatedLogout(ctx, userID, appID)
	}
	waitAsync()

	// One signed LogoutRequest per app reached the SP SLO endpoint.
	if sp.hits() != 2 {
		t.Fatalf("SP must receive one LogoutRequest per app (2), got %d", sp.hits())
	}
	if !sp.lastHadParam("SAMLRequest") || !sp.lastHadParam("Signature") {
		t.Fatal("SP LogoutRequest missing SAMLRequest/Signature")
	}

	// The per-user index must be empty so a repeat logout is a no-op.
	if left, _ := idxStore.AppsForUser(ctx, userID); len(left) != 0 {
		t.Fatalf("per-user index must drain after global logout, got %v", left)
	}
}
