package cas

import (
	"context"
	"slices"
	"testing"
	"time"
)

// End-to-end demo of the CAS half of global logout: a user is signed into TWO
// CAS apps (each backed by a real httptest SP). The global-logout orchestrator
// enumerates the user's apps via AppsForUser and drives SingleLogout per app;
// BOTH mock SPs must receive a CAS logoutRequest POST, and the per-user index
// must drain. This exercises the real handler + real Redis + real HTTP.
func TestGlobalLogoutE2E_CAS_AllUserAppsNotified(t *testing.T) {
	sp1 := newStubSP(t)
	sp2 := newStubSP(t)
	h, reg := newSLOHandler(t, &routingDoer{routes: map[string]*stubSP{
		sp1.srv.URL: sp1,
		sp2.srv.URL: sp2,
	}})
	ctx := context.Background()
	const userID = int64(6001)

	// User authenticated to two different CAS apps at two different services.
	if err := reg.RecordService(ctx, userID, 3001, sp1.srv.URL, "ST-1", time.Hour); err != nil {
		t.Fatalf("record app 3001: %v", err)
	}
	if err := reg.RecordService(ctx, userID, 3002, sp2.srv.URL, "ST-2", time.Hour); err != nil {
		t.Fatalf("record app 3002: %v", err)
	}

	// --- orchestrate exactly as app/run.go's global-logout closure does ---
	apps, err := reg.AppsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	slices.Sort(apps)
	if !slices.Equal(apps, []int64{3001, 3002}) {
		t.Fatalf("AppsForUser = %v, want [3001 3002]", apps)
	}
	for _, appID := range apps {
		h.SingleLogout(ctx, userID, appID)
	}
	waitAsync()

	// Both SPs must have received a CAS logoutRequest.
	if sp1.posts() != 1 || sp2.posts() != 1 {
		t.Fatalf("both SPs must get one CAS logout POST, sp1=%d sp2=%d", sp1.posts(), sp2.posts())
	}
	if !sp1.lastBodyContains("LogoutRequest") || !sp2.lastBodyContains("LogoutRequest") {
		t.Fatal("CAS logout body missing 'LogoutRequest' at one of the SPs")
	}
	if !sp1.lastBodyContains("ST-1") || !sp2.lastBodyContains("ST-2") {
		t.Fatal("each SP's logoutRequest must carry its own service ticket")
	}

	// The per-user index must be empty so a repeat logout is a no-op.
	if left, _ := reg.AppsForUser(ctx, userID); len(left) != 0 {
		t.Fatalf("per-user index must drain after global logout, got %v", left)
	}
}
