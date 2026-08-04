package app

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/session"
)

func revocationFixture(t *testing.T) (*session.Manager, int64) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	mgr := session.NewManager(rdb, time.Hour, 24*time.Hour)
	const userID int64 = 4242
	for _, ns := range []string{
		session.NamespacePortal,
		session.NamespaceConsole,
		session.NamespaceProtocol,
	} {
		if _, err := mgr.Create(context.Background(), ns, userID, 1, "10.0.0.1", "ua", "password"); err != nil {
			t.Fatalf("seed %s: %v", ns, err)
		}
	}
	return mgr, userID
}

func liveSessions(t *testing.T, mgr *session.Manager, userID int64) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, ns := range []string{
		session.NamespacePortal,
		session.NamespaceConsole,
		session.NamespaceProtocol,
	} {
		s, err := mgr.ListByUser(context.Background(), ns, userID)
		if err != nil {
			t.Fatalf("list %s: %v", ns, err)
		}
		out[ns] = len(s)
	}
	return out
}

// The protocol namespace holds the shared SSO session. Revoking only the two
// SPA namespaces — which is what every caller did before — leaves a revoked
// user able to keep completing OIDC/SAML/CAS sign-ins to downstream
// applications, which is precisely the access revocation is meant to cut.
func TestRevokeUserSessions_IncludesProtocolNamespace(t *testing.T) {
	mgr, uid := revocationFixture(t)

	revokeUserSessions(context.Background(), mgr, nil, uid, "test")

	for ns, n := range liveSessions(t, mgr, uid) {
		if n != 0 {
			t.Errorf("%s: %d session(s) survived revocation", ns, n)
		}
	}
}

// Event handlers run in their own goroutine, so the request context that
// published the event is usually cancelled before the handler reaches Redis.
// go-redis honours cancellation, so a revocation that used the publishing
// context silently did nothing whenever it lost that race — and the error was
// discarded. Revocation must not depend on beating the HTTP response.
func TestRevokeUserSessions_SurvivesCancelledPublisherContext(t *testing.T) {
	mgr, uid := revocationFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the request has already returned

	revokeUserSessions(ctx, mgr, nil, uid, "test")

	for ns, n := range liveSessions(t, mgr, uid) {
		if n != 0 {
			t.Errorf("%s: %d session(s) survived revocation under a cancelled context", ns, n)
		}
	}
}

// Which user events mean "an administrator put this account out of service".
//
// The negative cases carry the weight: the brute-force limiter publishes
// UserLocked for a policy lockout, and revoking on that would let an attacker
// evict someone from a live session simply by failing logins against their
// username.
func TestAdminStatusRevocation(t *testing.T) {
	const uid int64 = 77

	cases := []struct {
		name    string
		payload any
		want    bool
	}{
		{
			name:    "admin disables the account",
			payload: map[string]any{"user_id": uid, "status": user.StatusDisabled, "tenant_id": int64(1)},
			want:    true,
		},
		{
			name:    "admin locks the account via UpdateStatus",
			payload: map[string]any{"user_id": uid, "status": user.StatusLocked, "tenant_id": int64(1)},
			want:    true,
		},
		{
			name: "admin locks the account via LockUser",
			payload: map[string]any{
				"user_id": uid, "status": user.StatusLocked,
				"reason": "offboarded", "source": "admin", "actor_id": int64(1),
			},
			want: true,
		},
		{
			name:    "brute-force limiter lockout must NOT revoke",
			payload: map[string]any{"user_id": uid, "reason": "max_failed_attempts", "ip": "203.0.113.7"},
			want:    false,
		},
		{
			name:    "re-enabling the account is not a revocation",
			payload: map[string]any{"user_id": uid, "status": user.StatusActive},
			want:    false,
		},
		{
			name:    "an ordinary profile update is not a revocation",
			payload: map[string]any{"user_id": uid, "tenant_id": int64(1)},
			want:    false,
		},
		{
			name:    "a batch summary names no user",
			payload: map[string]any{"action": "batch_disable", "affected": 3, "status": user.StatusDisabled},
			want:    false,
		},
		{
			name:    "payload is not a map",
			payload: "user_id=77",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, status, ok := adminStatusRevocation(tc.payload)
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v (status=%d)", ok, tc.want, status)
			}
			if ok && got != uid {
				t.Errorf("user_id = %d, want %d", got, uid)
			}
		})
	}
}
