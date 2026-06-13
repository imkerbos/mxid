package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// enumStubQuerier returns a fixed user for one known username and a
// not-found error for everything else, so the test can compare the timing of
// the unknown-user path against the known-user/wrong-password path.
type enumStubQuerier struct {
	known string
	user  *UserAuth
}

func (q *enumStubQuerier) GetByUsername(_ context.Context, _ int64, username string) (*UserAuth, error) {
	if username == q.known {
		return q.user, nil
	}
	return nil, errors.New("not found")
}

// Both an unknown username and a known username with a wrong password must
// spend time in bcrypt — otherwise the unknown path returns in microseconds
// and leaks valid usernames via a timing oracle (OWASP A07). We assert the
// unknown path takes a non-trivial fraction of the known path: without the
// dummy-compare equalizer it would be ~1000x faster.
func TestAuthenticate_UnknownUserRunsBcrypt(t *testing.T) {
	hash, err := crypto.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	q := &enumStubQuerier{
		known: "alice",
		user: &UserAuth{
			ID: 1, Username: "alice", PasswordHash: hash, Status: statusActive,
		},
	}
	p := NewLocalProvider(q, 0)
	ctx := context.Background()

	mk := func(user string) *AuthRequest {
		return &AuthRequest{
			TenantID: 1,
			Credentials: map[string]string{
				"username": user,
				"password": "wrong-password",
			},
		}
	}

	// Warm up (first bcrypt call can pay one-time costs).
	_, _ = p.Authenticate(ctx, mk("alice"))
	_, _ = p.Authenticate(ctx, mk("nobody"))

	const iters = 5
	measure := func(user string) time.Duration {
		var total time.Duration
		for i := 0; i < iters; i++ {
			start := time.Now()
			res, _ := p.Authenticate(ctx, mk(user))
			total += time.Since(start)
			if res.Status != AuthFailed {
				t.Fatalf("expected AuthFailed for %q, got %v", user, res.Status)
			}
		}
		return total / iters
	}

	known := measure("alice")
	unknown := measure("nobody")

	// A bcrypt DefaultCost compare is on the order of tens of ms. Require the
	// unknown path to be at least half the known path — without the dummy
	// compare it would be sub-millisecond (orders of magnitude smaller).
	if unknown < known/2 {
		t.Fatalf("unknown-user path (%v) is far faster than known-user path (%v) "+
			"— timing oracle: dummy bcrypt not running", unknown, known)
	}
	// Sanity: a real bcrypt compare is never near-instant.
	if unknown < time.Millisecond {
		t.Fatalf("unknown-user path %v too fast to have run bcrypt", unknown)
	}
}

// A locked/disabled account must also burn bcrypt before short-circuiting so
// account-state can't be read off the response time either.
func TestAuthenticate_LockedRunsBcrypt(t *testing.T) {
	hash, _ := crypto.HashPassword("pw")
	q := &enumStubQuerier{
		known: "locked",
		user:  &UserAuth{ID: 2, Username: "locked", PasswordHash: hash, Status: statusLocked},
	}
	p := NewLocalProvider(q, 0)
	req := &AuthRequest{TenantID: 1, Credentials: map[string]string{"username": "locked", "password": "x"}}

	_, _ = p.Authenticate(context.Background(), req) // warm
	start := time.Now()
	res, _ := p.Authenticate(context.Background(), req)
	elapsed := time.Since(start)
	if res.Status != AuthLocked {
		t.Fatalf("want AuthLocked, got %v", res.Status)
	}
	if elapsed < time.Millisecond {
		t.Fatalf("locked path %v too fast — dummy bcrypt not running", elapsed)
	}
}
