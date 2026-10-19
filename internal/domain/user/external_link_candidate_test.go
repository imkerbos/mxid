package user

// These cover the decision to OFFER an account link, which sits on the
// authentication path: get it wrong in one direction and a federated login
// silently creates a second account; get it wrong in the other and it hands an
// external identity a prompt pointing at somebody else's account.
//
// Matching deliberately keys on email, not username. The suite pins that
// choice, because "alice and Alice are obviously the same person" is
// exactly the intuition that makes username matching look workable until two
// IdPs disagree on what a username is.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/snowflake"
)

func testUserIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	return g
}

func newLinkTestService(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{repo: NewGormRepository(db), idGen: testUserIDGen(t)}, db
}

func seedLocalUser(t *testing.T, db *gorm.DB, id int64, username, email string) {
	t.Helper()
	now := time.Now().UTC()
	u := &User{ID: id, TenantID: 1, Username: username, PasswordHash: "x", Status: StatusActive, CreatedAt: now, UpdatedAt: now}
	if email != "" {
		e := email
		u.Email = &e
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func teamsLogin(email string) *ExternalLoginInput {
	return &ExternalLoginInput{
		TenantID:     1,
		ProviderType: "teams",
		ProviderID:   "teams",
		ExternalID:   "7f3c9b10-aaaa-bbbb",
		Username:     "alice@contoso.onmicrosoft.com",
		Email:        email,
		AutoCreate:   true,
	}
}

// The migration case this exists for: a Lark-provisioned account meets a
// Teams login. Auto-create is ON, and must still not fire.
func TestResolveExternalLogin_OffersLinkInsteadOfSecondAccount(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "Alice", "Alice@Example.COM")

	_, err := svc.ResolveExternalLogin(context.Background(), teamsLogin("alice@example.com"))

	var link *ExternalLinkRequired
	if !errors.As(err, &link) {
		t.Fatalf("err = %v, want *ExternalLinkRequired", err)
	}
	if !errors.Is(err, ErrExternalLinkRequired) {
		t.Fatal("errors.Is(err, ErrExternalLinkRequired) = false; the sentinel is how callers match")
	}
	if link.UserID != 10 {
		t.Fatalf("candidate = %d, want 10", link.UserID)
	}
	// Nothing was created: the whole point is that auto-create did not fire.
	var users, identities int64
	db.Model(&User{}).Count(&users)
	db.Model(&UserIdentity{}).Count(&identities)
	if users != 1 || identities != 0 {
		t.Fatalf("users=%d identities=%d, want 1 and 0 — no account and no binding may be written before the holder proves ownership", users, identities)
	}
}

// The error must not name the account. It reaches server logs, and on the
// portal side it reaches a redirect; an unmasked value there turns the flow
// into "does this person have an account at this company".
func TestExternalLinkRequired_ErrorStringCarriesNoIdentifiers(t *testing.T) {
	e := &ExternalLinkRequired{UserID: 10, Username: "alice", Email: "alice@example.com"}
	for _, leak := range []string{"alice", "example.com", "10"} {
		if contains(e.Error(), leak) {
			t.Fatalf("Error() = %q, must not contain %q", e.Error(), leak)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

// Username agreement is not enough, and that is the design: the two IdPs in
// play report usernames in different shapes, so a username match would be
// both missed here and spurious elsewhere.
func TestResolveExternalLogin_UsernameMatchAloneDoesNotOfferLink(t *testing.T) {
	svc, db := newLinkTestService(t)
	// Same username, modulo case. No email at all on the local account.
	seedLocalUser(t, db, 10, "alice", "")

	in := teamsLogin("alice@example.com")
	if _, err := svc.ResolveExternalLogin(context.Background(), in); err != nil {
		t.Fatalf("expected auto-create, got %v", err)
	}
	var users int64
	db.Model(&User{}).Count(&users)
	if users != 2 {
		t.Fatalf("users = %d, want 2 (a username match must not be treated as the same person)", users)
	}
}

// Two accounts on one address is a data problem an administrator settles.
// Picking one would be picking who receives the identity.
func TestResolveExternalLogin_AmbiguousEmailRefuses(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "alice", "dup@example.com")
	seedLocalUser(t, db, 11, "alice2", "DUP@example.com")

	_, err := svc.ResolveExternalLogin(context.Background(), teamsLogin("dup@example.com"))
	if !errors.Is(err, ErrExternalLinkAmbiguous) {
		t.Fatalf("err = %v, want ErrExternalLinkAmbiguous", err)
	}
	var identities int64
	db.Model(&UserIdentity{}).Count(&identities)
	if identities != 0 {
		t.Fatalf("identities = %d, want 0", identities)
	}
}

// A candidate that already signs in through this same provider is refused.
// "The same person has a second Microsoft account" and "two different people"
// look identical from here, and the account already holding a working binding
// is the one with something to lose.
func TestResolveExternalLogin_CandidateAlreadyBoundToSameProviderRefuses(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "alice", "alice@example.com")
	now := time.Now().UTC()
	if err := db.Create(&UserIdentity{
		ID: 50, UserID: 10, TenantID: 1,
		ProviderType: "teams", ProviderID: "teams", ExternalID: "some-other-oid",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	_, err := svc.ResolveExternalLogin(context.Background(), teamsLogin("alice@example.com"))
	if !errors.Is(err, ErrExternalLinkAmbiguous) {
		t.Fatalf("err = %v, want ErrExternalLinkAmbiguous", err)
	}
}

// A candidate bound to a DIFFERENT provider is the migration case and must be
// offered — that is a Lark account meeting its owner's Teams login.
func TestResolveExternalLogin_CandidateBoundToOtherProviderIsOffered(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "alice", "alice@example.com")
	now := time.Now().UTC()
	if err := db.Create(&UserIdentity{
		ID: 50, UserID: 10, TenantID: 1,
		ProviderType: "lark", ProviderID: "lark", ExternalID: "ou_existing",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	_, err := svc.ResolveExternalLogin(context.Background(), teamsLogin("alice@example.com"))
	var link *ExternalLinkRequired
	if !errors.As(err, &link) || link.UserID != 10 {
		t.Fatalf("err = %v, want link offer for user 10", err)
	}
}

// No email from the IdP means nothing to match on. Falling back to the
// username here is the thing this design rejects.
func TestResolveExternalLogin_NoEmailFallsThroughToAutoCreate(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "alice", "alice@example.com")

	in := teamsLogin("")
	if _, err := svc.ResolveExternalLogin(context.Background(), in); err != nil {
		t.Fatalf("expected auto-create, got %v", err)
	}
	var users int64
	db.Model(&User{}).Count(&users)
	if users != 2 {
		t.Fatalf("users = %d, want 2", users)
	}
}

// With auto-create OFF — the setting recommended during a provider migration
// — a matched account must still be offered. Otherwise the safe configuration
// is also the one that blocks every user, and the operator is pushed toward
// the unsafe one.
func TestResolveExternalLogin_LinkOfferedEvenWhenAutoCreateDisabled(t *testing.T) {
	svc, db := newLinkTestService(t)
	seedLocalUser(t, db, 10, "alice", "alice@example.com")

	in := teamsLogin("alice@example.com")
	in.AutoCreate = false
	_, err := svc.ResolveExternalLogin(context.Background(), in)
	var link *ExternalLinkRequired
	if !errors.As(err, &link) {
		t.Fatalf("err = %v, want *ExternalLinkRequired even with AutoCreate=false", err)
	}
}

// An unmatched identity with auto-create off keeps the old refusal: the new
// path must not quietly turn "no account here" into something else.
func TestResolveExternalLogin_NoMatchAutoCreateOffStillNotLinked(t *testing.T) {
	svc, _ := newLinkTestService(t)
	in := teamsLogin("nobody@example.com")
	in.AutoCreate = false
	if _, err := svc.ResolveExternalLogin(context.Background(), in); !errors.Is(err, ErrExternalUserNotLinked) {
		t.Fatalf("err = %v, want ErrExternalUserNotLinked", err)
	}
}
