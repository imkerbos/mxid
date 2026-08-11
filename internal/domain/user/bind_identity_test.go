package user

// Self-service binding is the only path that recovers an external login without
// an administrator ever typing an external_id — typing one would let anyone with
// user.identity.manage graft a colleague's Lark account onto an account they
// control. Here the caller has completed OAuth, which proves they hold the
// external account; the only question left is who currently holds it locally.
//
// BindExternalIdentity branches on OWNER first, then on row state — see the
// decision table in external_login.go's doc comment. The two axes matter
// independently: a same-owner soft-deleted row (an admin unbound this exact
// user, who is now self-recovering) is a "reclaim", audited as an ordinary
// bind; a different-owner row (soft-deleted, or live with its owner gone) is
// a genuine "takeover", audited with the previous owner on record. Getting
// the two confused would make the most common, most benign recovery
// indistinguishable in the audit trail from an actual identity transfer.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newBindTestFixture(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	svc, _, db := newDeleteCascadeTestService(t)
	now := time.Now().UTC()
	for _, u := range []*User{
		{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: 1, Username: "other", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
		{ID: 3, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", u.ID, err)
		}
	}
	return svc, db
}

// newBindTestFixtureWithEvents is a second, narrower assembly helper — not a
// duplicate of newDeleteCascadeTestService's general wiring (newBindTestFixture
// above already reuses that for every other test in this file), but a version
// that exposes the event.Bus itself. newDeleteCascadeTestService builds its
// own private bus with no way to subscribe from outside, and the reclaim vs.
// takeover distinction can ONLY be observed on the published event (the end
// table state — one live row, right owner — is identical either way), so a
// test that tells them apart has no way to avoid this.
func newBindTestFixtureWithEvents(t *testing.T) (*Service, *gorm.DB, chan event.Event) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &UserDetail{}, &UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewGormRepository(db)
	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("new id gen: %v", err)
	}
	bus := event.NewBus(zap.NewNop())
	got := make(chan event.Event, 8)
	bus.Subscribe(event.UserUpdated, func(_ context.Context, e event.Event) { got <- e })
	svc := NewService(repo, idGen, bus, &bootstrap.SecurityConfig{}, nil, "")

	now := time.Now().UTC()
	for _, u := range []*User{
		{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
		{ID: 2, TenantID: 1, Username: "other", PasswordHash: "x", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", u.ID, err)
		}
	}
	return svc, db, got
}

func bindInput(userID int64) *BindIdentityInput {
	return &BindIdentityInput{
		TenantID: 1, UserID: userID,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		DisplayName: "Layne",
	}
}

func TestBindCreatesWhenExternalIDIsFree(t *testing.T) {
	svc, db := newBindTestFixture(t)
	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("bind: %v", err)
	}
	var got UserIdentity
	if err := db.Where("external_id = ?", "ext-1").First(&got).Error; err != nil {
		t.Fatalf("binding must exist: %v", err)
	}
	if got.UserID != 1 {
		t.Fatalf("binding must attach to the caller, got user %d", got.UserID)
	}
}

// TestBindPersistsRawIntoExtra pins that BindIdentityInput.Raw is not a
// write-only field: the create path must JSON-encode it into Extra exactly
// as ResolveExternalLogin does for the equivalent data on a login-time
// binding, not silently discard it.
func TestBindPersistsRawIntoExtra(t *testing.T) {
	svc, db := newBindTestFixture(t)
	in := bindInput(1)
	in.Raw = map[string]any{"union_id": "u-123", "open_id": "o-456"}

	if err := svc.BindExternalIdentity(context.Background(), in); err != nil {
		t.Fatalf("bind: %v", err)
	}
	var got UserIdentity
	if err := db.Where("external_id = ?", "ext-1").First(&got).Error; err != nil {
		t.Fatalf("binding must exist: %v", err)
	}
	if got.Extra == nil || *got.Extra == "" {
		t.Fatal("Raw must be persisted into Extra, got nil/empty")
	}
	for _, want := range []string{"union_id", "u-123", "open_id", "o-456"} {
		if !strings.Contains(*got.Extra, want) {
			t.Fatalf("Extra must contain %q from the raw profile, got %q", want, *got.Extra)
		}
	}
}

// TestBindPicksTheMostRecentlyUnboundRow pins the tiebreak among soft-deleted
// rows. The partial unique index constrains only LIVE rows, so one
// (tenant, provider_type, external_id) can accumulate many deleted ones — one
// per past unbind — and GetAnyIdentityByExternal's `deleted_at IS NULL DESC`
// alone leaves the choice among them to the planner. That choice decides
// whether BindExternalIdentity sees the caller's own row (a reclaim) or a
// stranger's (a takeover): the same end state, a different audit event.
//
// Seeded so the planner's natural order (by rowid) returns the WRONG row: the
// older unbind has the lower id.
func TestBindPicksTheMostRecentlyUnboundRow(t *testing.T) {
	svc, db, events := newBindTestFixtureWithEvents(t)
	now := time.Now().UTC()

	// id 10 — user 2's binding, unbound long ago.
	// id 20 — user 1's binding (the caller's own), unbound most recently.
	for _, seed := range []struct {
		id, userID int64
		deletedAt  time.Time
	}{
		{id: 10, userID: 2, deletedAt: now.Add(-48 * time.Hour)},
		{id: 20, userID: 1, deletedAt: now.Add(-1 * time.Hour)},
	} {
		if err := db.Exec(
			`INSERT INTO mxid_user_identity (id, user_id, tenant_id, provider_type, provider_id, external_id, created_at, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			seed.id, seed.userID, 1, "lark", "p1", "ext-1", now, now, seed.deletedAt,
		).Error; err != nil {
			t.Fatalf("seed %d: %v", seed.id, err)
		}
	}

	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("bind: %v", err)
	}

	var live []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 || live[0].ID != 20 {
		t.Fatalf("bind must restore the most recently unbound row (id 20), got %+v", live)
	}

	// And the audit consequence: restoring the caller's OWN row is a reclaim,
	// never a takeover. Picking id 10 would have produced the opposite event
	// while reaching an indistinguishable table state — which is why this test
	// asserts on the event and not only on the row.
	select {
	case e := <-events:
		payload, ok := e.Payload.(map[string]any)
		if !ok {
			t.Fatalf("unexpected payload type %T", e.Payload)
		}
		if payload["action"] != "identity_bound" {
			t.Fatalf("restoring the caller's own most recent row is a reclaim, got action %v", payload["action"])
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected a bind event, none arrived")
	}
}

// TestBindPersistsRawIntoExtraOnReclaimAndTakeover extends the create-path
// test above to the two branches that go through RestoreIdentityTo instead of
// CreateIdentity. Both call setIdentityExtra before the write, but the update
// map named only user_id / external_name / deleted_at / updated_at — so the
// assignment was a dead write and the row kept whatever profile it carried
// before it was unbound. The create-only test could not see that, because the
// create path uses a different write.
func TestBindPersistsRawIntoExtraOnReclaimAndTakeover(t *testing.T) {
	cases := []struct {
		name string
		// seedOwner is the user the pre-existing soft-deleted row belongs to:
		// the caller themselves (reclaim) or somebody else (takeover).
		seedOwner int64
	}{
		{name: "reclaim (caller's own unbound row)", seedOwner: 1},
		{name: "takeover (another user's unbound row)", seedOwner: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, db := newBindTestFixture(t)
			now := time.Now().UTC()
			stale := `{"union_id":"STALE"}`
			if err := db.Create(&UserIdentity{
				ID: 10, UserID: tc.seedOwner, TenantID: 1,
				ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
				Extra:     &stale,
				CreatedAt: now, UpdatedAt: now,
			}).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
			// An administrator unbinds it: soft delete only, both users stay live.
			if err := db.Where("id = ?", 10).Delete(&UserIdentity{}).Error; err != nil {
				t.Fatalf("unbind: %v", err)
			}

			in := bindInput(1)
			in.Raw = map[string]any{"union_id": "u-123", "open_id": "o-456"}
			if err := svc.BindExternalIdentity(context.Background(), in); err != nil {
				t.Fatalf("bind: %v", err)
			}

			var got UserIdentity
			if err := db.Where("id = ?", 10).First(&got).Error; err != nil {
				t.Fatalf("binding must be live again: %v", err)
			}
			if got.Extra == nil {
				t.Fatal("Extra must be persisted on this path too, got nil")
			}
			if strings.Contains(*got.Extra, "STALE") {
				t.Fatalf("the pre-unbind profile must be replaced by the one the IdP "+
					"just returned, still got %q", *got.Extra)
			}
			for _, want := range []string{"union_id", "u-123", "open_id", "o-456"} {
				if !strings.Contains(*got.Extra, want) {
					t.Fatalf("Extra must contain %q from the raw profile, got %q", want, *got.Extra)
				}
			}
		})
	}
}

func TestBindRefusesWhenHeldByLiveUser(t *testing.T) {
	svc, db := newBindTestFixture(t)
	now := time.Now().UTC()
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 2, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := svc.BindExternalIdentity(context.Background(), bindInput(1))
	if !errors.Is(err, ErrExternalIDTaken) {
		t.Fatalf("want ErrExternalIDTaken, got %v", err)
	}

	// The live binding must be untouched: it still belongs to user 2.
	var still UserIdentity
	if err := db.Where("external_id = ?", "ext-1").First(&still).Error; err != nil {
		t.Fatalf("live binding must still exist: %v", err)
	}
	if still.UserID != 2 {
		t.Fatalf("refused bind must not move the live binding, got owner %d", still.UserID)
	}
}

// TestBindTakesOverSomeoneElsesSoftDeletedRow covers the "different owner,
// soft-deleted row" table entry: an administrator already severed user 3
// from this external account (via Service.Delete's binding sweep), so the
// row BindExternalIdentity sees is already soft-deleted by the time it looks.
// This exercises the unconditional "someone else's deleted row" branch —
// takeover regardless of whether GetByID can still find user 3 — NOT the
// GetByID liveness check itself. See
// TestBindTakesOverLiveOrphanRowWhenOwnerIsGone below for the branch this
// test does NOT cover: a row that is still LIVE when BindExternalIdentity
// looks, whose owner has to be discovered gone via GetByID.
func TestBindTakesOverSomeoneElsesSoftDeletedRow(t *testing.T) {
	svc, db := newBindTestFixture(t)
	now := time.Now().UTC()
	// user 3 is the "layne-1" shell that auto-provisioning minted and an admin
	// then deleted, taking the real external_id down with it.
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 3, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.Delete(context.Background(), 3); err != nil {
		t.Fatalf("delete shell account: %v", err)
	}

	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("takeover from a deleted account must succeed: %v", err)
	}

	var live []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 || live[0].UserID != 1 {
		t.Fatalf("exactly one live binding must remain, owned by the caller; got %+v", live)
	}
	if live[0].ID != 10 {
		t.Fatalf("takeover must move the existing row, not mint a new one; got id %d", live[0].ID)
	}
}

// TestBindTakesOverLiveOrphanRowWhenOwnerIsGone covers the table entry the
// review found genuinely uncovered: "someone else's row, LIVE, owner
// deleted" — the pre-Task-9 orphan shape (ResolveExternalLogin's own doc
// comment names it), where the identity row was never swept because the
// owner was removed by some path that predates or bypasses the sweep. The
// row is still live by ordinary gorm scoping when BindExternalIdentity looks
// it up; only the explicit GetByID(existing.UserID) check inside
// BindExternalIdentity discovers the owner is gone. The user row is deleted
// directly through the repository (NOT svc.Delete, which sweeps bindings) so
// the identity row starts — and, until BindExternalIdentity's GetByID check
// runs, stays — live. This is deliberately the state
// TestBindTakesOverSomeoneElsesSoftDeletedRow does NOT produce.
func TestBindTakesOverLiveOrphanRowWhenOwnerIsGone(t *testing.T) {
	svc, repo, db := newDeleteCascadeTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.Create(&User{ID: 1, TenantID: 1, Username: "layne", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed caller: %v", err)
	}
	if err := db.Create(&User{ID: 3, TenantID: 1, Username: "layne-1", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
		t.Fatalf("seed shell owner: %v", err)
	}
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 3, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	// repo.Delete soft-deletes ONLY the user row — it does not sweep
	// bindings (that ordering lives in Service.Delete, added by Task 9).
	// This reproduces the orphan shape: owner gone, binding still live.
	if err := repo.Delete(ctx, 3); err != nil {
		t.Fatalf("delete owner directly: %v", err)
	}

	// Sanity check on the precondition itself: if this fails, the test
	// below would silently degrade into TestBindTakesOverSomeoneElsesSoftDeletedRow
	// instead of testing what it claims to.
	var stillLive UserIdentity
	if err := db.Where("id = ?", 10).First(&stillLive).Error; err != nil {
		t.Fatalf("identity row must still be LIVE before bind (this test's whole point): %v", err)
	}
	if _, err := repo.GetByID(ctx, 3); err == nil {
		t.Fatal("owner must be gone from live lookups before bind (this test's whole point)")
	}

	if err := svc.BindExternalIdentity(ctx, bindInput(1)); err != nil {
		t.Fatalf("takeover of a live orphan row must succeed: %v", err)
	}

	var live []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 || live[0].UserID != 1 {
		t.Fatalf("exactly one live binding must remain, owned by the caller; got %+v", live)
	}
	if live[0].ID != 10 {
		t.Fatalf("takeover must move the existing row, not mint a new one; got id %d", live[0].ID)
	}
}

// TestBindReclaimsOwnRowWithoutTakeoverEvent covers the row the review's
// controller ruling added: the caller's OWN row, soft-deleted (an
// administrator unbound this exact user, who now self-recovers via OAuth).
// The end table state (one live row, owned by user 1) is identical to a
// cross-user takeover, so the only way to tell "reclaim" and "takeover"
// apart is the emitted event — this test asserts on that, not on table
// state, and would not catch a regression that only checked row counts.
func TestBindReclaimsOwnRowWithoutTakeoverEvent(t *testing.T) {
	svc, db, events := newBindTestFixtureWithEvents(t)
	now := time.Now().UTC()
	if err := db.Create(&UserIdentity{
		ID: 10, UserID: 1, TenantID: 1,
		ProviderType: "lark", ProviderID: "p1", ExternalID: "ext-1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// An administrator unbinds user 1's OWN identity — soft-delete only,
	// user 1 stays live. Same shape DeleteIdentity produces in production.
	if err := db.Where("user_id = ? AND id = ?", 1, 10).Delete(&UserIdentity{}).Error; err != nil {
		t.Fatalf("unbind: %v", err)
	}

	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("reclaim by the same owner must succeed: %v", err)
	}

	var live []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&live).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) != 1 || live[0].UserID != 1 || live[0].ID != 10 {
		t.Fatalf("reclaim must restore the SAME row to the SAME owner; got %+v", live)
	}

	select {
	case e := <-events:
		payload, ok := e.Payload.(map[string]any)
		if !ok {
			t.Fatalf("unexpected payload type %T", e.Payload)
		}
		if payload["action"] == "identity_taken_over" {
			t.Fatalf("same-owner reclaim must NOT be audited as a takeover, got action %v", payload["action"])
		}
		if _, has := payload["previous_user_id"]; has {
			t.Fatalf("same-owner reclaim must carry no previous_user_id, got payload %+v", payload)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected an identity_bound event for the reclaim, none arrived")
	}
}

// TestBindIsIdempotentForSameUser pins ruling 4: a user who is already bound to
// this exact external account must get neither an error nor a duplicate row.
// Without the early-return in BindExternalIdentity, this would either violate
// the partial unique index (mis-surfaced as ErrExternalIDTaken against the
// caller's own binding) or, if the index check were skipped, insert a second
// live row for the same external id.
func TestBindIsIdempotentForSameUser(t *testing.T) {
	svc, db := newBindTestFixture(t)

	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if err := svc.BindExternalIdentity(context.Background(), bindInput(1)); err != nil {
		t.Fatalf("repeat bind by the same user must be a no-op, got: %v", err)
	}

	var all []UserIdentity
	if err := db.Where("external_id = ?", "ext-1").Find(&all).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("repeat bind must not create a duplicate row, got %d", len(all))
	}
}

// TestBindSurfacesTypedErrorOnCreateRace pins the no-locking ruling for the
// free-external-id branch: BindExternalIdentity's occupancy check
// (GetAnyIdentityByExternal) and its CreateIdentity call are not atomic, so a
// concurrent first-time bind for the same external id can land in the gap.
// The partial unique index is the real backstop in production; here a gorm
// "before create" hook fires the racing insert at the exact moment between
// the check and the write, deterministically reproducing the race without
// real goroutines (same technique as
// TestRestoreSurfacesTypedErrorOnIndexRace in identity_restore_test.go). The
// assertion is that the driver's raw unique-violation error is translated to
// ErrExternalIDTaken, never leaked to the caller.
func TestBindSurfacesTypedErrorOnCreateRace(t *testing.T) {
	svc, db := newBindTestFixture(t)

	if err := db.Exec(`CREATE UNIQUE INDEX uk_user_identity_external
		ON mxid_user_identity (tenant_id, provider_type, external_id)
		WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create partial unique index: %v", err)
	}

	raced := false
	db.Callback().Create().Before("gorm:create").Register("test:racing-bind-insert", func(tx *gorm.DB) {
		if raced {
			return
		}
		// Only fire for the identity insert BindExternalIdentity is about to
		// make, not the fixture's own user seeding earlier in the test.
		if _, ok := tx.Statement.Dest.(*UserIdentity); !ok {
			return
		}
		raced = true
		now := time.Now().UTC()
		if err := tx.Exec(
			`INSERT INTO mxid_user_identity (id, user_id, tenant_id, provider_type, provider_id, external_id, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			999, 2, 1, "lark", "p1", "ext-1", now, now,
		).Error; err != nil {
			t.Fatalf("racing insert: %v", err)
		}
	})

	err := svc.BindExternalIdentity(context.Background(), bindInput(1))
	if !raced {
		t.Fatal("race hook never fired, test did not exercise the intended window")
	}
	if !errors.Is(err, ErrExternalIDTaken) {
		t.Fatalf("want the index violation surfaced as ErrExternalIDTaken, got %v", err)
	}
}
