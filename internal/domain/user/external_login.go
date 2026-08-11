package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/event"
)

// ExternalLoginInput is the data the external-IdP feature hands to
// ResolveExternalLogin after a successful OAuth exchange. The external IdP
// implementation is EE-only (lives in the mxid-ee module); it reaches this CE
// account-linking entry point through the pkg/ee/registry seam, whose neutral
// registry.ResolverInput is field-identical to this struct.
type ExternalLoginInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any

	// AutoCreate controls behaviour when no binding exists. The caller pulls
	// this from ExternalIDP.AutoCreate.
	AutoCreate bool
	// DefaultOrgID auto-attaches new users to a department; nil = no attach.
	DefaultOrgID *int64
}

// ErrExternalUserDeleted means the external identity maps to a local account
// an administrator deleted. Auto-provisioning must not paper over this:
// deletion is an administrative decision and a login attempt does not get to
// overrule it. Two data shapes reach this: a live binding whose user row is
// gone (a pre-000068 orphan, predating Task 9's delete-time sweep), and a
// soft-deleted binding whose user is also soft-deleted. A soft-deleted
// binding whose user is still LIVE is a different situation — an
// administrator unbound the identity, not the account — and gets
// ErrExternalUserNotLinked instead; see ResolveExternalLogin.
var ErrExternalUserDeleted = errors.New("external identity belongs to a deleted account")

// ResolveExternalLogin maps an external identity to a local user ID.
//
//	live binding, user loads fine        → return its UserID (refresh attrs)
//	live binding, user row gone          → ErrExternalUserDeleted (orphan)
//	no live binding, prior binding found,
//	  its user is also deleted           → ErrExternalUserDeleted
//	no live binding, prior binding found,
//	  its user is still live             → ErrExternalUserNotLinked (the
//	                                        identity was unbound, not the
//	                                        account — never claim it was
//	                                        deleted when it wasn't)
//	no binding ever + auto               → create local user + identity row
//	no binding ever + !auto              → ErrExternalUserNotLinked so the
//	                                        caller renders a "no account,
//	                                        contact admin" page
//
// Neither of the "prior binding found" outcomes falls through to
// auto-create: an unbind is an administrator's intent exactly as a delete
// is, and a login must not silently overturn either by minting a fresh
// account.
//
// Idempotent on repeat logins from the same external user.
func (s *Service) ResolveExternalLogin(ctx context.Context, in *ExternalLoginInput) (*User, error) {
	if in.ExternalID == "" {
		return nil, fmt.Errorf("external id required")
	}

	binding, err := s.repo.GetIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID)
	if err == nil {
		// Refresh stored attrs opportunistically so console reflects latest IdP state.
		updated := false
		if in.DisplayName != "" && (binding.ExternalName == nil || *binding.ExternalName != in.DisplayName) {
			name := in.DisplayName
			binding.ExternalName = &name
			updated = true
		}
		if len(in.Raw) > 0 {
			if raw, mErr := json.Marshal(in.Raw); mErr == nil {
				s := string(raw)
				binding.Extra = &s
				updated = true
			}
		}
		if updated {
			binding.UpdatedAt = time.Now()
			_ = s.repo.UpdateIdentity(ctx, binding)
		}
		// Fetch the user row.
		u, err := s.repo.GetByID(ctx, binding.UserID)
		if err != nil {
			if dberr.IsNotFound(err) {
				// The binding is live but its user is gone: the account was
				// deleted before bindings were swept (pre-Task-9 orphan data).
				return nil, ErrExternalUserDeleted
			}
			return nil, fmt.Errorf("get linked user: %w", err)
		}
		return u, nil
	}
	if !dberr.IsNotFound(err) {
		return nil, fmt.Errorf("lookup identity: %w", err)
	}

	// No live binding. Before provisioning, check whether one existed and was
	// swept away — either because the user was deleted (Task 9's sweep) or
	// because an administrator unbound the identity while the account stayed
	// live (Task 6's restore flow). Auto-creating here would hand the
	// external account a brand-new empty profile and quietly overturn either
	// administrative decision.
	prior, perr := s.repo.GetAnyIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID)
	switch {
	case perr == nil:
		priorUser, uerr := s.repo.GetAnyByID(ctx, prior.UserID)
		if uerr != nil {
			if dberr.IsNotFound(uerr) {
				// The user row is gone entirely (not merely soft-deleted) —
				// same refusal as any other deleted account.
				return nil, ErrExternalUserDeleted
			}
			return nil, fmt.Errorf("check prior binding owner: %w", uerr)
		}
		if priorUser.DeletedAt.Valid {
			return nil, ErrExternalUserDeleted
		}
		// The account is still live: only the binding was unbound. Telling
		// this user their account was deleted would be false.
		return nil, ErrExternalUserNotLinked
	case dberr.IsNotFound(perr):
		// No binding ever existed for this external id — the genuinely fresh
		// case. Fall through to AutoCreate below.
	default:
		return nil, fmt.Errorf("check prior binding: %w", perr)
	}

	if !in.AutoCreate {
		return nil, ErrExternalUserNotLinked
	}

	// Auto-provision a local user. Username collisions get a `-N` suffix so
	// the operation is best-effort idempotent.
	username := pickUsername(in)
	finalUsername, err := s.allocUsername(ctx, in.TenantID, username)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user := &User{
		ID:        s.idGen.Generate(),
		TenantID:  in.TenantID,
		Username:  finalUsername,
		Status:    StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if in.Email != "" {
		// Only set email if not already used; otherwise leave blank.
		if _, err := s.repo.GetByEmail(ctx, in.TenantID, in.Email); err != nil && dberr.IsNotFound(err) {
			e := in.Email
			user.Email = &e
		}
	}
	if in.Phone != "" {
		if _, err := s.repo.GetByPhone(ctx, in.TenantID, in.Phone); err != nil && dberr.IsNotFound(err) {
			p := in.Phone
			user.Phone = &p
		}
	}
	if in.DisplayName != "" {
		d := in.DisplayName
		user.DisplayName = &d
	}
	if in.Avatar != "" {
		a := in.Avatar
		user.Avatar = &a
	}
	// External users have no local password — set a random hash that won't
	// match anything sane to keep PasswordHash NOT NULL contracts happy.
	random, err := randomDummyHash()
	if err != nil {
		return nil, err
	}
	user.PasswordHash = random

	// Seed an empty detail row so /users/:id/detail always returns something.
	detail := &UserDetail{
		ID:        s.idGen.Generate(),
		UserID:    user.ID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Build the identity row before writing anything: all three rows go in one
	// transaction below.
	rawJSON := ""
	if len(in.Raw) > 0 {
		if b, err := json.Marshal(in.Raw); err == nil {
			rawJSON = string(b)
		}
	}
	displayPtr := func() *string {
		if in.DisplayName == "" {
			return nil
		}
		v := in.DisplayName
		return &v
	}()
	extraPtr := func() *string {
		if rawJSON == "" {
			return nil
		}
		return &rawJSON
	}()
	identity := &UserIdentity{
		ID:           s.idGen.Generate(),
		UserID:       user.ID,
		TenantID:     in.TenantID,
		ProviderType: in.ProviderType,
		ProviderID:   in.ProviderID,
		ExternalID:   in.ExternalID,
		ExternalName: displayPtr,
		Extra:        extraPtr,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	// Atomic. Previously these were three separate writes, so a failure after
	// the user row committed left an account with no identity binding — and the
	// next login from the same external subject, finding no binding, created
	// another account under a suffixed username. One unreachable account and one
	// consumed seat per retry.
	if err := s.repo.CreateWithIdentity(ctx, user, detail, identity); err != nil {
		return nil, fmt.Errorf("create external user: %w", err)
	}

	return user, nil
}

// ErrExternalUserNotLinked is returned when no local binding exists and the
// IdP has auto_create disabled.
var ErrExternalUserNotLinked = errors.New("no local account linked to this external identity")

// pickUsername chooses the best candidate username from the external profile.
// Falls back through username → email local part → provider-prefixed externalID.
func pickUsername(in *ExternalLoginInput) string {
	u := strings.TrimSpace(in.Username)
	if u == "" && in.Email != "" {
		u = strings.SplitN(in.Email, "@", 2)[0]
	}
	if u == "" {
		u = in.ProviderType + "_" + in.ExternalID
	}
	// sanitise: keep alphanumerics, dot, dash, underscore.
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, u)
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		out = "user"
	}
	return out
}

// allocUsername returns the first variant of base that doesn't already exist.
// Loops with -1, -2, ... up to 999 before giving up.
func (s *Service) allocUsername(ctx context.Context, tenantID int64, base string) (string, error) {
	candidate := base
	for i := 0; i < 1000; i++ {
		_, err := s.repo.GetByUsername(ctx, tenantID, candidate)
		if dberr.IsNotFound(err) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("check username: %w", err)
		}
		candidate = fmt.Sprintf("%s-%d", base, i+1)
	}
	return "", fmt.Errorf("could not allocate unique username")
}

// randomDummyHash mints a bcrypt-shaped string that won't match any real
// password but still satisfies the NOT NULL constraint on password_hash.
func randomDummyHash() (string, error) {
	// We deliberately do NOT use the real crypto.HashPassword (bcrypt rounds
	// take ~100ms — wasted on a string that can never match). Encode 32
	// random bytes and prefix with the bcrypt signature so the column passes
	// any optional shape checks.
	b := make([]byte, 32)
	if _, err := randReadDummy(b); err != nil {
		return "", err
	}
	return crypto.NoLocalPasswordPrefix + fmt.Sprintf("%x", b), nil
}

// BindIdentityInput carries an already-authenticated external identity plus the
// logged-in local user it should attach to. Unlike ExternalLoginInput there are
// no auto-provision knobs: the caller is signed in, so there is nothing to
// provision.
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
}

// BindExternalIdentity attaches an external account to an existing local user.
// The caller must already have completed the IdP's authentication — that is
// what proves they hold the external account. This function decides who holds
// the row by owner first, then by row state — NOT by row state first: a
// same-owner soft-deleted row (an admin unbound this exact user, who is now
// self-recovering) must never be mistaken for a different-owner deleted row
// (a genuine takeover), because those two get different audit treatment.
//
//	no row at all                              → create
//	caller's own row, live                     → no-op (idempotent, already bound)
//	caller's own row, soft-deleted              → reclaim: restore to the SAME
//	                                              owner, an ordinary rebind event
//	someone else's row, live, owner still live  → refuse, ErrExternalIDTaken —
//	                                              taking it would move that
//	                                              user's login
//	someone else's row, live, owner deleted     → takeover (the pre-sweep
//	                                              orphan case: the row was
//	                                              never swept when its owner
//	                                              was deleted)
//	someone else's row, soft-deleted             → takeover — an administrator
//	                                              already unbound the other
//	                                              user from it; two people
//	                                              cannot hold the same
//	                                              external account, and the
//	                                              caller just proved they hold
//	                                              it now
//
// Only the last two rows are a takeover: audited as its own action, distinct
// from an ordinary bind, with the previous owner on record. The reclaim row
// deliberately gets an ordinary bind event instead — the account never
// changed hands, so recording it as a takeover would make the most common,
// most benign recovery indistinguishable from an actual identity transfer.
func (s *Service) BindExternalIdentity(ctx context.Context, in *BindIdentityInput) error {
	if in == nil || in.ExternalID == "" || in.UserID == 0 {
		return fmt.Errorf("user id and external id required")
	}

	// The caller must still be a live user in the tenant they claim. Nothing
	// upstream re-reads deleted_at on the request path: the EE callback takes
	// bindUserID from the Redis state entry and the tenant from the IdP row,
	// and session revocation on delete is best-effort and detached (app/run.go
	// publishes revokeUserSessions through safego.Go and only logs failures).
	// A soft-deleted user whose revocation did not land therefore still holds a
	// working cookie, and without this check could complete a bind — writing a
	// LIVE binding onto a deleted account, which is precisely the orphan shape
	// Service.Delete's identity sweep exists to eliminate.
	//
	// GetByID is soft-delete-scoped (GetAnyByID is the unscoped variant), so a
	// deleted caller is a not-found here.
	caller, err := s.repo.GetByID(ctx, in.UserID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("load bind caller: %w", err)
	}
	if caller.TenantID != in.TenantID {
		// Cross-tenant bind attempt: the identity's tenant comes from the IdP
		// row, the user id from the session. They must agree, or the binding
		// would live in a tenant its owner is not in.
		return ErrUserNotFound
	}

	existing, err := s.repo.GetAnyIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID)
	switch {
	case err == nil:
		if existing.UserID == in.UserID {
			// The caller already owns this row, whatever state it's in.
			if !existing.DeletedAt.Valid {
				return nil // already bound and live; idempotent no-op
			}
			return s.reclaimIdentity(ctx, existing, in)
		}
		// A different user owns the row.
		if !existing.DeletedAt.Valid {
			// Live binding on someone else. Refuse unless that owner is gone
			// — a live binding whose owner GetByID can't find is the
			// pre-sweep orphan shape (see ResolveExternalLogin's own
			// doc comment), not a row this branch should trust as occupied.
			if _, uerr := s.repo.GetByID(ctx, existing.UserID); uerr == nil {
				return ErrExternalIDTaken
			} else if !dberr.IsNotFound(uerr) {
				return fmt.Errorf("check binding owner: %w", uerr)
			}
			// Owner is deleted — fall through to takeover.
		}
		// Reaching here means either: a soft-deleted row on someone else
		// (administrator already severed that user from it), or a live row
		// on someone else whose account no longer exists. Both are takeovers.
		return s.takeOverIdentity(ctx, existing, in)
	case dberr.IsNotFound(err):
		// No binding, live or deleted, ever existed for this external id.
	default:
		return fmt.Errorf("lookup identity: %w", err)
	}

	now := time.Now()
	identity := &UserIdentity{
		ID:           s.idGen.Generate(),
		UserID:       in.UserID,
		TenantID:     in.TenantID,
		ProviderType: in.ProviderType,
		ProviderID:   in.ProviderID,
		ExternalID:   in.ExternalID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if in.DisplayName != "" {
		name := in.DisplayName
		identity.ExternalName = &name
	}
	setIdentityExtra(identity, in.Raw)
	if err := s.repo.CreateIdentity(ctx, identity); err != nil {
		if errors.Is(err, ErrExternalIDTaken) {
			return err
		}
		return fmt.Errorf("create identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": in.UserID, "action": "identity_bound", "provider": in.ProviderType},
	})
	return nil
}

// setIdentityExtra JSON-encodes raw into identity.Extra, matching the
// treatment ResolveExternalLogin gives the equivalent field on an existing
// binding. A marshal failure is swallowed exactly as it is there: Raw is
// best-effort diagnostic profile data, not required for the binding itself
// to succeed.
func setIdentityExtra(identity *UserIdentity, raw map[string]any) {
	if len(raw) == 0 {
		return
	}
	if b, err := json.Marshal(raw); err == nil {
		s := string(b)
		identity.Extra = &s
	}
}

// reclaimIdentity restores a binding the caller already owns but that an
// administrator soft-deleted (unbound), back to that SAME owner. This is not
// a takeover — the account never changed hands — so it is audited as an
// ordinary bind, with no previous_user_id: reserving the takeover event for
// the rows where an external identity genuinely moves between users.
func (s *Service) reclaimIdentity(ctx context.Context, existing *UserIdentity, in *BindIdentityInput) error {
	existing.UpdatedAt = time.Now()
	if in.DisplayName != "" {
		name := in.DisplayName
		existing.ExternalName = &name
	}
	setIdentityExtra(existing, in.Raw)
	if err := s.repo.RestoreIdentityTo(ctx, existing); err != nil {
		if errors.Is(err, ErrExternalIDTaken) {
			return err
		}
		return fmt.Errorf("reclaim identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": in.UserID, "action": "identity_bound", "provider": in.ProviderType},
	})
	return nil
}

// takeOverIdentity moves a binding whose previous owner is a DIFFERENT user
// — either deleted outright or already severed from this external account by
// an administrator's unbind — onto the caller. Audited as its own action,
// distinct from an ordinary bind: it is the one path where an external
// identity changes hands, and the previous owner is worth recording.
func (s *Service) takeOverIdentity(ctx context.Context, existing *UserIdentity, in *BindIdentityInput) error {
	prevOwner := existing.UserID
	existing.UserID = in.UserID
	existing.UpdatedAt = time.Now()
	if in.DisplayName != "" {
		name := in.DisplayName
		existing.ExternalName = &name
	}
	setIdentityExtra(existing, in.Raw)
	if err := s.repo.RestoreIdentityTo(ctx, existing); err != nil {
		if errors.Is(err, ErrExternalIDTaken) {
			return err
		}
		return fmt.Errorf("take over identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserUpdated,
		Payload: map[string]any{
			"user_id": in.UserID, "action": "identity_taken_over",
			"provider": in.ProviderType, "previous_user_id": prevOwner,
		},
	})
	return nil
}
