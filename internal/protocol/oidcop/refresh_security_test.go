package oidcop

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
)

// fakeUserStatus is a stub UserStatusResolver for the disabled-account guard
// tests below.
type fakeUserStatus struct {
	active bool
	err    error
}

func (f fakeUserStatus) IsUserActive(ctx context.Context, userID string) (bool, error) {
	return f.active, f.err
}

// seedRefreshChain stores a fresh access token + refresh token pair (as the
// initial code-flow issuance would) and returns the refresh record.
func seedRefreshChain(t *testing.T, s *Storage, refreshID, accessID, clientID, subject string) *refreshToken {
	t.Helper()
	ctx := context.Background()
	access := &accessToken{
		ID:         accessID,
		ClientID:   clientID,
		Subject:    subject,
		Expiration: time.Now().Add(time.Hour),
	}
	if err := s.setJSON(ctx, kToken(access.ID), access, time.Hour); err != nil {
		t.Fatalf("seed access token: %v", err)
	}
	rt, err := s.storeRefreshToken(ctx, refreshID, access, nil, time.Now(), "")
	if err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	return rt
}

// --- A. Disabled-account guard ----------------------------------------------

// TestTokenRequestByRefreshToken_DisabledUser_Rejected proves that a refresh
// token whose owner is no longer active is rejected on presentation, mirroring
// the hand-rolled engine's guard (internal/protocol/oidc/handler.go:838).
func TestTokenRequestByRefreshToken_DisabledUser_Rejected(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: false}

	rt := seedRefreshChain(t, s, "rt-disabled-0", "at-disabled-0", "client1", "42")

	if _, err := s.TokenRequestByRefreshToken(context.Background(), rt.Token); err == nil {
		t.Fatal("expected refresh to be rejected for a disabled user, got nil error")
	}
}

// TestTokenRequestByRefreshToken_DisabledUser_EndsFamily proves the guard does
// more than deny-this-once: the token (and its family) is actually revoked,
// so a re-presentation — even if the account were reactivated in between —
// finds nothing live.
func TestTokenRequestByRefreshToken_DisabledUser_EndsFamily(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: false}

	rt := seedRefreshChain(t, s, "rt-disabled-1", "at-disabled-1", "client1", "42")

	if _, err := s.TokenRequestByRefreshToken(context.Background(), rt.Token); err == nil {
		t.Fatal("expected refresh to be rejected for a disabled user")
	}

	// Even if the account is reactivated afterwards, the already-revoked
	// token must stay dead.
	s.users = fakeUserStatus{active: true}
	if _, err := s.TokenRequestByRefreshToken(context.Background(), rt.Token); err == nil {
		t.Fatal("expected the token to remain revoked after the disabled-account guard tripped")
	}
}

// --- B. Reuse detection + family cascade ------------------------------------

// TestRefreshRotation_HappyPath proves normal rotation still works: presenting
// the live token T0 rotates it into T1, and T1 is then usable.
func TestRefreshRotation_HappyPath(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: true}
	ctx := context.Background()

	rt0 := seedRefreshChain(t, s, "rt-happy-0", "at-happy-0", "client1", "42")

	access1 := &accessToken{ID: "at-happy-1", ClientID: "client1", Subject: "42", Expiration: time.Now().Add(time.Hour)}
	if err := s.setJSON(ctx, kToken(access1.ID), access1, time.Hour); err != nil {
		t.Fatalf("seed access1: %v", err)
	}
	if err := s.renewRefreshToken(ctx, rt0.Token, "rt-happy-1", access1); err != nil {
		t.Fatalf("happy-path rotation failed: %v", err)
	}

	if _, err := s.TokenRequestByRefreshToken(ctx, "rt-happy-1"); err != nil {
		t.Fatalf("rotated (current) token should still be valid, got: %v", err)
	}
}

// TestRefreshReuse_RevokesFamilyIncludingLiveDescendant is the core WS3-B
// scenario: T0 rotates into T1 (normal), then T0 (now spent) is replayed.
// That must revoke the ENTIRE family — including T1, the legitimate client's
// current live token — not just deny the replay itself.
func TestRefreshReuse_RevokesFamilyIncludingLiveDescendant(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: true}
	ctx := context.Background()

	rt0 := seedRefreshChain(t, s, "rt-reuse-0", "at-reuse-0", "client1", "42")

	access1 := &accessToken{ID: "at-reuse-1", ClientID: "client1", Subject: "42", Expiration: time.Now().Add(time.Hour)}
	if err := s.setJSON(ctx, kToken(access1.ID), access1, time.Hour); err != nil {
		t.Fatalf("seed access1: %v", err)
	}
	if err := s.renewRefreshToken(ctx, rt0.Token, "rt-reuse-1", access1); err != nil {
		t.Fatalf("rotation T0->T1 failed: %v", err)
	}

	// Sanity: T1 works before the replay.
	if _, err := s.TokenRequestByRefreshToken(ctx, "rt-reuse-1"); err != nil {
		t.Fatalf("T1 should be valid before replay, got: %v", err)
	}

	// Replay the spent T0.
	if _, err := s.TokenRequestByRefreshToken(ctx, rt0.Token); err == nil {
		t.Fatal("expected an error presenting a spent (already-rotated) refresh token")
	}

	// T1 — the live descendant, never itself presented twice — must now ALSO
	// be dead: that is the family cascade.
	if _, err := s.TokenRequestByRefreshToken(ctx, "rt-reuse-1"); err == nil {
		t.Fatal("expected family cascade to revoke the live descendant token T1 too")
	}
}

// TestRefreshReuse_NeverTriggersOnCurrentToken proves the cascade triggers
// ONLY on presenting a spent token — presenting the still-live current token
// twice in a row (no rotation in between) must not revoke anything; the
// second presentation just sees the same live record.
func TestRefreshReuse_NeverTriggersOnCurrentToken(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: true}
	ctx := context.Background()

	rt0 := seedRefreshChain(t, s, "rt-live-0", "at-live-0", "client1", "42")

	if _, err := s.TokenRequestByRefreshToken(ctx, rt0.Token); err != nil {
		t.Fatalf("first read of the live token should succeed, got: %v", err)
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, rt0.Token); err != nil {
		t.Fatalf("re-reading the still-live (never rotated) token should succeed, got: %v", err)
	}
}

// --- Reuse audit -------------------------------------------------------------

// TestRefreshReuse_EmitsAuditEvent proves detected reuse raises the
// event.OIDCTokenReuse signal, mirroring the hand-rolled engine's
// handler.go:804 emitAudit call.
func TestRefreshReuse_EmitsAuditEvent(t *testing.T) {
	s := newTestStorage(t)
	s.users = fakeUserStatus{active: true}
	bus := event.NewBus(zap.NewNop())
	s.events = bus
	ctx := context.Background()

	// event.Bus fans out to handlers in goroutines, so the handler and the test
	// body run concurrently — deliver via a channel rather than a shared slice
	// (the latter is a data race under -race).
	captured := make(chan event.Event, 4)
	bus.Subscribe(event.OIDCTokenReuse, func(_ context.Context, evt event.Event) {
		captured <- evt
	})

	rt0 := seedRefreshChain(t, s, "rt-audit-0", "at-audit-0", "client1", "42")

	access1 := &accessToken{ID: "at-audit-1", ClientID: "client1", Subject: "42", Expiration: time.Now().Add(time.Hour)}
	if err := s.setJSON(ctx, kToken(access1.ID), access1, time.Hour); err != nil {
		t.Fatalf("seed access1: %v", err)
	}
	if err := s.renewRefreshToken(ctx, rt0.Token, "rt-audit-1", access1); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	// Replay the spent token.
	if _, err := s.TokenRequestByRefreshToken(ctx, rt0.Token); err == nil {
		t.Fatal("expected an error presenting a spent refresh token")
	}

	// Publish is async — wait for the single reuse event.
	var evt event.Event
	select {
	case evt = <-captured:
	case <-time.After(time.Second):
		t.Fatal("expected exactly 1 OIDCTokenReuse event, got 0")
	}
	// No second event should follow (reuse fires once).
	select {
	case extra := <-captured:
		t.Fatalf("expected exactly 1 OIDCTokenReuse event, got a second: %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}

	payload, ok := evt.Payload.(map[string]any)
	if !ok {
		t.Fatalf("expected payload to be map[string]any, got %T", evt.Payload)
	}
	if payload["client_id"] != "client1" {
		t.Fatalf("expected client_id=client1 in reuse audit payload, got %v", payload["client_id"])
	}
}
