package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewManager(rdb, 30*time.Minute, 12*time.Hour)
}

func TestStepUpFresh(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { tt := now.Add(-d); return &tt }

	cases := []struct {
		name     string
		verified *time.Time
		window   time.Duration
		want     bool
	}{
		{"never verified", nil, 30 * time.Minute, false},
		{"within window", ago(10 * time.Minute), 30 * time.Minute, true},
		{"exactly at edge is stale", ago(30 * time.Minute), 30 * time.Minute, false},
		{"expired", ago(31 * time.Minute), 30 * time.Minute, false},
		{"zero window forces challenge", ago(1 * time.Second), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{MFAVerifiedAt: tc.verified}
			if got := s.StepUpFresh(now, tc.window); got != tc.want {
				t.Fatalf("StepUpFresh = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMarkMFAVerified_PersistsTimestamp(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	sess, err := m.Create(ctx, NamespaceConsole, 1, 1, "1.2.3.4", "ua", "password")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Fresh session has never passed MFA.
	if sess.MFAVerifiedAt != nil {
		t.Fatalf("new session should have nil MFAVerifiedAt")
	}

	if err := m.MarkMFAVerified(ctx, NamespaceConsole, sess.ID); err != nil {
		t.Fatalf("mark: %v", err)
	}

	got, err := m.Get(ctx, NamespaceConsole, sess.ID)
	if err != nil || got == nil {
		t.Fatalf("get after mark: %v", err)
	}
	if got.MFAVerifiedAt == nil {
		t.Fatalf("MFAVerifiedAt not persisted")
	}
	if !got.StepUpFresh(time.Now(), 30*time.Minute) {
		t.Fatalf("freshly verified session should be step-up fresh")
	}
}

func TestMarkMFAVerified_MissingSessionNoError(t *testing.T) {
	m := newTestManager(t)
	if err := m.MarkMFAVerified(context.Background(), NamespaceConsole, "does-not-exist"); err != nil {
		t.Fatalf("missing session must be a no-op, got %v", err)
	}
}

func TestSetEnrollPending_PersistsAndClears(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Create(ctx, NamespaceConsole, 1, 1, "ip", "ua", "password")
	if sess.MFAEnrollPending {
		t.Fatalf("new session must not be enroll-pending")
	}

	if err := m.SetEnrollPending(ctx, NamespaceConsole, sess.ID, true); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	got, _ := m.Get(ctx, NamespaceConsole, sess.ID)
	if got == nil || !got.MFAEnrollPending {
		t.Fatalf("pending flag not persisted")
	}

	if err := m.SetEnrollPending(ctx, NamespaceConsole, sess.ID, false); err != nil {
		t.Fatalf("clear pending: %v", err)
	}
	got, _ = m.Get(ctx, NamespaceConsole, sess.ID)
	if got == nil || got.MFAEnrollPending {
		t.Fatalf("pending flag not cleared")
	}
}

// Create must flag the session MFAEnrollPending when the enroll decider fires —
// the single chokepoint that makes mandatory MFA apply to EVERY login method
// (password / SMS / magic link / external IdP), not just the password handler.
func TestManager_Create_EnrollDecider(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	m := NewManager(rdb, 30*time.Minute, 12*time.Hour)

	// No decider → not pending.
	s1, err := m.Create(context.Background(), NamespaceConsole, 1, 1, "ip", "ua", "external_idp")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s1.MFAEnrollPending {
		t.Fatal("no decider must leave MFAEnrollPending=false")
	}

	// Decider true → pending, regardless of the auth method (here: external IdP).
	m.SetEnrollDecider(func(_ context.Context, tenantID, userID int64) bool {
		return tenantID == 1 && userID == 2
	})
	s2, err := m.Create(context.Background(), NamespaceConsole, 2, 1, "ip", "ua", "external_idp")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !s2.MFAEnrollPending {
		t.Fatal("decider=true must set MFAEnrollPending on the created session")
	}
	// And it must survive a round-trip through redis.
	got, err := m.Get(context.Background(), NamespaceConsole, s2.ID)
	if err != nil || got == nil || !got.MFAEnrollPending {
		t.Fatalf("persisted session must keep MFAEnrollPending: %+v err=%v", got, err)
	}

	// Decider false for a different user → not pending.
	s3, _ := m.Create(context.Background(), NamespaceConsole, 3, 1, "ip", "ua", "sms_otp")
	if s3.MFAEnrollPending {
		t.Fatal("decider=false must leave the session unflagged")
	}
}
