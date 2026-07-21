package saml

import (
	"context"
	"slices"
	"testing"
	"time"
)

// AppsForUser drives the SAML side of global logout: it must enumerate every
// app a user holds a SAML session to, and drop an app once its session index
// is deleted (so a later global logout doesn't fan out to a dead SP).
func TestSessionIndexStore_AppsForUser(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	ctx := context.Background()
	const userID = int64(5001)

	ref := SAMLSessionRef{SessionIndex: "idx", NameID: "u@x", SPEntityID: "sp", NameIDFormat: NameIDEmail}
	if err := s.Record(ctx, userID, 1001, ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, userID, 1002, ref, time.Hour); err != nil {
		t.Fatal(err)
	}

	apps, err := s.AppsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	slices.Sort(apps)
	if !slices.Equal(apps, []int64{1001, 1002}) {
		t.Fatalf("AppsForUser = %v, want [1001 1002]", apps)
	}

	// Deleting one app's session removes it from the per-user index.
	if err := s.Delete(ctx, userID, 1001); err != nil {
		t.Fatal(err)
	}
	apps, _ = s.AppsForUser(ctx, userID)
	if !slices.Equal(apps, []int64{1002}) {
		t.Fatalf("after delete, AppsForUser = %v, want [1002]", apps)
	}
}

// No sessions → empty, not an error.
func TestSessionIndexStore_AppsForUser_Empty(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	apps, err := s.AppsForUser(context.Background(), 9999)
	if err != nil || len(apps) != 0 {
		t.Fatalf("want empty, got %v err=%v", apps, err)
	}
}
