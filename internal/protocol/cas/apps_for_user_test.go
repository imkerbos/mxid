package cas

import (
	"context"
	"slices"
	"testing"
	"time"
)

// AppsForUser drives the CAS side of global logout: enumerate every app a user
// has an active CAS service session to, and drop an app once its registry
// entry is cleared.
func TestServiceRegistry_AppsForUser(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	ctx := context.Background()
	const userID = int64(5001)

	if err := r.RecordService(ctx, userID, 2001, "https://a.example/cb", "ST-a", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordService(ctx, userID, 2002, "https://b.example/cb", "ST-b", time.Hour); err != nil {
		t.Fatal(err)
	}

	apps, err := r.AppsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	slices.Sort(apps)
	if !slices.Equal(apps, []int64{2001, 2002}) {
		t.Fatalf("AppsForUser = %v, want [2001 2002]", apps)
	}

	// Clearing one app's services removes it from the per-user index.
	if err := r.Clear(ctx, userID, 2001); err != nil {
		t.Fatal(err)
	}
	apps, _ = r.AppsForUser(ctx, userID)
	if !slices.Equal(apps, []int64{2002}) {
		t.Fatalf("after clear, AppsForUser = %v, want [2002]", apps)
	}
}

func TestServiceRegistry_AppsForUser_Empty(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	apps, err := r.AppsForUser(context.Background(), 9999)
	if err != nil || len(apps) != 0 {
		t.Fatalf("want empty, got %v err=%v", apps, err)
	}
}
