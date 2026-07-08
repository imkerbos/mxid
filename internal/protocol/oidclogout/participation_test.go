package oidclogout

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestIndex(t *testing.T) *Index {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewIndex(rdb)
}

// TestParticipation_PeekIsNonDestructive verifies Peek returns the tracked
// app IDs without consuming the Redis set — repeated Peek calls must return
// the same result.
func TestParticipation_PeekIsNonDestructive(t *testing.T) {
	idx := newTestIndex(t)
	ctx := context.Background()
	sid := "sess-1"

	if err := idx.Track(ctx, sid, 1001, time.Hour); err != nil {
		t.Fatalf("Track appA: %v", err)
	}
	if err := idx.Track(ctx, sid, 1002, time.Hour); err != nil {
		t.Fatalf("Track appB: %v", err)
	}

	got, err := idx.Peek(ctx, sid)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if !containsAll(got, 1001, 1002) {
		t.Fatalf("Peek #1 = %v, want to contain 1001 and 1002", got)
	}

	// Peek again — must be repeatable (non-destructive).
	got2, err := idx.Peek(ctx, sid)
	if err != nil {
		t.Fatalf("Peek #2: %v", err)
	}
	if !containsAll(got2, 1001, 1002) {
		t.Fatalf("Peek #2 = %v, want to still contain 1001 and 1002 (Peek must not destroy)", got2)
	}
}

// TestParticipation_ListIsDestructive verifies List returns the tracked app
// IDs and then empties the set — a subsequent List/Peek must return nothing.
func TestParticipation_ListIsDestructive(t *testing.T) {
	idx := newTestIndex(t)
	ctx := context.Background()
	sid := "sess-2"

	if err := idx.Track(ctx, sid, 2001, time.Hour); err != nil {
		t.Fatalf("Track appA: %v", err)
	}
	if err := idx.Track(ctx, sid, 2002, time.Hour); err != nil {
		t.Fatalf("Track appB: %v", err)
	}

	got, err := idx.List(ctx, sid)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsAll(got, 2001, 2002) {
		t.Fatalf("List = %v, want to contain 2001 and 2002", got)
	}

	// The set must now be empty.
	got2, err := idx.Peek(ctx, sid)
	if err != nil {
		t.Fatalf("Peek after List: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("Peek after List = %v, want empty (List must be destructive)", got2)
	}

	got3, err := idx.List(ctx, sid)
	if err != nil {
		t.Fatalf("List #2: %v", err)
	}
	if len(got3) != 0 {
		t.Fatalf("List #2 = %v, want empty", got3)
	}
}

// TestParticipation_EmptySID guards against panics/queries on an empty
// session id (mirrors the reference store's ssoSID == "" short-circuit).
func TestParticipation_EmptySID(t *testing.T) {
	idx := newTestIndex(t)
	ctx := context.Background()

	if err := idx.Track(ctx, "", 1, time.Hour); err != nil {
		t.Fatalf("Track empty sid: %v", err)
	}
	if got, err := idx.Peek(ctx, ""); err != nil || len(got) != 0 {
		t.Fatalf("Peek empty sid = %v, %v", got, err)
	}
	if got, err := idx.List(ctx, ""); err != nil || len(got) != 0 {
		t.Fatalf("List empty sid = %v, %v", got, err)
	}
}

func containsAll(got []int64, want ...int64) bool {
	set := make(map[int64]bool, len(got))
	for _, id := range got {
		set[id] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return len(got) == len(want)
}
