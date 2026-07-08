package authz

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// stubBindings counts EffectiveBindingsForUser calls so tests can assert
// cache hit/miss behaviour without dragging in a real DB.
type stubBindings struct {
	calls atomic.Int64
	data  []EffectiveBinding
	err   error
}

func (s *stubBindings) EffectiveBindingsForUser(_ context.Context, _, _ int64) ([]EffectiveBinding, error) {
	s.calls.Add(1)
	return s.data, s.err
}

func sampleBindings() []EffectiveBinding {
	return []EffectiveBinding{{
		RoleID:      7,
		Permissions: map[string]struct{}{"user.read": {}, "user.update": {}},
		Source:      "direct",
		SourceID:    42,
		ScopeType:   ScopeOrg,
		ScopeID:     99,
	}}
}

func newRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func TestCache_L1Hit(t *testing.T) {
	ctx := context.Background()
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, nil, CacheOptions{L1TTL: time.Second})

	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)

	if got := stub.calls.Load(); got != 1 {
		t.Errorf("expected 1 DB call (L1 cached), got %d", got)
	}
}

func TestCache_L1Expiry(t *testing.T) {
	ctx := context.Background()
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, nil, CacheOptions{L1TTL: 10 * time.Millisecond})

	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	time.Sleep(20 * time.Millisecond)
	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)

	if got := stub.calls.Load(); got != 2 {
		t.Errorf("expected 2 DB calls after L1 expiry, got %d", got)
	}
}

func TestCache_L2HitAfterL1Eviction(t *testing.T) {
	ctx := context.Background()
	rdb, _ := newRedis(t)
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, rdb,
		CacheOptions{L1TTL: 10 * time.Millisecond, L2TTL: time.Minute})

	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	time.Sleep(20 * time.Millisecond)
	c.l1Clear()

	got, err := c.EffectiveBindingsForUser(ctx, 1, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].RoleID != 7 {
		t.Fatalf("L2 round-trip lost data: %#v", got)
	}
	if stub.calls.Load() != 1 {
		t.Errorf("expected L2 hit avoids extra DB call, got %d calls", stub.calls.Load())
	}
}

func TestCache_InvalidateClearsBothLevels(t *testing.T) {
	ctx := context.Background()
	rdb, mr := newRedis(t)
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, rdb, CacheOptions{})

	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	if err := c.Invalidate(ctx, 1, 100); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if mr.Exists(cacheKey(1, 100)) {
		t.Errorf("L2 should be deleted by Invalidate")
	}
	c.mu.RLock()
	_, present := c.l1[cacheKey(1, 100)]
	c.mu.RUnlock()
	if present {
		t.Errorf("L1 should be deleted by Invalidate")
	}
}

func TestCache_InvalidateAllClearsL1(t *testing.T) {
	ctx := context.Background()
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, nil, CacheOptions{})

	_, _ = c.EffectiveBindingsForUser(ctx, 1, 100)
	_, _ = c.EffectiveBindingsForUser(ctx, 1, 200)
	if err := c.InvalidateAll(ctx); err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}
	c.mu.RLock()
	n := len(c.l1)
	c.mu.RUnlock()
	if n != 0 {
		t.Errorf("InvalidateAll should empty L1, got %d entries", n)
	}
}

func TestCache_BindingProviderErrorNotCached(t *testing.T) {
	ctx := context.Background()
	stub := &stubBindings{err: context.DeadlineExceeded}
	c := NewCachedBindingProvider(ctx, stub, nil, CacheOptions{})

	if _, err := c.EffectiveBindingsForUser(ctx, 1, 100); err == nil {
		t.Fatalf("expected DB error to propagate")
	}
	// Recover and ensure next call retries the DB rather than serving
	// a stale empty cached value.
	stub.err = nil
	stub.data = sampleBindings()
	if _, err := c.EffectiveBindingsForUser(ctx, 1, 100); err != nil {
		t.Fatalf("recovery call: %v", err)
	}
	if stub.calls.Load() != 2 {
		t.Errorf("error must not poison cache, want 2 DB calls got %d", stub.calls.Load())
	}
}

func TestCache_PubSubInvalidatesPeerL1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb, _ := newRedis(t)
	stub := &stubBindings{data: sampleBindings()}
	peerA := NewCachedBindingProvider(ctx, stub, rdb, CacheOptions{})
	peerB := NewCachedBindingProvider(ctx, stub, rdb, CacheOptions{})

	_, _ = peerA.EffectiveBindingsForUser(ctx, 1, 100)
	_, _ = peerB.EffectiveBindingsForUser(ctx, 1, 100)

	// peerA emits invalidate → peerB's subscriber goroutine should drop
	// its L1 entry.
	if err := peerA.Invalidate(ctx, 1, 100); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}

	// Allow the subscriber goroutine to consume the message.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		peerB.mu.RLock()
		_, present := peerB.l1[cacheKey(1, 100)]
		peerB.mu.RUnlock()
		if !present {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("peer B's L1 was not invalidated within the deadline")
}

// InvalidateAll must purge the shared L2 (Redis) entries, not just clear L1.
// Previously it left L2 to age out on its TTL (up to 5 min), so a permission
// change routed through the coarse InvalidateAll fallback (e.g. a group/org
// role-member add) stayed stale for minutes. purgeL2 runs async, so poll.
func TestCache_InvalidateAllPurgesL2(t *testing.T) {
	ctx := context.Background()
	rdb, mr := newRedis(t)
	stub := &stubBindings{data: sampleBindings()}
	c := NewCachedBindingProvider(ctx, stub, rdb, CacheOptions{L1TTL: time.Minute, L2TTL: time.Hour})

	// Prime L1+L2 for the user.
	if _, err := c.EffectiveBindingsForUser(ctx, 1, 100); err != nil {
		t.Fatalf("prime: %v", err)
	}
	key := cacheKey(1, 100)
	if _, err := mr.Get(key); err != nil {
		t.Fatalf("L2 not primed: %v", err)
	}

	if err := c.InvalidateAll(ctx); err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}

	// purgeL2 is async — poll until the key is gone.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !mr.Exists(key) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("InvalidateAll did not purge L2 within deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
