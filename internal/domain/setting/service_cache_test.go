package setting

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// testKey is deliberately NOT in sensitiveFields so Set/Get never touch
// masterKey (nil is fine for this test).
const testKey = "test.cache"

// fakeRepo is a tiny in-memory Repository so these tests never touch a real
// DB. Shared between two Service instances to simulate two pods reading/
// writing the same backing store.
type fakeRepo struct {
	mu   sync.Mutex
	rows map[string]*Setting
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: make(map[string]*Setting)}
}

func (f *fakeRepo) key(key string, tenantID int64) string {
	return cacheKeyFor(key, tenantID)
}

func (f *fakeRepo) Get(_ context.Context, key string, tenantID int64) (*Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.rows[f.key(key, tenantID)]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	cp := *s
	return &cp, nil
}

func (f *fakeRepo) Upsert(_ context.Context, s *Setting) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *s
	f.rows[f.key(s.Key, s.TenantID)] = &cp
	return nil
}

func (f *fakeRepo) List(_ context.Context, tenantID int64) ([]*Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*Setting
	for _, s := range f.rows {
		if s.TenantID == tenantID {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) Delete(_ context.Context, key string, tenantID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, f.key(key, tenantID))
	return nil
}

type cachePayload struct {
	V string `json:"v"`
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// TestCrossPodInvalidation simulates two pods sharing a DB and a Redis
// instance. Pod B warms its cache, pod A writes a new value; pod B must
// observe the new value quickly (via pub/sub eviction), not the stale one
// for up to cacheTTL.
func TestCrossPodInvalidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	repo := newFakeRepo()
	const tenantID = int64(1)

	if err := repo.Upsert(ctx, &Setting{Key: testKey, TenantID: tenantID, Value: []byte(`{"v":"old"}`)}); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}

	rdb := newTestRedis(t)

	svcA := NewService(repo, nil)
	svcA.SetRedisInvalidation(ctx, rdb)

	svcB := NewService(repo, nil)
	svcB.SetRedisInvalidation(ctx, rdb)

	// Warm pod B's cache with the old value.
	var warm cachePayload
	if err := svcB.Get(ctx, testKey, tenantID, &warm); err != nil {
		t.Fatalf("warm get: %v", err)
	}
	if warm.V != "old" {
		t.Fatalf("expected warm value 'old', got %q", warm.V)
	}

	// Pod A writes a new value: repo update + local invalidate + publish.
	if err := svcA.Set(ctx, testKey, tenantID, cachePayload{V: "new"}, nil); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Pod B should observe the new value shortly, without waiting for the
	// 60s cache TTL to expire — the pub/sub broadcast should have evicted
	// its stale entry immediately.
	deadline := time.Now().Add(2 * time.Second)
	var got cachePayload
	for {
		if err := svcB.Get(ctx, testKey, tenantID, &got); err != nil {
			t.Fatalf("poll get: %v", err)
		}
		if got.V == "new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pod B still serving stale value %q after deadline", got.V)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNilRedisInvalidationIsLocalOnly ensures a Service with no Redis wired
// still invalidates its own cache correctly and never panics.
func TestNilRedisInvalidationIsLocalOnly(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	const tenantID = int64(1)

	svc := NewService(repo, nil)
	svc.SetRedisInvalidation(ctx, nil) // nil rdb — must be a no-op, no panic

	if err := svc.Set(ctx, testKey, tenantID, cachePayload{V: "first"}, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	var got cachePayload
	if err := svc.Get(ctx, testKey, tenantID, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.V != "first" {
		t.Fatalf("expected 'first', got %q", got.V)
	}

	if err := svc.Set(ctx, testKey, tenantID, cachePayload{V: "second"}, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := svc.Get(ctx, testKey, tenantID, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.V != "second" {
		t.Fatalf("expected local invalidate to pick up 'second', got %q", got.V)
	}
}
