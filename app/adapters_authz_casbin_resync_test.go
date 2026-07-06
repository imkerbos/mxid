package app

// Verifies that a Casbin resync broadcast published by a peer replica is
// picked up on this pod's Redis subscriber and triggers a local
// engine.Sync — the cross-pod half of wireCasbinSync. The in-process event
// bus path (same-pod resync) is exercised elsewhere; this test isolates the
// pub/sub propagation so a regression there (e.g. wrong channel name, no
// subscriber goroutine) fails loudly instead of only showing up as stale
// permissions on non-publishing replicas in production.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/authz"
)

// countingPolicyLoader is a fake authz.PolicyLoader whose LoadPolicies
// increments a counter each call, so tests can assert a resync happened
// without wiring a real DB.
type countingPolicyLoader struct {
	calls atomic.Int64
}

func (l *countingPolicyLoader) LoadPolicies(_ context.Context) ([]authz.RolePolicy, []int64, error) {
	l.calls.Add(1)
	return nil, nil, nil
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestStartCasbinResyncSubscriber_PeerBroadcastTriggersLocalSync(t *testing.T) {
	rdb := newTestRedis(t)
	engine, err := authz.NewCasbinEngine()
	if err != nil {
		t.Fatalf("NewCasbinEngine: %v", err)
	}
	loader := &countingPolicyLoader{}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startCasbinResyncSubscriber(ctx, rdb, engine, loader, nil)

	// Give the subscribe goroutine a moment to attach before publishing —
	// miniredis pub/sub only delivers to subscribers registered at publish
	// time, same as real Redis.
	deadline := time.Now().Add(time.Second)
	for rdb.PubSubNumSub(ctx, casbinResyncChannel).Val()[casbinResyncChannel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never attached to channel")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := rdb.Publish(ctx, casbinResyncChannel, "1").Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline = time.Now().Add(time.Second)
	for loader.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("resync subscriber did not call loader within timeout (calls=%d)", loader.calls.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartCasbinResyncSubscriber_NilRedisIsNoop(t *testing.T) {
	engine, err := authz.NewCasbinEngine()
	if err != nil {
		t.Fatalf("NewCasbinEngine: %v", err)
	}
	loader := &countingPolicyLoader{}

	// Must not panic when Redis is unavailable — the in-process-only path
	// stays intact.
	startCasbinResyncSubscriber(context.Background(), nil, engine, loader, nil)

	time.Sleep(50 * time.Millisecond)
	if got := loader.calls.Load(); got != 0 {
		t.Errorf("expected no sync with nil redis, got %d calls", got)
	}
}
