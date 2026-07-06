package portal

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// TestStartBrokerRedisSubscriber_FansOutToLocalBroker verifies that an event
// published on the portal:events Redis channel (as would happen from another
// pod's AttachBusSubscribers) reaches a local sseBroker subscriber.
func TestStartBrokerRedisSubscriber_FansOutToLocalBroker(t *testing.T) {
	rdb := newTestRedis(t)

	startBrokerRedisSubscriber(rdb, zap.NewNop())

	ch := sseBroker.subscribe()
	defer sseBroker.unsubscribe(ch)

	// Give the subscription goroutine a moment to actually subscribe before
	// publishing (miniredis pub/sub is synchronous per-connection but the
	// Go client's Channel() consumer goroutine still needs to start).
	time.Sleep(50 * time.Millisecond)

	data, err := json.Marshal(brokerEvent{Type: "apps_updated", Payload: map[string]any{"x": 1}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := rdb.Publish(context.Background(), portalEventsChannel, data).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.Type != "apps_updated" {
			t.Fatalf("expected type apps_updated, got %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for redis-fanned-out event")
	}
}

// TestAttachBusSubscribers_NilRDBFallsBackToLocalBroker verifies that with a
// nil rdb (dev/tests), bus events still reach the local broker directly,
// preserving today's in-process behavior.
func TestAttachBusSubscribers_NilRDBFallsBackToLocalBroker(t *testing.T) {
	bus := event.NewBus(nil)
	AttachBusSubscribers(bus, nil, zap.NewNop())

	ch := sseBroker.subscribe()
	defer sseBroker.unsubscribe(ch)

	bus.Publish(context.Background(), event.Event{Type: "app_access.changed", Payload: map[string]any{"y": 2}})

	select {
	case ev := <-ch:
		if ev.Type != "apps_updated" {
			t.Fatalf("expected type apps_updated, got %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-process fallback event")
	}
}
