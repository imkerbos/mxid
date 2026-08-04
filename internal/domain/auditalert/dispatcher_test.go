package auditalert

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/outbox"
)

type recordingEnqueuer struct {
	mu   sync.Mutex
	msgs []*outbox.Message
}

func (e *recordingEnqueuer) Enqueue(_ context.Context, msg *outbox.Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.msgs = append(e.msgs, msg)
	return nil
}

func (e *recordingEnqueuer) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.msgs)
}

func (e *recordingEnqueuer) last() *outbox.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.msgs) == 0 {
		return nil
	}
	return e.msgs[len(e.msgs)-1]
}

func policyOf(p Policy) PolicyProvider {
	return func(context.Context, int64) (Policy, error) { return p, nil }
}

func newRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func sampleAlert() Alert {
	return Alert{
		AuditID:   1,
		TenantID:  1,
		Time:      time.Now(),
		EventType: "user.deleted",
		ActorName: "admin",
		IP:        "203.0.113.4",
	}
}

func TestDispatchEnqueuesMatchingEvent(t *testing.T) {
	rdb, _ := newRedis(t)
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.deleted", "user.locked"},
	}), enq, rdb, time.Minute, nil)

	d.Dispatch(context.Background(), sampleAlert())

	if enq.count() != 1 {
		t.Fatalf("enqueued %d messages, want 1", enq.count())
	}
	msg := enq.last()
	if msg.Kind != Kind {
		t.Errorf("kind = %q, want %q", msg.Kind, Kind)
	}
	var got Alert
	if err := json.Unmarshal(msg.Payload, &got); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if got.EventType != "user.deleted" || got.ActorName != "admin" {
		t.Errorf("payload lost fields: %+v", got)
	}
}

func TestDispatchIgnoresUnselectedEvents(t *testing.T) {
	rdb, _ := newRedis(t)
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.locked"},
	}), enq, rdb, time.Minute, nil)

	d.Dispatch(context.Background(), sampleAlert()) // user.deleted

	if enq.count() != 0 {
		t.Errorf("an unselected event was alerted on")
	}
}

func TestDispatchNoOpWhenUnconfigured(t *testing.T) {
	rdb, _ := newRedis(t)
	cases := []struct {
		name string
		pol  Policy
	}{
		{"no webhook", Policy{EventTypes: []string{"user.deleted"}}},
		{"no event types", Policy{WebhookURL: "https://hook.example.com/a"}},
		{"nothing at all", Policy{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enq := &recordingEnqueuer{}
			New(policyOf(tc.pol), enq, rdb, time.Minute, nil).
				Dispatch(context.Background(), sampleAlert())
			if enq.count() != 0 {
				t.Errorf("alerted with an incomplete policy")
			}
		})
	}
}

// Ten thousand failed logins is one incident. An alert channel that floods gets
// muted, which is the same as not having one.
func TestCooldownSuppressesAStorm(t *testing.T) {
	rdb, _ := newRedis(t)
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.deleted"},
	}), enq, rdb, time.Minute, nil)

	for range 100 {
		d.Dispatch(context.Background(), sampleAlert())
	}

	if enq.count() != 1 {
		t.Fatalf("100 identical events produced %d alerts, want 1", enq.count())
	}
}

// A suppressed burst must not vanish silently: the next alert says how many
// occurrences it stands for, because "one failed login" and "one failed login,
// plus 4000 you did not hear about" are different incidents.
func TestSuppressedCountIsReportedOnTheNextAlert(t *testing.T) {
	rdb, mr := newRedis(t)
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.deleted"},
	}), enq, rdb, time.Minute, nil)

	d.Dispatch(context.Background(), sampleAlert()) // fires
	for range 7 {
		d.Dispatch(context.Background(), sampleAlert()) // suppressed
	}

	var first Alert
	_ = json.Unmarshal(enq.last().Payload, &first)
	if first.SuppressedSinceLast != 0 {
		t.Errorf("first alert reported %d suppressed, want 0", first.SuppressedSinceLast)
	}

	mr.FastForward(2 * time.Minute) // cooldown expires
	d.Dispatch(context.Background(), sampleAlert())

	if enq.count() != 2 {
		t.Fatalf("enqueued %d alerts, want 2", enq.count())
	}
	var second Alert
	if err := json.Unmarshal(enq.last().Payload, &second); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if second.SuppressedSinceLast != 7 {
		t.Errorf("suppressed_since_last = %d, want 7", second.SuppressedSinceLast)
	}
}

// Different event types are separate incidents and must not share a cooldown.
func TestCooldownIsPerEventType(t *testing.T) {
	rdb, _ := newRedis(t)
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.deleted", "user.locked"},
	}), enq, rdb, time.Minute, nil)

	a := sampleAlert()
	d.Dispatch(context.Background(), a)
	a.EventType = "user.locked"
	d.Dispatch(context.Background(), a)

	if enq.count() != 2 {
		t.Errorf("enqueued %d alerts, want 2 — one cooldown swallowed another event type", enq.count())
	}
}

// An alerting path that goes quiet when Redis is down would be least useful
// exactly when infrastructure is misbehaving. Suppression is an optimisation;
// notifying is the job.
func TestFailsOpenWithoutRedis(t *testing.T) {
	enq := &recordingEnqueuer{}
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{"user.deleted"},
	}), enq, nil, time.Minute, nil)

	d.Dispatch(context.Background(), sampleAlert())
	d.Dispatch(context.Background(), sampleAlert())

	if enq.count() != 2 {
		t.Errorf("enqueued %d alerts without Redis, want 2 (fail open)", enq.count())
	}
}

func TestEventTypeMatchIsForgivingOfWhitespaceAndCase(t *testing.T) {
	rdb, _ := newRedis(t)
	enq := &recordingEnqueuer{}
	// An administrator typing a comma-separated list produces exactly this.
	d := New(policyOf(Policy{
		WebhookURL: "https://hook.example.com/a",
		EventTypes: []string{" User.Deleted "},
	}), enq, rdb, time.Minute, nil)

	d.Dispatch(context.Background(), sampleAlert())

	if enq.count() != 1 {
		t.Errorf("a padded, differently-cased event type did not match")
	}
}

func TestNilDispatcherIsSafe(t *testing.T) {
	var d *Dispatcher
	d.Dispatch(context.Background(), sampleAlert())
}
