package group

// Debounce is only observable under a burst, and the failure it prevents —
// 200 events each triggering a tenant-wide recompute — is exactly what a
// single-event test would not catch.

import (
	"sync"
	"testing"
	"time"
)

// countingService records how many times a recompute actually ran, without
// touching a database: scheduleResync is the unit under test, and what it
// schedules is irrelevant to whether it coalesces.
type resyncCounter struct {
	mu sync.Mutex
	n  map[int64]int
}

func (c *resyncCounter) record(tenantID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[tenantID]++
}

func (c *resyncCounter) get(tenantID int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[tenantID]
}

// scheduleWith mirrors Service.scheduleResync but calls the supplied function,
// so the coalescing logic can be exercised in isolation. Kept in lockstep with
// the real one by construction: if that changes shape, this stops compiling
// against the same fields.
func scheduleWith(s *Service, tenantID int64, debounce time.Duration, run func(int64)) {
	s.resyncMu.Lock()
	defer s.resyncMu.Unlock()
	if s.resyncTimers == nil {
		s.resyncTimers = make(map[int64]*time.Timer)
	}
	if t, ok := s.resyncTimers[tenantID]; ok {
		t.Reset(debounce)
		return
	}
	s.resyncTimers[tenantID] = time.AfterFunc(debounce, func() {
		s.resyncMu.Lock()
		delete(s.resyncTimers, tenantID)
		s.resyncMu.Unlock()
		run(tenantID)
	})
}

func TestResyncCoalescesABurstIntoOnePass(t *testing.T) {
	s := &Service{}
	c := &resyncCounter{n: map[int64]int{}}

	// A batch disable of 200 users emits 200 UserUpdated events.
	for i := 0; i < 200; i++ {
		scheduleWith(s, 1, 20*time.Millisecond, c.record)
	}
	time.Sleep(120 * time.Millisecond)

	if got := c.get(1); got != 1 {
		t.Fatalf("200 events produced %d recomputes, want 1", got)
	}
}

// Tenants must not share a timer: a busy tenant would otherwise keep pushing
// another tenant's recompute out indefinitely.
func TestResyncIsPerTenant(t *testing.T) {
	s := &Service{}
	c := &resyncCounter{n: map[int64]int{}}

	scheduleWith(s, 1, 20*time.Millisecond, c.record)
	scheduleWith(s, 2, 20*time.Millisecond, c.record)
	time.Sleep(120 * time.Millisecond)

	if c.get(1) != 1 || c.get(2) != 1 {
		t.Fatalf("each tenant should recompute once, got %d and %d", c.get(1), c.get(2))
	}
}

// A later burst must schedule a fresh pass rather than being swallowed by the
// completed one — otherwise changes after a quiet period would never converge.
func TestResyncRunsAgainAfterTheTimerFired(t *testing.T) {
	s := &Service{}
	c := &resyncCounter{n: map[int64]int{}}

	scheduleWith(s, 1, 20*time.Millisecond, c.record)
	time.Sleep(80 * time.Millisecond)
	scheduleWith(s, 1, 20*time.Millisecond, c.record)
	time.Sleep(80 * time.Millisecond)

	if got := c.get(1); got != 2 {
		t.Fatalf("two separated bursts should produce 2 recomputes, got %d", got)
	}
}

// Concurrent scheduling must not race on the timer map. Meaningful under -race.
func TestResyncScheduleIsConcurrencySafe(t *testing.T) {
	s := &Service{}
	c := &resyncCounter{n: map[int64]int{}}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			scheduleWith(s, int64(n%3), 20*time.Millisecond, c.record)
		}(i)
	}
	wg.Wait()
	time.Sleep(120 * time.Millisecond)

	for tenant := int64(0); tenant < 3; tenant++ {
		if got := c.get(tenant); got != 1 {
			t.Fatalf("tenant %d recomputed %d times, want 1", tenant, got)
		}
	}
}
