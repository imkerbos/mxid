package bootstrap

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A panicking worker must not take the process with it.
//
// An unrecovered panic in any goroutine kills the whole program, so before this
// one bad row could stop every login in the deployment: the reconcile worker
// runs on startup, panics on the row, the pod dies, Kubernetes restarts it, the
// row is still there. CrashLoopBackOff until somebody finds and deletes the
// data — which is exactly what happened in the field.
//
// If this test is ever "fixed" by removing the recover, the failure mode is a
// full outage, not a failed test: `go test` would report the panic here, but
// production would report nothing at all until the pod stopped coming up.
func TestSpawnWorkerContainsAPanic(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	a := &App{Logger: zap.New(core)}

	done := make(chan struct{})
	a.SpawnWorker(func() {
		defer close(done)
		panic("a rule expression tripped a nil dereference")
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never ran")
	}

	// Reaching here at all is the assertion: an unrecovered panic would have
	// taken the test binary down. The rest checks the operator can still find
	// the underlying defect.
	a.workers.Wait()

	entries := logs.FilterMessageSnippet("goroutine panicked").All()
	if len(entries) != 1 {
		t.Fatalf("want exactly one panic log, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["recover"] == nil {
		t.Error("the panic value was not logged — the cause would be unknowable")
	}
	if stack, ok := fields["stack"].(string); !ok || stack == "" {
		t.Error("no stack was logged — the defect stays unfindable, and it still has to be fixed")
	}
	if fields["job"] == nil {
		t.Error("no job name was logged — the operator cannot tell which job stopped")
	}
}

// A worker that returns normally must not log a panic, so the ERROR above stays
// a signal rather than noise.
func TestSpawnWorkerLogsNothingOnACleanReturn(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	a := &App{Logger: zap.New(core)}

	ran := make(chan struct{})
	a.SpawnWorker(func() { close(ran) })

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never ran")
	}
	a.workers.Wait()

	if n := logs.Len(); n != 0 {
		t.Errorf("a clean worker logged %d error(s): %v", n, logs.All())
	}
}
