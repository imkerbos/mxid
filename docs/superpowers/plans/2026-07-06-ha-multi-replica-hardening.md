# HA Multi-Replica Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the whole MXID backend safe to run as N>1 replicas by eliminating every single-writer background job race, every stale per-pod cache, and the pod-local realtime/storage gaps found in the HA audit.

**Architecture:** Three fix patterns, applied per finding:
1. **Leader election** via a new `pkg/dlock` (Postgres session-level advisory lock on a dedicated connection) wraps the 4 single-writer background loops so exactly one pod runs each; automatic failover when the leader dies. On non-Postgres (sqlite tests) it degrades to a direct pass-through (single process = always leader).
2. **Cross-pod Redis pub/sub** broadcast (mirroring the existing `pkg/authz/cache.go` `authz:invalidate` pattern) propagates cache invalidations / reloads for Casbin authz, EE license, settings, and portal SSE.
3. **Shared persistent storage** (Helm PVC) + a DB uniqueness constraint hardens the audit anchor sink and anchor ledger.

**Tech Stack:** Go 1.25.11, GORM (Postgres primary + sqlite for unit tests), `redis/go-redis/v9`, `casbin`, Helm/Kubernetes.

## Global Constraints

- Go toolchain `go 1.25.11`. Do not bump.
- **No AI / Claude / Anthropic attribution** in commits or PRs — no `Co-Authored-By`, no "generated with". Conventional Commits, English subject, scopes like `feat(audit):`, `feat(dlock):`.
- **Squash-merge** the feature branch into one Conventional-Commit summary at the end; keep granular commits while working.
- **TDD**: failing test first, minimal impl, green, commit.
- **Postgres-specific behavior MUST have a gated pg e2e test.** Advisory locks and partial/unique indexes DO NOT exist / behave differently on sqlite. Per the jsonb postmortem (`docs/postmortems/2026-07-06-audit-jsonb-verify-failure.md`), sqlite unit tests cannot catch driver-specific behavior. Any task touching advisory locks or new DB constraints adds/extends a test guarded by `MXID_E2E_DSN` (throwaway Postgres), following the pattern in `internal/domain/audit/e2e_postgres_test.go`.
- Reuse the single shared `*redis.Client` (`app.Redis`, `internal/bootstrap/app.go:55`). Never construct a second Redis client.
- Reuse the shared `*gorm.DB` (`app.DB`, `internal/bootstrap/app.go:54`); get `*sql.DB` via `app.DB.DB()`.
- Follow the existing Redis channel naming style (`authz:invalidate`) for new channels.
- Every background worker start site in `app/run.go` must stay wrapped so it is a no-op-but-safe when NOT the leader; never remove the graceful-shutdown wiring (`workerCtx`).
- Next migration number is **000053**; increment for each new migration.

---

## File Structure

**New files:**
- `pkg/dlock/dlock.go` — leader-election primitive (advisory-lock on dedicated conn).
- `pkg/dlock/dlock_test.go` — unit tests (sqlite pass-through).
- `pkg/dlock/dlock_pg_e2e_test.go` — gated pg contention test.
- `internal/domain/authz` or extend `app/adapters_authz.go` — Casbin cross-pod resync subscriber (Redis).
- `migrations/000053_oidc_keyset_one_active.up.sql` / `.down.sql` — partial unique index ≤1 active key.
- `migrations/000054_audit_anchor_unique.up.sql` / `.down.sql` — unique constraint on anchor span.

**Modified files:**
- `app/run.go` — wrap `chainer.Run`, `anchorer.Run`, OIDC rotation, `access.StartSweeper` in `dlock.RunAsLeader`; subscribe License reload.
- `internal/domain/oidckey/rotation.go` / `service.go` — (only if the partial index needs the rotation WHERE clause aligned).
- `pkg/authz/casbin.go` / `app/adapters_authz.go` — publish + subscribe casbin resync over Redis.
- `internal/gateway/console/settings/handler.go` + `app/run.go` — publish `license:reload`; subscribe → re-read + `SetCurrent`.
- `internal/domain/setting/service.go` — publish `settings:invalidate` on `Set`; subscribe → local cache delete.
- `internal/gateway/portal/events.go` — back the SSE broker with Redis pub/sub.
- `deploy/helm/mxid/values.yaml`, `templates/backend-statefulset.yaml`, `templates/secret.yaml` — audit env keys + anchor-sink PVC.

---

## Priority Order (execute top to bottom)

1. Task 1 — `pkg/dlock` primitive (blocks Tasks 2,4,5,9)
2. Task 2 — 🔴 CRITICAL: OIDC key rotation → leader + ≤1-active index
3. Task 3 — 🔴 CRITICAL: Casbin authz cross-pod resync
4. Task 4 — 🟠 HIGH: audit chainer → leader
5. Task 5 — 🟠 HIGH: audit anchorer → leader + anchor unique constraint
6. Task 6 — 🟠 HIGH: audit anchor sink PVC + audit env keys in Helm
7. Task 7 — 🟠 HIGH: EE license cross-pod reload
8. Task 8 — 🟡 MEDIUM: settings cache cross-pod invalidation
9. Task 9 — 🟡 MEDIUM: JIT access sweeper → leader
10. Task 10 — 🟡 MEDIUM: portal SSE cross-pod via Redis pub/sub

---

### Task 1: `pkg/dlock` leader-election primitive

**Files:**
- Create: `pkg/dlock/dlock.go`
- Test: `pkg/dlock/dlock_test.go`
- Test (gated pg): `pkg/dlock/dlock_pg_e2e_test.go`

**Interfaces:**
- Produces:
  - `func RunAsLeader(ctx context.Context, db *gorm.DB, key int64, logger *zap.Logger, run func(ctx context.Context))` — Blocks until `ctx` is cancelled. Acquires a Postgres session-level advisory lock on `key` using a dedicated connection; once held, calls `run(leaderCtx)` where `leaderCtx` is cancelled if the lock connection dies or `ctx` is cancelled. If not acquired yet, retries every ~5s. On Postgres-lock loss it stops `run` and re-contends. On a NON-Postgres dialect (`db.Dialector.Name() != "postgres"`) it calls `run(ctx)` immediately and directly (single-process test/dev = always leader). Releases the lock + closes the conn on exit.
  - Advisory-lock key constants (define here so all callers share one namespace, avoiding accidental collisions):
    ```go
    const (
        KeyAuditChainer  int64 = 0x4D584944_0001 // "MXID" | 1
        KeyAuditAnchorer int64 = 0x4D584944_0002
        KeyOIDCRotation  int64 = 0x4D584944_0003
        KeyAccessSweeper int64 = 0x4D584944_0004
    )
    ```

- [ ] **Step 1: Write the failing unit test (sqlite pass-through)**

`pkg/dlock/dlock_test.go`:
```go
package dlock

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

// On sqlite (non-postgres) RunAsLeader must run `run` directly and pass through
// context cancellation for graceful shutdown.
func TestRunAsLeader_SQLitePassthrough(t *testing.T) {
	db := newSQLite(t)
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{})
	go RunAsLeader(ctx, db, KeyAuditChainer, zap.NewNop(), func(c context.Context) {
		close(ran)
		<-c.Done() // should unblock when parent ctx cancels
	})
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("run never invoked on sqlite")
	}
	cancel()
	// give the goroutine a moment; if leaderCtx wasn't derived from ctx this hangs
	time.Sleep(50 * time.Millisecond)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/dlock/ -run TestRunAsLeader_SQLitePassthrough -v`
Expected: FAIL — `undefined: RunAsLeader` / `undefined: KeyAuditChainer`.

- [ ] **Step 3: Write minimal implementation**

`pkg/dlock/dlock.go`:
```go
// Package dlock provides a Postgres advisory-lock based leader election so a
// single-writer background job runs on exactly one replica at a time, with
// automatic failover. On non-Postgres dialects it degrades to running the job
// directly (single-process dev/test).
package dlock

import (
	"context"
	"database/sql"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	KeyAuditChainer  int64 = 0x4D5849440001
	KeyAuditAnchorer int64 = 0x4D5849440002
	KeyOIDCRotation  int64 = 0x4D5849440003
	KeyAccessSweeper int64 = 0x4D5849440004
)

const retryInterval = 5 * time.Second

// RunAsLeader blocks until ctx is cancelled. It runs `run` only while this
// process holds the advisory lock `key`.
func RunAsLeader(ctx context.Context, db *gorm.DB, key int64, logger *zap.Logger, run func(ctx context.Context)) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if db.Dialector.Name() != "postgres" {
		run(ctx) // single-process: always leader
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		logger.Error("dlock: cannot get sql.DB", zap.Error(err))
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := leadOnce(ctx, sqlDB, key, logger, run); err != nil {
			logger.Warn("dlock: leadership loop error", zap.Int64("key", key), zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}
}

// leadOnce pulls a dedicated connection, contends for the lock, and — if it
// wins — runs `run` until ctx is cancelled or the connection breaks.
func leadOnce(ctx context.Context, sqlDB *sql.DB, key int64, logger *zap.Logger, run func(ctx context.Context)) error {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() // returns conn to pool; session locks auto-release on close

	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&got); err != nil {
		return err
	}
	if !got {
		// Someone else is leader. Wait a bit, then let the outer loop retry.
		select {
		case <-ctx.Done():
		case <-time.After(retryInterval):
		}
		return nil
	}
	logger.Info("dlock: acquired leadership", zap.Int64("key", key))
	defer func() {
		// best-effort unlock; conn.Close also releases session locks
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
	}()

	leaderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Watchdog: if the lock connection dies, we are no longer leader.
	go func() {
		t := time.NewTicker(retryInterval)
		defer t.Stop()
		for {
			select {
			case <-leaderCtx.Done():
				return
			case <-t.C:
				if err := conn.PingContext(leaderCtx); err != nil {
					logger.Warn("dlock: lock connection lost, stepping down", zap.Int64("key", key), zap.Error(err))
					cancel()
					return
				}
			}
		}
	}()

	run(leaderCtx)
	return nil
}
```

- [ ] **Step 4: Run unit test to verify it passes**

Run: `go test ./pkg/dlock/ -run TestRunAsLeader_SQLitePassthrough -v`
Expected: PASS.

- [ ] **Step 5: Write the gated pg contention test**

`pkg/dlock/dlock_pg_e2e_test.go`:
```go
package dlock

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Two concurrent RunAsLeader calls on the same key against real Postgres:
// exactly one must be running `run` at any moment.
func TestRunAsLeader_PGSingleLeader(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("set MXID_E2E_DSN to a throwaway Postgres to run")
	}
	open := func() *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			t.Fatalf("open pg: %v", err)
		}
		return db
	}
	const key int64 = 0x11223344
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var active int32
	var maxActive int32
	work := func(c context.Context) {
		atomic.AddInt32(&active, 1)
		for {
			cur := atomic.LoadInt32(&active)
			if m := atomic.LoadInt32(&maxActive); cur > m {
				atomic.CompareAndSwapInt32(&maxActive, m, cur)
			}
			select {
			case <-c.Done():
				atomic.AddInt32(&active, -1)
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	go RunAsLeader(ctx, open(), key, zap.NewNop(), work)
	go RunAsLeader(ctx, open(), key, zap.NewNop(), work)

	time.Sleep(3 * time.Second)
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("expected exactly 1 concurrent leader, saw max %d", got)
	}
	cancel()
	time.Sleep(500 * time.Millisecond)
}
```

- [ ] **Step 6: Run the gated pg test**

Run: `MXID_E2E_DSN="$MXID_E2E_DSN" go test ./pkg/dlock/ -run TestRunAsLeader_PGSingleLeader -v` (if `MXID_E2E_DSN` unset, it skips — that's acceptable locally but the controller must run it against a throwaway pg before merge).
Expected: PASS (or SKIP if no DSN — controller ensures a real run before Task 1 is marked complete).

- [ ] **Step 7: Commit**

```bash
git add pkg/dlock/
git commit -m "feat(dlock): add Postgres advisory-lock leader election primitive"
```

---

### Task 2: 🔴 OIDC signing-key rotation → leader + ≤1-active index

**Why:** Every pod runs `RunRotation` (`internal/domain/oidckey/rotation.go:14`, started via its call site) with no lock → N pods mint duplicate ACTIVE keys, can leave 0/1/N active keys, JWKS disagrees pod-to-pod. Signing-key correctness/security bug.

**Files:**
- Modify: `app/run.go` — wrap the OIDC rotation goroutine in `dlock.RunAsLeader(..., dlock.KeyOIDCRotation, ...)`.
- Create: `migrations/000053_oidc_keyset_one_active.up.sql` / `.down.sql`.
- Test (gated pg): `internal/domain/oidckey/rotation_pg_e2e_test.go`.

**Interfaces:**
- Consumes: `dlock.RunAsLeader`, `dlock.KeyOIDCRotation` (Task 1).

- [ ] **Step 1: Find the rotation goroutine start site**

Run: `grep -n "RunRotation" app/run.go`
There must be a `go ....RunRotation(...)` call. (If rotation is started elsewhere, wrap it there.) Read ~10 lines around it to capture the exact call (the ticker interval and `onErr` callback).

- [ ] **Step 2: Write the failing pg e2e test (concurrent rotation must yield ≤1 active key)**

`internal/domain/oidckey/rotation_pg_e2e_test.go` — gated on `MXID_E2E_DSN`. Migrate the keyset schema (or run migrations), then invoke `Service.MaybeRotate` concurrently from two goroutines against the same DB with an `every` that forces rotation, and assert `SELECT count(*) FROM mxid_oidc_keyset WHERE status = 1` equals exactly 1 after the partial unique index exists. Model it on `internal/domain/audit/e2e_postgres_test.go`'s setup. Assert that concurrent rotation attempts do not produce >1 active row (the second INSERT of an active key must fail the partial unique index, and rotation must handle/skip that).

Expected initial state: FAIL (no index → duplicate active rows possible; or the test compiles but count > 1).

- [ ] **Step 3: Write the partial unique index migration**

First **read the exact columns** of `mxid_oidc_keyset` (`migrations/000036_oidc_provider_keyset.up.sql`) and confirm the scope of "active" (single-tenant product → likely global; if a `provider`/`tenant` column scopes keys, the partial index must include it to match `Rotate`'s `WHERE status=1` demotion clause). Then:

`migrations/000053_oidc_keyset_one_active.up.sql`:
```sql
-- Enforce at most one ACTIVE (status=1) signing key so concurrent rotation on
-- multiple replicas cannot leave two simultaneously-active keys. Scope columns
-- must match oidckey.Service.Rotate's demote WHERE clause.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oidc_keyset_one_active
    ON mxid_oidc_keyset (status)
    WHERE status = 1;
```
(If the table is provider/tenant-scoped, change to `ON mxid_oidc_keyset (<scope_col>) WHERE status = 1`.)

`migrations/000053_oidc_keyset_one_active.down.sql`:
```sql
DROP INDEX IF EXISTS uq_oidc_keyset_one_active;
```

- [ ] **Step 4: Wrap the rotation goroutine in the leader primitive**

In `app/run.go`, change the rotation start (exact code depends on Step 1; example shape):
```go
// before: go oidcKeySvc.RunRotation(workerCtx, rotateEvery, onRotateErr)
go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyOIDCRotation, a.Logger, func(ctx context.Context) {
	oidcKeySvc.RunRotation(ctx, rotateEvery, onRotateErr)
})
```
Add the `dlock` import if missing.

- [ ] **Step 5: Verify build + rotation service still handles the unique-violation path**

`MaybeRotate`/`Rotate` (`internal/domain/oidckey/service.go:142`) must not crash if an INSERT of a new active key hits the partial unique index (belt-and-suspenders even with the leader lock, since the lock only guarantees one rotator at a time — the index is the last-resort guard). Confirm the rotation returns/logs the error rather than panicking. Adjust `Rotate` to treat a unique-violation on the active-key insert as "someone else already rotated; reload and continue" if needed.

Run: `go build ./...` — Expected: builds.

- [ ] **Step 6: Run tests**

Run: `go test ./internal/domain/oidckey/... ./app/...` (unit) and `MXID_E2E_DSN=... go test ./internal/domain/oidckey/ -run PG -v` (gated).
Expected: PASS (gated skips without DSN — controller runs it against throwaway pg before marking complete).

- [ ] **Step 7: Commit**

```bash
git add app/run.go migrations/000053_* internal/domain/oidckey/
git commit -m "fix(oidckey): run key rotation under leader lock and enforce single active key"
```

---

### Task 3: 🔴 Casbin authz cross-pod resync

**Why:** `wireCasbinSync` (`app/adapters_authz.go:230`) rebuilds the in-memory Casbin enforcer only from the **in-process** event bus. A permission revoked on pod A is never resynced on pods B/C → they keep granting the revoked permission until restart = silent stale authorization. The sibling `wireAuthzCacheInvalidation` already does this correctly via Redis pub/sub on `authz:invalidate` — mirror that.

**Files:**
- Modify: `app/adapters_authz.go` — in the casbin resync handler, also publish to a Redis channel; add a subscriber that calls `engine.Sync` on every pod.
- Reference pattern: `pkg/authz/cache.go` (`invalidateChannel = "authz:invalidate"`, `startSubscriber`, `rdb.Subscribe`, `rdb.Publish`).
- Test: `app/adapters_authz_casbin_resync_test.go` (or nearest existing authz test file) — a unit test that publishing to the channel triggers a resync callback.

**Interfaces:**
- Consumes: `app.Redis` (`*redis.Client`), `authz.CasbinEngine.Sync(ctx, loader)`, `event.Bus`.
- New channel constant: `casbinResyncChannel = "authz:casbin:resync"`.

- [ ] **Step 1: Read the current wiring**

Read `app/adapters_authz.go:224-320` (both `wireCasbinSync` and `wireAuthzCacheInvalidation`) and `pkg/authz/cache.go:startSubscriber` + the `Publish` call, so the new code matches the existing style exactly (same error handling, same logger use, same `subOnce` guard idea).

- [ ] **Step 2: Write the failing test**

Write a test that: constructs the resync wiring with a real (miniredis or the test Redis) client, publishes a message to `authz:casbin:resync`, and asserts the `engine.Sync` loader is invoked (use a fake `PolicyLoader` / a counter). If the repo already uses `miniredis` in tests, use it; otherwise use `app.Redis` behind a `MXID_TEST_REDIS`-gated test mirroring existing Redis-touching tests. Assert sync-count increments within ~1s of the publish.

Expected: FAIL (no subscriber exists yet).

- [ ] **Step 3: Implement publish + subscribe**

In `wireCasbinSync`, after the local `engine.Sync` succeeds on the publishing pod, publish a small message so peers resync:
```go
const casbinResyncChannel = "authz:casbin:resync"

// inside the resync handler, after a successful local Sync:
if a.Redis != nil {
	if err := a.Redis.Publish(context.Background(), casbinResyncChannel, "1").Err(); err != nil && a.Logger != nil {
		a.Logger.Warn("casbin: failed to broadcast resync", zap.Error(err))
	}
}
```
Add a subscriber started once at wiring time (mirror `startSubscriber` in `pkg/authz/cache.go`), which on each message calls `engine.Sync(context.Background(), loader)`. **Guard against a resync→publish loop**: the subscriber path must call `engine.Sync` directly and must NOT re-publish (only the EventBus-triggered local handler publishes). Keep the subscriber goroutine tied to the app context for graceful shutdown.

- [ ] **Step 4: Run the test**

Run: `go test ./app/... -run Casbin -v`
Expected: PASS.

- [ ] **Step 5: Build**

Run: `go build ./...`
Expected: builds.

- [ ] **Step 6: Commit**

```bash
git add app/adapters_authz.go app/adapters_authz_casbin_resync_test.go
git commit -m "fix(authz): propagate Casbin policy resync across replicas via Redis pub/sub"
```

---

### Task 4: 🟠 Audit chainer → leader

**Why:** `chainer.Run` (`app/run.go:887`) is single-writer with no lock; two pods pull the same pending rows, compute the same `seq`, race → PK-collision transaction-abort storms every 2s. The file's own comment says "never run two of these" — nothing enforces it. Wrap in the leader primitive.

**Files:**
- Modify: `app/run.go:886-887`.
- Test: covered by Task 1's dlock pg e2e for the locking mechanism; add a build-level check only. No new logic in the chainer itself.

**Interfaces:**
- Consumes: `dlock.RunAsLeader`, `dlock.KeyAuditChainer` (Task 1).

- [ ] **Step 1: Wrap the chainer goroutine**

`app/run.go` around line 886-887:
```go
chainer := audit.NewChainer(a.DB, auditChainKey, "default", a.Logger)
go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAuditChainer, a.Logger, func(ctx context.Context) {
	chainer.Run(ctx, 2*time.Second)
})
```
Ensure `dlock` is imported.

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: builds.

- [ ] **Step 3: Run the existing audit suite (no regression)**

Run: `go test ./internal/domain/audit/...`
Expected: PASS (single-process behavior unchanged — dlock passes through on sqlite).

- [ ] **Step 4: Run the audit pg e2e (chain still drains under leader)**

Run: `MXID_E2E_DSN=... go test ./internal/domain/audit/ -run PG -v`
Expected: PASS — capture→chain→verify still works end-to-end with the leader wrapper (the single test process is the leader).

- [ ] **Step 5: Commit**

```bash
git add app/run.go
git commit -m "fix(audit): run chainer under leader lock for multi-replica safety"
```

---

### Task 5: 🟠 Audit anchorer → leader + anchor span unique constraint

**Why:** `anchorer.Run` (`app/run.go:906`) has NO protection: two pods compute identical `(from_seq,to_seq,root,sig)` and both insert (each gets a fresh Snowflake PK → no rejection), polluting the tamper-evident ledger with duplicate anchors. Wrap in leader AND add a DB unique constraint on the anchor span as a last-resort guard.

**Files:**
- Modify: `app/run.go:905-906`.
- Create: `migrations/000054_audit_anchor_unique.up.sql` / `.down.sql`.
- Test (gated pg): extend `internal/domain/audit/e2e_postgres_test.go` or add `anchorer_pg_e2e_test.go` — a duplicate anchor insert for the same span must be rejected.

**Interfaces:**
- Consumes: `dlock.RunAsLeader`, `dlock.KeyAuditAnchorer` (Task 1).

- [ ] **Step 1: Read the anchor table columns**

Read `migrations/000052_audit_anchor.up.sql` to get exact column names for tenant / chain_class / from_seq / to_seq.

- [ ] **Step 2: Write the failing pg e2e test**

Add a gated test: insert an anchor row for span (tenant=1, class='default', from=1, to=10), then attempt a second insert of the same span; assert the second fails with a unique-violation once the constraint exists. Expected initial: FAIL (duplicate currently allowed).

- [ ] **Step 3: Write the unique constraint migration**

`migrations/000054_audit_anchor_unique.up.sql` (adjust column names to match Step 1):
```sql
-- One anchor per (tenant, chain_class, from_seq, to_seq) span, so two replicas
-- racing the anchorer cannot both insert the same anchor into the ledger.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_anchor_span
    ON mxid_audit_anchor (tenant_id, chain_class, from_seq, to_seq);
```
`migrations/000054_audit_anchor_unique.down.sql`:
```sql
DROP INDEX IF EXISTS uq_audit_anchor_span;
```

- [ ] **Step 4: Make the anchorer tolerate the unique violation**

Read `internal/domain/audit/anchorer.go:32-96`. The insert of an anchor row must treat a unique-violation as "already anchored by the leader/another attempt; skip this span" — log at debug/info, not error, and continue. (With the leader lock this is rare, but the constraint is the last-resort guard.)

- [ ] **Step 5: Wrap the anchorer goroutine**

`app/run.go` around 905-906:
```go
anchorer := audit.NewAnchorer(a.DB, auditAnchorPriv, auditAnchorSink, a.IDGen, a.Logger)
go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAuditAnchorer, a.Logger, func(ctx context.Context) {
	anchorer.Run(ctx, 60*time.Second)
})
```

- [ ] **Step 6: Build + test**

Run: `go build ./...` then `go test ./internal/domain/audit/...` and `MXID_E2E_DSN=... go test ./internal/domain/audit/ -run PG -v`.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app/run.go migrations/000054_* internal/domain/audit/anchorer.go
git commit -m "fix(audit): run anchorer under leader lock and enforce unique anchor span"
```

---

### Task 6: 🟠 Audit anchor sink PVC + audit env keys in Helm

**Why:** The anchorer's `FileSink` writes to a local path resolving to `/app/data/audit-anchors.log`. On K8s with an ephemeral pod filesystem, the anchor DB rows reference `external_uri` values that only resolve on the pod that wrote them and are lost on restart/reschedule — defeating the "external offline copy survives DB compromise" guarantee. Also the chart's StatefulSet is **missing** the audit env keys (`MXID_CRYPTO_AUDIT_CHAIN_KEY`, `MXID_CRYPTO_AUDIT_ANCHOR_KEY`, `MXID_AUDIT_ANCHOR_SINK_PATH`, etc.). Give the anchor sink a persistent volume and wire the env.

**Files:**
- Modify: `deploy/helm/mxid/values.yaml` — add `audit:` block (chainKey/anchorKey secret refs, anchor sink PVC size/enabled, anchorSinkPath).
- Modify: `deploy/helm/mxid/templates/backend-statefulset.yaml` — add the audit env vars + a `volumeClaimTemplates` entry for the anchor sink dir + a `volumeMount`.
- Modify: `deploy/helm/mxid/templates/secret.yaml` — add `MXID_CRYPTO_AUDIT_CHAIN_KEY` / `MXID_CRYPTO_AUDIT_ANCHOR_KEY`.
- No Go test (infra); validate with `helm template`.

**Interfaces:**
- Consumes: the config keys read by `internal/bootstrap/config.go` (`CryptoConfig.AuditChainKey`, `AuditAnchorKey`, `AuditConfig.AnchorSinkPath`) — confirm the exact env var names by reading the `mapstructure`/env bindings there.

- [ ] **Step 1: Read config env bindings**

Read `internal/bootstrap/config.go` for the audit chain/anchor key + anchor sink path env var names (the `MXID_*` names). Read the current `deploy/helm/mxid/templates/backend-statefulset.yaml` env block + the note at line ~122 ("No volumeClaimTemplates — stateless").

- [ ] **Step 2: Add the audit secrets to `secret.yaml`**

Mirror the existing `MXID_CRYPTO_KEY_ENCRYPTION_KEY` entry, adding `MXID_CRYPTO_AUDIT_CHAIN_KEY` and `MXID_CRYPTO_AUDIT_ANCHOR_KEY` sourced from `.Values.secrets.*` (base64/stringData as the existing secret does).

- [ ] **Step 3: Add `audit` values to `values.yaml`**

```yaml
audit:
  anchorSink:
    enabled: true
    path: /app/data/audit-anchors.log
    persistence:
      size: 1Gi
      storageClass: ""   # default SC
secrets:
  # ...existing...
  auditChainKey: ""     # 32-byte hex/base64; injected at deploy, never committed
  auditAnchorKey: ""    # Ed25519 seed; injected at deploy
```

- [ ] **Step 4: Add volumeClaimTemplates + mount + env to the StatefulSet**

Add a `volumeClaimTemplates` entry (the StatefulSet already exists, so this is additive) for a PVC mounted at the directory of `.Values.audit.anchorSink.path` (`/app/data`), a matching `volumeMount`, the two `MXID_CRYPTO_AUDIT_*` env from the secret, and `MXID_AUDIT_ANCHOR_SINK_PATH` from `.Values.audit.anchorSink.path`. Replace the "No volumeClaimTemplates — stateless" comment.

Note: with a per-pod PVC, only the **leader** pod (Task 5) writes the sink — the non-leader PVCs stay empty, which is fine (failover leader writes to its own PVC). Document this in a chart comment; a fuller design (shared object storage / S3 sink) is out of scope for this task.

- [ ] **Step 5: Validate the chart renders**

Run: `helm template deploy/helm/mxid --set secrets.auditChainKey=deadbeef --set secrets.auditAnchorKey=deadbeef | grep -A2 -i "audit\|volumeClaim"`
Expected: env vars + volumeClaimTemplates present, no template errors.

- [ ] **Step 6: Commit**

```bash
git add deploy/helm/mxid/
git commit -m "feat(helm): persist audit anchor sink via PVC and wire audit secrets"
```

---

### Task 7: 🟠 EE license cross-pod reload

**Why:** `license.SetCurrent` is called in `putLicense` only in the handling pod's process (`internal/gateway/console/settings/handler.go`). Activating/upgrading/expiring a license on pod A leaves pods B/C on the old edition until restart — CE caps enforced inconsistently, EE routes 403 on some pods. Broadcast a reload over Redis.

**Files:**
- Modify: `internal/gateway/console/settings/handler.go` — after persisting + local `SetCurrent`, publish `license:reload`.
- Modify: `app/run.go` — subscribe to `license:reload`; on message, re-read `platformconfig.KeyLicense`, rebuild the `Manager`, `license.SetCurrent`.
- Test: `app/run.go` license-reload subscriber unit test (fake redis / miniredis), asserting a publish triggers a re-read + SetCurrent.

**Interfaces:**
- Consumes: `app.Redis`, `platformconfig.Service.Get(ctx, KeyLicense, &lic)`, `license.SetCurrent(mgr)`.
- New channel: `licenseReloadChannel = "license:reload"`.

- [ ] **Step 1: Read the license boot + putLicense code**

Read `app/run.go:225-235` (boot read + `SetCurrent`) and `putLicense` in `internal/gateway/console/settings/handler.go:460-485` to reuse the exact Manager-construction code.

- [ ] **Step 2: Write the failing subscriber test**

Test: start the license-reload subscriber against a test Redis, seed `platformconfig` with a license value, publish `license:reload`, assert `license.Current()` reflects the seeded license within ~1s. Expected: FAIL (no subscriber).

- [ ] **Step 3: Extract a reusable reload function**

Factor the "read KeyLicense → build Manager → SetCurrent" logic into one function callable at boot AND from the subscriber (DRY — don't duplicate the Manager construction). E.g. `func reloadLicense(ctx, platformConfigService) error` in `app/run.go`.

- [ ] **Step 4: Add the subscriber in `app/run.go`**

Mirror the pub/sub subscriber pattern; on each `license:reload` message call `reloadLicense`. Tie to the app context for shutdown.

- [ ] **Step 5: Publish on `putLicense`**

In the console handler, after successful persist + local `SetCurrent`, `a.Redis.Publish(ctx, "license:reload", "1")` (thread the Redis client into the handler if not already available — check how the handler gets its deps).

- [ ] **Step 6: Build + test**

Run: `go build ./...` then `go test ./app/... -run License -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app/run.go internal/gateway/console/settings/handler.go
git commit -m "fix(license): reload license across replicas via Redis pub/sub"
```

---

### Task 8: 🟡 Settings cache cross-pod invalidation

**Why:** `setting.Service` caches settings in-memory with a 60s TTL (`internal/domain/setting/service.go:42`) and `invalidate` only clears the **local** pod's map. Changing a setting on pod A (e.g. disabling a login method, rotating SMTP) stays stale up to 60s on other pods. Mirror the authz `invalidate` Redis pub/sub.

**Files:**
- Modify: `internal/domain/setting/service.go` — accept a `*redis.Client`; on `Set`, publish the cache key to `settings:invalidate`; subscribe and delete the local cache entry on message.
- Modify: the setting.Service constructor call site (find via grep) to pass `app.Redis`.
- Test: `internal/domain/setting/service_test.go` — publishing invalidation clears the local cache entry.

**Interfaces:**
- Consumes: `app.Redis`.
- New channel: `settingsInvalidateChannel = "settings:invalidate"`; message payload = the cache key `"<key>|<tenantID>"` (matches the existing `cacheKey` format at `service.go:136`).

- [ ] **Step 1: Read the cache + invalidate + constructor**

Read `internal/domain/setting/service.go` fully (it's small): `cache map`, `cacheKey` format, `invalidate`, `Set`, and `New...` constructor signature. Grep the constructor call site: `grep -rn "setting.NewService\|setting.New(" app/ internal/`.

- [ ] **Step 2: Write the failing test**

Test: two `Service` instances sharing one test Redis (simulating two pods) over the same DB. Warm instance B's cache for key K (a `Get`). Call `Set(K)` on instance A. Assert instance B's subsequent `Get(K)` returns the new value (its cache entry was invalidated via pub/sub) rather than the stale cached one. Expected: FAIL (no cross-pod invalidation).

- [ ] **Step 3: Implement pub/sub invalidation**

- Add `rdb *redis.Client` to `Service`; thread it through the constructor (keep it optional/nil-safe so existing non-Redis tests still construct).
- In `invalidate(key, tenantID)`: after the local delete, if `rdb != nil` publish the cache key to `settings:invalidate`.
- Add a `startSubscriber(ctx)` (mirror `pkg/authz/cache.go`) that on each message deletes that cache key from the local map. Guard the subscriber-triggered delete so it does NOT re-publish (avoid a loop): give the subscriber a direct local-delete path separate from `invalidate`.

- [ ] **Step 4: Wire the Redis client at the constructor call site**

Pass `app.Redis` where `setting.Service` is constructed. Start the subscriber with the app context.

- [ ] **Step 5: Build + test**

Run: `go build ./...` then `go test ./internal/domain/setting/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/domain/setting/service.go app/run.go
git commit -m "fix(settings): invalidate settings cache across replicas via Redis pub/sub"
```

---

### Task 9: 🟡 JIT access sweeper → leader

**Why:** `access.StartSweeper` (`app/run.go:1101`) has no claim; every pod processes the same due grants → each publishes `access.grant.expired`, duplicating audit-chain entries and double-invoking downstream logout. DB converges (idempotent) but the tamper-evident audit trail records the same expiry N times. Wrap in the leader primitive.

**Files:**
- Modify: `app/run.go:1101`.

**Interfaces:**
- Consumes: `dlock.RunAsLeader`, `dlock.KeyAccessSweeper` (Task 1).

- [ ] **Step 1: Read the current call**

Read `app/run.go:1095-1105`. Note it currently uses `context.Background()` (not `workerCtx`) — switch to `workerCtx` so it participates in graceful shutdown too.

- [ ] **Step 2: Wrap in the leader primitive**

```go
// before: access.StartSweeper(context.Background(), accessJITSvc, accessJITRepo, 30*time.Second, a.Logger)
go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyAccessSweeper, a.Logger, func(ctx context.Context) {
	access.StartSweeper(ctx, accessJITSvc, accessJITRepo, 30*time.Second, a.Logger)
})
```
Confirm `StartSweeper` blocks (runs its own ticker loop) rather than returning immediately — read `internal/domain/access/sweeper.go:14-27`. If `StartSweeper` itself does `go func()` internally and returns, wrap so the leader `run` blocks until ctx done (e.g. call the internal loop directly, or have `run` block on `<-ctx.Done()` after starting). The leader `run` callback MUST block for the duration of leadership.

- [ ] **Step 3: Build + test**

Run: `go build ./...` then `go test ./internal/domain/access/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add app/run.go
git commit -m "fix(access): run JIT expiry sweeper under leader lock to avoid duplicate audit events"
```

---

### Task 10: 🟡 Portal SSE cross-pod via Redis pub/sub

**Why:** The portal SSE broker (`internal/gateway/portal/events.go:34`) is pod-local. A client's SSE stream on pod A never receives events (`app_access.changed`, `tenant.updated/deleted`) triggered on pod B → live UI refresh silently misses cross-pod events. Back the broker with Redis pub/sub so any pod's event reaches all connected clients.

**Files:**
- Modify: `internal/gateway/portal/events.go` — `AttachBusSubscribers` publishes bus events to a Redis channel; the broker's `run` also subscribes to that Redis channel and fans out to local SSE connections.
- Modify: the `AttachBusSubscribers` call site to pass `app.Redis`.
- Test: `internal/gateway/portal/events_test.go` — an event published to Redis by a "pod A" reaches a "pod B" broker's subscriber channel.

**Interfaces:**
- Consumes: `app.Redis`, `event.Bus`.
- New channel: `portalEventsChannel = "portal:events"`; payload = JSON `{type, payload}` (the `brokerEvent` shape, JSON-encoded).

- [ ] **Step 1: Read the broker**

Read `internal/gateway/portal/events.go` fully (broker, `run`, `subscribe`, `AttachBusSubscribers`, the per-connection ping ticker at line 131, and the SSE handler that consumes `subscribe()`).

- [ ] **Step 2: Write the failing test**

Test: two brokers sharing one test Redis (pod A + pod B). Subscribe a client on broker B. Publish a `brokerEvent` via broker A's Redis-publish path. Assert broker B's subscribed client channel receives the event within ~1s. Expected: FAIL (broker is pod-local today).

- [ ] **Step 3: Route bus events through Redis**

- Change `AttachBusSubscribers(bus, rdb)`: each bus handler, instead of (or in addition to) `sseBroker.pub <- ev`, JSON-encodes the `brokerEvent` and `rdb.Publish(ctx, "portal:events", data)`.
- In the broker (`run` or a new `startRedisSubscriber`), subscribe to `portal:events`, decode each message into `brokerEvent`, and push to `b.pub` for local fan-out.
- This makes the local bus → Redis → all brokers (including the originating pod) → local SSE clients. Ensure an event is delivered **once** per client (publish to Redis only; the local broker fans out solely from the Redis subscription, not also directly from the bus — otherwise the originating pod's clients get it twice).
- Keep `app.Redis == nil` degrading to the current in-process behavior (dev without the wiring).

- [ ] **Step 4: Wire the Redis client at the call site**

Update the `AttachBusSubscribers` call (grep it) to pass `app.Redis`, and start the broker's Redis subscriber with the app context.

- [ ] **Step 5: Build + test**

Run: `go build ./...` then `go test ./internal/gateway/portal/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/portal/events.go app/run.go
git commit -m "fix(portal): deliver SSE events across replicas via Redis pub/sub"
```

---

## Self-Review

**Spec coverage** — every HA-audit finding maps to a task:
- #1 Casbin → Task 3. #2 OIDC rotation → Task 2. #3 chainer → Task 4. #4 anchorer → Task 5. #5 license → Task 7. #6 settings → Task 8. #7 JIT sweeper → Task 9. #8 SSE → Task 10. #9 anchor sink storage → Task 6. Shared primitive → Task 1. All 9 findings + primitive covered.

**Type consistency** — `dlock.RunAsLeader(ctx, *gorm.DB, int64, *zap.Logger, func(context.Context))` and the `KeyAudit*/KeyOIDCRotation/KeyAccessSweeper` constants are defined in Task 1 and consumed with those exact names in Tasks 2/4/5/9. Redis channel constants are each defined in their own task. `reloadLicense` (Task 7) is defined and consumed within Task 7.

**Placeholder scan** — the pub/sub tasks (3/7/8/10) intentionally instruct the implementer to read the exact current code and mirror `pkg/authz/cache.go` rather than transcribing unchanged surrounding code; each provides the channel name, the publish payload format, the loop-prevention rule, and the test to write. The migration column names in Tasks 2/5 are gated on a "read the exact columns first" step because the partial-index scope must match the domain code's WHERE clause — this is a required verification, not a placeholder.

**Postgres-specificity** — Tasks 1, 2, 5 carry gated `MXID_E2E_DSN` pg tests because advisory locks and partial/unique indexes do not behave on sqlite (per the jsonb postmortem lesson). The controller must run these against a throwaway Postgres before marking those tasks complete, not rely on the skip.
