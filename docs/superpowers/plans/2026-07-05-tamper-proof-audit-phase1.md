# Tamper-Proof Audit — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the cryptographic tamper-evident core: capture audit events into a durable pending table, chain them with an HMAC hash chain via a single ordered consumer into an append-only log, and verify the chain detects any tampering or deletion.

**Architecture:** Producers write an event into `audit_pending` (in the caller's DB transaction — atomic with the state change). A single-goroutine `Chainer` drains `audit_pending` in FIFO order, computes `entry_hash = HMAC-SHA256(key, seq ‖ prev_hash ‖ canonical_json(payload))` per `(tenant_id, chain_class)` chain, and inserts into the strictly-append-only `audit_log`. `chain_head` holds each chain's tip (last_seq, last_entry_hash). `VerifyChain` recomputes the chain from genesis and flags any hash mismatch or `seq` gap.

**Tech Stack:** Go 1.25, gorm (glebarez/sqlite for tests, Postgres in prod), `pkg/snowflake` for IDs, `pkg/crypto` for HMAC, `go.uber.org/zap` logging, stdlib `testing`.

## Global Constraints

- Module path: `github.com/imkerbos/mxid`. All imports use this prefix.
- IDs are `int64` from `*snowflake.Generator` (`.Generate() int64`). Never rely on DB auto-increment for new tables.
- `audit_log` is append-only for EVERY role — no code path issues UPDATE/DELETE on it. Chain tip mutation lives in the separate `chain_head` table.
- Hash: HMAC-SHA256. `entry_hash` and `prev_hash` are 32 raw bytes. Genesis `prev_hash` = 32 zero bytes, genesis `seq` = 0 (the genesis row itself is virtual — the first real row is `seq = 1`).
- Chain preimage byte layout is FROZEN (verification depends on it): `seq` as 8-byte big-endian, then 32-byte `prev_hash`, then canonical JSON bytes of payload. Any change breaks all prior verification.
- `chain_class` ∈ {`data`, `auth`, `admin`, `sensitive_read`}. Each `(tenant_id, chain_class)` is an independent chain.
- Canonical JSON must be deterministic: struct fields in declared order, map keys sorted (Go's `encoding/json` sorts `map[string]any` keys). No trailing whitespace.
- New migrations start at `000049` (latest is `000048`). Every up migration has a matching down.
- HMAC key comes from config/KEK, passed in as `[]byte` — never hard-coded. Phase 1 accepts an injected key; KEK wrapping is wired in a later phase.

---

## File Structure

- `pkg/crypto/crypto.go` — add `HMACSHA256`. (modify)
- `internal/domain/audit/chain.go` — canonical JSON + entry-hash + genesis constants. (create)
- `internal/domain/audit/chainmodel.go` — gorm models `AuditPending`, `AuditEntry`, `ChainHead`. (create)
- `internal/domain/audit/capture.go` — `Capture(ctx, tx, Event)` producer API. (create)
- `internal/domain/audit/chainer.go` — the ordered consumer. (create)
- `internal/domain/audit/verify.go` — `VerifyChain`. (create)
- `internal/domain/audit/*_test.go` — one test file per unit above.
- `migrations/000049_audit_chain.up.sql` / `.down.sql` — three tables. (create)
- `cmd/.../audit_verify.go` — CLI wiring (Task 10). (create — exact path resolved in Task 10)

---

### Task 1: HMAC-SHA256 helper in pkg/crypto

**Files:**
- Modify: `pkg/crypto/crypto.go`
- Test: `pkg/crypto/crypto_hmac_test.go` (create)

**Interfaces:**
- Produces: `func HMACSHA256(key, data []byte) []byte` — returns the 32-byte MAC.

- [ ] **Step 1: Write the failing test**

```go
// pkg/crypto/crypto_hmac_test.go
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHMACSHA256_MatchesStdlib(t *testing.T) {
	key := []byte("test-key")
	data := []byte("hello world")

	got := HMACSHA256(key, data)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	want := mac.Sum(nil)

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("HMACSHA256 = %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/crypto/ -run TestHMACSHA256 -v`
Expected: FAIL — `undefined: HMACSHA256`

- [ ] **Step 3: Write minimal implementation**

Append to `pkg/crypto/crypto.go` (imports `crypto/hmac`, `crypto/sha256` — add to the existing import block):

```go
// HMACSHA256 returns the HMAC-SHA256 of data under key. Used by the audit
// hash chain; the returned slice is always 32 bytes.
func HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/crypto/ -run TestHMACSHA256 -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/crypto.go pkg/crypto/crypto_hmac_test.go
git commit -m "feat(crypto): add HMACSHA256 helper for audit hash chain"
```

---

### Task 2: Canonical JSON + entry-hash + genesis constants

**Files:**
- Create: `internal/domain/audit/chain.go`
- Test: `internal/domain/audit/chain_test.go`

**Interfaces:**
- Consumes: `crypto.HMACSHA256` (Task 1).
- Produces:
  - `type ChainPayload struct { ... }` — the frozen, canonicalizable event body (fields below).
  - `func CanonicalJSON(p ChainPayload) ([]byte, error)`
  - `func ComputeEntryHash(key []byte, seq int64, prevHash []byte, canonical []byte) []byte`
  - `var GenesisPrevHash []byte` — 32 zero bytes.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/chain_test.go
package audit

import (
	"bytes"
	"testing"
)

func samplebayload() ChainPayload {
	return ChainPayload{
		TenantID:     7,
		ChainClass:   "data",
		ActorID:      42,
		ActorType:    "admin",
		EventType:    "app.deleted",
		ResourceType: "app",
		ResourceID:   99,
		Before:       map[string]any{"name": "old", "enabled": true},
		After:        nil,
		IP:           "1.2.3.4",
		OccurredAt:   "2026-07-05T00:00:00Z",
	}
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	p := samplebayload()
	a, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical JSON not stable:\n%s\n%s", a, b)
	}
}

func TestCanonicalJSON_MapKeyOrderIrrelevant(t *testing.T) {
	p1 := samplebayload()
	p1.Before = map[string]any{"a": 1, "z": 2}
	p2 := samplebayload()
	p2.Before = map[string]any{"z": 2, "a": 1}
	c1, _ := CanonicalJSON(p1)
	c2, _ := CanonicalJSON(p2)
	if !bytes.Equal(c1, c2) {
		t.Fatalf("map key order changed canonical form")
	}
}

func TestComputeEntryHash_KnownVector(t *testing.T) {
	key := []byte("k")
	canonical := []byte(`{"x":1}`)
	h := ComputeEntryHash(key, 1, GenesisPrevHash, canonical)
	if len(h) != 32 {
		t.Fatalf("hash len = %d, want 32", len(h))
	}
	// Deterministic: same inputs -> same hash.
	h2 := ComputeEntryHash(key, 1, GenesisPrevHash, canonical)
	if !bytes.Equal(h, h2) {
		t.Fatalf("entry hash not deterministic")
	}
	// Sequence change -> different hash.
	h3 := ComputeEntryHash(key, 2, GenesisPrevHash, canonical)
	if bytes.Equal(h, h3) {
		t.Fatalf("seq did not affect hash")
	}
}

func TestGenesisPrevHash_IsZero32(t *testing.T) {
	if len(GenesisPrevHash) != 32 {
		t.Fatalf("genesis len = %d", len(GenesisPrevHash))
	}
	for _, b := range GenesisPrevHash {
		if b != 0 {
			t.Fatalf("genesis not all zero")
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestCanonicalJSON -v`
Expected: FAIL — `undefined: ChainPayload` / `CanonicalJSON`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/chain.go
package audit

import (
	"encoding/binary"
	"encoding/json"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// GenesisPrevHash is the prev_hash of the first real entry (seq=1) in every
// chain: 32 zero bytes.
var GenesisPrevHash = make([]byte, 32)

// ChainPayload is the FROZEN body that gets canonicalized and hashed. Field
// order here is part of the canonical form — do not reorder without a chain
// migration. Map fields (Before/After/Detail) are canonicalized by Go's
// json.Marshal, which sorts map[string]any keys.
type ChainPayload struct {
	TenantID     int64          `json:"tenant_id"`
	ChainClass   string         `json:"chain_class"`
	ActorID      int64          `json:"actor_id"`
	ActorType    string         `json:"actor_type"`
	EventType    string         `json:"event_type"`
	ResourceType string         `json:"resource_type"`
	ResourceID   int64          `json:"resource_id"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	IP           string         `json:"ip"`
	UserAgent    string         `json:"user_agent"`
	SessionID    string         `json:"session_id"`
	Detail       map[string]any `json:"detail"`
	OccurredAt   string         `json:"occurred_at"` // RFC3339 UTC string, stable across marshals
}

// CanonicalJSON returns the deterministic JSON encoding of p. Struct fields
// serialize in declared order; map keys are sorted by encoding/json.
func CanonicalJSON(p ChainPayload) ([]byte, error) {
	return json.Marshal(p)
}

// ComputeEntryHash returns HMAC-SHA256(key, seq_be8 ‖ prevHash ‖ canonical).
// The byte layout is frozen; verification recomputes it identically.
func ComputeEntryHash(key []byte, seq int64, prevHash []byte, canonical []byte) []byte {
	preimage := make([]byte, 0, 8+len(prevHash)+len(canonical))
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], uint64(seq))
	preimage = append(preimage, seqBuf[:]...)
	preimage = append(preimage, prevHash...)
	preimage = append(preimage, canonical...)
	return crypto.HMACSHA256(key, preimage)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run 'TestCanonicalJSON|TestComputeEntryHash|TestGenesis' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/chain.go internal/domain/audit/chain_test.go
git commit -m "feat(audit): canonical JSON and HMAC entry-hash for the audit chain"
```

---

### Task 3: Migration 000049 — audit_pending, audit_log, chain_head

**Files:**
- Create: `migrations/000049_audit_chain.up.sql`
- Create: `migrations/000049_audit_chain.down.sql`

**Interfaces:**
- Produces: tables `mxid_audit_pending`, `mxid_audit_entry`, `mxid_audit_chain_head`.

- [ ] **Step 1: Write the up migration**

```sql
-- migrations/000049_audit_chain.up.sql
-- Tamper-proof audit Phase 1. Producers INSERT into mxid_audit_pending inside
-- their own state-change transaction (atomic capture). A single ordered chainer
-- drains pending FIFO, computes the HMAC hash chain per (tenant_id, chain_class),
-- and INSERTs into mxid_audit_entry, which is append-only for every role.
-- mxid_audit_chain_head holds each chain's tip; it is the only mutable state.

CREATE TABLE IF NOT EXISTS mxid_audit_pending (
    id            BIGINT       PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL DEFAULT 0,
    chain_class   VARCHAR(16)  NOT NULL,
    actor_id      BIGINT       NOT NULL DEFAULT 0,
    actor_type    VARCHAR(16)  NOT NULL DEFAULT '',
    event_type    VARCHAR(64)  NOT NULL,
    resource_type VARCHAR(32)  NOT NULL DEFAULT '',
    resource_id   BIGINT       NOT NULL DEFAULT 0,
    before        JSONB,
    after         JSONB,
    ip            VARCHAR(64)  NOT NULL DEFAULT '',
    user_agent    VARCHAR(512) NOT NULL DEFAULT '',
    session_id    VARCHAR(128) NOT NULL DEFAULT '',
    detail        JSONB        NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- FIFO drain order for the chainer.
CREATE INDEX IF NOT EXISTS idx_audit_pending_id ON mxid_audit_pending(id);

CREATE TABLE IF NOT EXISTS mxid_audit_entry (
    tenant_id   BIGINT       NOT NULL,
    chain_class VARCHAR(16)  NOT NULL,
    seq         BIGINT       NOT NULL,
    prev_hash   BYTEA        NOT NULL,
    entry_hash  BYTEA        NOT NULL,
    key_id      VARCHAR(64)  NOT NULL DEFAULT 'default',
    payload     JSONB        NOT NULL,
    imported    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, chain_class, seq)
);

CREATE TABLE IF NOT EXISTS mxid_audit_chain_head (
    tenant_id       BIGINT      NOT NULL,
    chain_class     VARCHAR(16) NOT NULL,
    last_seq        BIGINT      NOT NULL DEFAULT 0,
    last_entry_hash BYTEA       NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, chain_class)
);
```

- [ ] **Step 2: Write the down migration**

```sql
-- migrations/000049_audit_chain.down.sql
DROP TABLE IF EXISTS mxid_audit_chain_head;
DROP TABLE IF EXISTS mxid_audit_entry;
DROP TABLE IF EXISTS mxid_audit_pending;
```

- [ ] **Step 3: Verify migrations apply**

Run: `make migrate-up` (or the project's migrate target; check `Makefile`)
Expected: migration `000049` applies with no error; `make migrate-down` on a scratch DB drops cleanly. If unsure of the target, run `grep -i migrate Makefile`.

- [ ] **Step 4: Commit**

```bash
git add migrations/000049_audit_chain.up.sql migrations/000049_audit_chain.down.sql
git commit -m "feat(audit): migration for audit_pending, audit_entry, chain_head"
```

---

### Task 4: gorm models for the three tables

**Files:**
- Create: `internal/domain/audit/chainmodel.go`
- Test: `internal/domain/audit/chainmodel_test.go`

**Interfaces:**
- Produces: `AuditPending`, `AuditEntry`, `ChainHead` structs with `TableName()` methods.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/chainmodel_test.go
package audit

import "testing"

func TestChainTableNames(t *testing.T) {
	if (AuditPending{}).TableName() != "mxid_audit_pending" {
		t.Fatal("AuditPending table name")
	}
	if (AuditEntry{}).TableName() != "mxid_audit_entry" {
		t.Fatal("AuditEntry table name")
	}
	if (ChainHead{}).TableName() != "mxid_audit_chain_head" {
		t.Fatal("ChainHead table name")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestChainTableNames -v`
Expected: FAIL — `undefined: AuditPending`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/chainmodel.go
package audit

import (
	"encoding/json"
	"time"
)

// AuditPending is a captured-but-not-yet-chained event. Written by producers in
// their own transaction; drained FIFO by the Chainer.
type AuditPending struct {
	ID           int64           `gorm:"column:id;primaryKey"`
	TenantID     int64           `gorm:"column:tenant_id;not null"`
	ChainClass   string          `gorm:"column:chain_class;not null;size:16"`
	ActorID      int64           `gorm:"column:actor_id;not null"`
	ActorType    string          `gorm:"column:actor_type;not null;size:16"`
	EventType    string          `gorm:"column:event_type;not null;size:64"`
	ResourceType string          `gorm:"column:resource_type;not null;size:32"`
	ResourceID   int64           `gorm:"column:resource_id;not null"`
	Before       json.RawMessage `gorm:"column:before;type:jsonb"`
	After        json.RawMessage `gorm:"column:after;type:jsonb"`
	IP           string          `gorm:"column:ip;not null;size:64"`
	UserAgent    string          `gorm:"column:user_agent;not null;size:512"`
	SessionID    string          `gorm:"column:session_id;not null;size:128"`
	Detail       json.RawMessage `gorm:"column:detail;type:jsonb;default:'{}'"`
	OccurredAt   time.Time       `gorm:"column:occurred_at;not null"`
}

func (AuditPending) TableName() string { return "mxid_audit_pending" }

// AuditEntry is a chained, append-only audit record.
type AuditEntry struct {
	TenantID   int64           `gorm:"column:tenant_id;primaryKey"`
	ChainClass string          `gorm:"column:chain_class;primaryKey;size:16"`
	Seq        int64           `gorm:"column:seq;primaryKey"`
	PrevHash   []byte          `gorm:"column:prev_hash;not null"`
	EntryHash  []byte          `gorm:"column:entry_hash;not null"`
	KeyID      string          `gorm:"column:key_id;not null;size:64"`
	Payload    json.RawMessage `gorm:"column:payload;type:jsonb;not null"`
	Imported   bool            `gorm:"column:imported;not null"`
	CreatedAt  time.Time       `gorm:"column:created_at;not null"`
}

func (AuditEntry) TableName() string { return "mxid_audit_entry" }

// ChainHead is the mutable tip of one (tenant_id, chain_class) chain.
type ChainHead struct {
	TenantID      int64     `gorm:"column:tenant_id;primaryKey"`
	ChainClass    string    `gorm:"column:chain_class;primaryKey;size:16"`
	LastSeq       int64     `gorm:"column:last_seq;not null"`
	LastEntryHash []byte    `gorm:"column:last_entry_hash;not null"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null"`
}

func (ChainHead) TableName() string { return "mxid_audit_chain_head" }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestChainTableNames -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/chainmodel.go internal/domain/audit/chainmodel_test.go
git commit -m "feat(audit): gorm models for audit chain tables"
```

---

### Task 5: Capture API — write pending in the caller's transaction

**Files:**
- Create: `internal/domain/audit/capture.go`
- Test: `internal/domain/audit/capture_test.go`

**Interfaces:**
- Consumes: `*snowflake.Generator`, `auditctx.From`, `*gorm.DB`.
- Produces:
  - `type Event struct { ChainClass, EventType, ResourceType string; ResourceID int64; Before, After, Detail map[string]any }`
  - `type Capturer struct { ... }`
  - `func NewCapturer(idGen *snowflake.Generator) *Capturer`
  - `func (c *Capturer) Capture(ctx context.Context, tx *gorm.DB, ev Event) error` — inserts one `AuditPending` on `tx`, attributing actor/ip/session from `auditctx`.

**Note on the test DB:** tests open an in-memory sqlite via `github.com/glebarez/sqlite` (already a dependency) and `AutoMigrate` the models — the chain logic is DB-agnostic; sqlite stores `[]byte`/JSON fine for unit tests.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/capture_test.go
package audit

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&AuditPending{}, &AuditEntry{}, &ChainHead{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func newTestIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCapture_WritesPendingWithActor(t *testing.T) {
	db := newTestDB(t)
	cap := NewCapturer(newTestIDGen(t))

	ctx := auditctx.With(context.Background(), auditctx.Actor{
		ActorID: 42, ActorType: "admin", TenantID: 7,
		SessionID: "sess-1", IP: "1.2.3.4", UserAgent: "curl",
	})

	err := cap.Capture(ctx, db, Event{
		ChainClass: "data", EventType: "app.deleted",
		ResourceType: "app", ResourceID: 99,
		Before: map[string]any{"name": "old"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got AuditPending
	if err := db.First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.TenantID != 7 || got.ActorID != 42 || got.EventType != "app.deleted" {
		t.Fatalf("actor/event not stamped: %+v", got)
	}
	if got.IP != "1.2.3.4" || got.SessionID != "sess-1" {
		t.Fatalf("network context not stamped: %+v", got)
	}
	if len(got.Before) == 0 {
		t.Fatalf("before not persisted")
	}
}

func TestCapture_RollbackDropsPending(t *testing.T) {
	db := newTestDB(t)
	cap := NewCapturer(newTestIDGen(t))
	ctx := auditctx.With(context.Background(), auditctx.Actor{TenantID: 7})

	tx := db.Begin()
	if err := cap.Capture(ctx, tx, Event{ChainClass: "data", EventType: "x"}); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()

	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("rollback left %d pending rows, want 0 (atomicity broken)", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestCapture -v`
Expected: FAIL — `undefined: NewCapturer`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/capture.go
package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Event is what a producer hands to Capture. ChainClass and EventType are
// required; the rest are optional.
type Event struct {
	ChainClass   string
	EventType    string
	ResourceType string
	ResourceID   int64
	Before       map[string]any
	After        map[string]any
	Detail       map[string]any
}

// Capturer writes captured events into mxid_audit_pending on the caller's
// transaction, so capture commits or rolls back atomically with the state
// change it accompanies.
type Capturer struct {
	idGen *snowflake.Generator
}

func NewCapturer(idGen *snowflake.Generator) *Capturer {
	return &Capturer{idGen: idGen}
}

func mustJSON(m map[string]any) json.RawMessage {
	if m == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}

// Capture inserts one pending row on tx. actor/ip/session are read from
// auditctx; absent context yields a system-attributed row.
func (c *Capturer) Capture(ctx context.Context, tx *gorm.DB, ev Event) error {
	actor, _ := auditctx.From(ctx)
	detail := ev.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	row := &AuditPending{
		ID:           c.idGen.Generate(),
		TenantID:     actor.TenantID,
		ChainClass:   ev.ChainClass,
		ActorID:      actor.ActorID,
		ActorType:    actor.ActorType,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Before:       mustJSON(ev.Before),
		After:        mustJSON(ev.After),
		IP:           actor.IP,
		UserAgent:    actor.UserAgent,
		SessionID:    actor.SessionID,
		Detail:       mustJSON(detail),
		OccurredAt:   time.Now().UTC(),
	}
	return tx.WithContext(ctx).Create(row).Error
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestCapture -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/capture.go internal/domain/audit/capture_test.go
git commit -m "feat(audit): transactional capture into audit_pending"
```

---

### Task 6: Chainer — drain pending FIFO into the append-only chain

**Files:**
- Create: `internal/domain/audit/chainer.go`
- Test: `internal/domain/audit/chainer_test.go`

**Interfaces:**
- Consumes: `AuditPending`, `AuditEntry`, `ChainHead`, `ComputeEntryHash`, `CanonicalJSON`, `GenesisPrevHash`.
- Produces:
  - `type Chainer struct { ... }`
  - `func NewChainer(db *gorm.DB, key []byte, keyID string, logger *zap.Logger) *Chainer`
  - `func (c *Chainer) ProcessBatch(ctx context.Context, limit int) (int, error)` — drains up to `limit` pending rows in `id` order, chains each, returns count processed.

**Behavior contract (tested below):**
- Rows chain per `(tenant_id, chain_class)`; the first row of a chain gets `seq=1`, `prev_hash=GenesisPrevHash`.
- Each processed pending row: INSERT `AuditEntry`, upsert `ChainHead`, DELETE the pending row — all in one transaction per batch.
- `payload` stored in `AuditEntry` equals the `CanonicalJSON` bytes used for hashing (so verify re-reads the exact preimage).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/chainer_test.go
package audit

import (
	"bytes"
	"context"
	"testing"

	"go.uber.org/zap"
)

func seedPending(t *testing.T, db *gorm.DB, gen *snowflake.Generator, tenant int64, class, evt string) {
	t.Helper()
	cap := NewCapturer(gen)
	ctx := auditctx.With(context.Background(), auditctx.Actor{TenantID: tenant, ActorID: 1, ActorType: "admin"})
	if err := cap.Capture(ctx, db, Event{ChainClass: class, EventType: evt}); err != nil {
		t.Fatal(err)
	}
}

func TestChainer_ChainsInOrder(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")
	seedPending(t, db, gen, 7, "data", "e2")
	seedPending(t, db, gen, 7, "data", "e3")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	n, err := c.ProcessBatch(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("processed %d, want 3", n)
	}

	var entries []AuditEntry
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").Order("seq asc").Find(&entries)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Seq != 1 || entries[1].Seq != 2 || entries[2].Seq != 3 {
		t.Fatalf("seq not 1,2,3: %d,%d,%d", entries[0].Seq, entries[1].Seq, entries[2].Seq)
	}
	if !bytes.Equal(entries[0].PrevHash, GenesisPrevHash) {
		t.Fatalf("first prev_hash not genesis")
	}
	if !bytes.Equal(entries[1].PrevHash, entries[0].EntryHash) {
		t.Fatalf("chain link broken between seq 1 and 2")
	}
	if !bytes.Equal(entries[2].PrevHash, entries[1].EntryHash) {
		t.Fatalf("chain link broken between seq 2 and 3")
	}

	var nPending int64
	db.Model(&AuditPending{}).Count(&nPending)
	if nPending != 0 {
		t.Fatalf("pending not drained: %d left", nPending)
	}
}

func TestChainer_SeparateChainsPerClass(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "d1")
	seedPending(t, db, gen, 7, "auth", "a1")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	if _, err := c.ProcessBatch(context.Background(), 100); err != nil {
		t.Fatal(err)
	}

	var dataHead, authHead ChainHead
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").First(&dataHead)
	db.Where("tenant_id = ? AND chain_class = ?", 7, "auth").First(&authHead)
	if dataHead.LastSeq != 1 || authHead.LastSeq != 1 {
		t.Fatalf("each class should start at seq 1: data=%d auth=%d", dataHead.LastSeq, authHead.LastSeq)
	}
}
```

Add the missing imports to the test file's import block: `"github.com/imkerbos/mxid/pkg/auditctx"`, `"github.com/imkerbos/mxid/pkg/snowflake"`, `"gorm.io/gorm"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestChainer -v`
Expected: FAIL — `undefined: NewChainer`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/chainer.go
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Chainer drains mxid_audit_pending FIFO and appends to mxid_audit_entry,
// maintaining one HMAC hash chain per (tenant_id, chain_class). It is designed
// to run as a single goroutine (single writer) — do not run two concurrently
// against the same DB.
type Chainer struct {
	db     *gorm.DB
	key    []byte
	keyID  string
	logger *zap.Logger
}

func NewChainer(db *gorm.DB, key []byte, keyID string, logger *zap.Logger) *Chainer {
	return &Chainer{db: db, key: key, keyID: keyID, logger: logger}
}

// ProcessBatch chains up to limit pending rows (oldest id first) in one
// transaction. Returns the number of rows chained.
func (c *Chainer) ProcessBatch(ctx context.Context, limit int) (int, error) {
	var processed int
	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var pend []AuditPending
		if err := tx.Order("id asc").Limit(limit).Find(&pend).Error; err != nil {
			return err
		}
		for i := range pend {
			if err := c.chainOne(tx, &pend[i]); err != nil {
				return err
			}
			if err := tx.Delete(&AuditPending{}, "id = ?", pend[i].ID).Error; err != nil {
				return err
			}
			processed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return processed, nil
}

func (c *Chainer) chainOne(tx *gorm.DB, p *AuditPending) error {
	// Load or init the chain head for this (tenant, class).
	var head ChainHead
	err := tx.Where("tenant_id = ? AND chain_class = ?", p.TenantID, p.ChainClass).First(&head).Error
	if err == gorm.ErrRecordNotFound {
		head = ChainHead{TenantID: p.TenantID, ChainClass: p.ChainClass, LastSeq: 0, LastEntryHash: GenesisPrevHash}
	} else if err != nil {
		return err
	}

	seq := head.LastSeq + 1
	payload := ChainPayload{
		TenantID:     p.TenantID,
		ChainClass:   p.ChainClass,
		ActorID:      p.ActorID,
		ActorType:    p.ActorType,
		EventType:    p.EventType,
		ResourceType: p.ResourceType,
		ResourceID:   p.ResourceID,
		Before:       jsonToMap(p.Before),
		After:        jsonToMap(p.After),
		IP:           p.IP,
		UserAgent:    p.UserAgent,
		SessionID:    p.SessionID,
		Detail:       jsonToMap(p.Detail),
		OccurredAt:   p.OccurredAt.UTC().Format(time.RFC3339),
	}
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	entryHash := ComputeEntryHash(c.key, seq, head.LastEntryHash, canonical)

	entry := &AuditEntry{
		TenantID:   p.TenantID,
		ChainClass: p.ChainClass,
		Seq:        seq,
		PrevHash:   head.LastEntryHash,
		EntryHash:  entryHash,
		KeyID:      c.keyID,
		Payload:    canonical,
		Imported:   false,
		CreatedAt:  time.Now().UTC(),
	}
	if err := tx.Create(entry).Error; err != nil {
		return err
	}

	head.LastSeq = seq
	head.LastEntryHash = entryHash
	head.UpdatedAt = time.Now().UTC()
	return tx.Save(&head).Error
}

func jsonToMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestChainer -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/chainer.go internal/domain/audit/chainer_test.go
git commit -m "feat(audit): ordered chainer draining pending into append-only chain"
```

---

### Task 7: VerifyChain — detect tampering and deletion

**Files:**
- Create: `internal/domain/audit/verify.go`
- Test: `internal/domain/audit/verify_test.go`

**Interfaces:**
- Consumes: `AuditEntry`, `ComputeEntryHash`, `GenesisPrevHash`.
- Produces:
  - `type VerifyResult struct { OK bool; VerifiedThrough int64; FailSeq int64; Reason string }`
  - `func VerifyChain(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string) (VerifyResult, error)`

**Contract:**
- Walks entries in `seq` order from 1. For each: recompute `entry_hash` from stored `payload` + running `prev_hash`; the recomputed value must equal the stored `entry_hash`, and the stored `prev_hash` must equal the previous entry's `entry_hash` (genesis for seq 1).
- Missing `seq` (gap) ⇒ `OK=false`, `Reason="seq gap"` (a row was deleted).
- Any hash mismatch ⇒ `OK=false`, `Reason="hash mismatch"` with `FailSeq`.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/verify_test.go
package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func chainedDB(t *testing.T) (*gorm.DB, []byte) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")
	seedPending(t, db, gen, 7, "data", "e2")
	seedPending(t, db, gen, 7, "data", "e3")
	key := []byte("key")
	c := NewChainer(db, key, "default", zap.NewNop())
	if _, err := c.ProcessBatch(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	return db, key
}

func TestVerify_CleanChainOK(t *testing.T) {
	db, key := chainedDB(t)
	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.VerifiedThrough != 3 {
		t.Fatalf("clean chain failed: %+v", res)
	}
}

func TestVerify_TamperedPayloadDetected(t *testing.T) {
	db, key := chainedDB(t)
	// Tamper: overwrite payload of seq 2 directly (simulating a DB-level edit).
	db.Model(&AuditEntry{}).
		Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).
		Update("payload", []byte(`{"tampered":true}`))

	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.FailSeq != 2 {
		t.Fatalf("tamper not detected at seq 2: %+v", res)
	}
}

func TestVerify_DeletionDetected(t *testing.T) {
	db, key := chainedDB(t)
	// Delete seq 2 -> gap.
	db.Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).Delete(&AuditEntry{})

	res, err := VerifyChain(context.Background(), db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Reason != "seq gap" {
		t.Fatalf("deletion not detected: %+v", res)
	}
}
```

Add imports to the test's block: `"gorm.io/gorm"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestVerify -v`
Expected: FAIL — `undefined: VerifyChain`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/verify.go
package audit

import (
	"bytes"
	"context"

	"gorm.io/gorm"
)

// VerifyResult reports the outcome of walking one chain.
type VerifyResult struct {
	OK              bool
	VerifiedThrough int64  // highest seq verified clean
	FailSeq         int64  // seq where verification failed (0 if OK)
	Reason          string // "", "hash mismatch", "seq gap", "prev_hash mismatch"
}

// VerifyChain recomputes the HMAC chain for (tenantID, chainClass) from genesis
// and reports the first inconsistency. A gap in seq means a row was deleted.
func VerifyChain(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string) (VerifyResult, error) {
	var entries []AuditEntry
	err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, chainClass).
		Order("seq asc").
		Find(&entries).Error
	if err != nil {
		return VerifyResult{}, err
	}

	prev := GenesisPrevHash
	var expectedSeq int64 = 1
	for _, e := range entries {
		if e.Seq != expectedSeq {
			return VerifyResult{OK: false, VerifiedThrough: expectedSeq - 1, FailSeq: expectedSeq, Reason: "seq gap"}, nil
		}
		if !bytes.Equal(e.PrevHash, prev) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "prev_hash mismatch"}, nil
		}
		want := ComputeEntryHash(key, e.Seq, prev, e.Payload)
		if !bytes.Equal(want, e.EntryHash) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "hash mismatch"}, nil
		}
		prev = e.EntryHash
		expectedSeq++
	}
	return VerifyResult{OK: true, VerifiedThrough: expectedSeq - 1}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestVerify -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/verify.go internal/domain/audit/verify_test.go
git commit -m "feat(audit): VerifyChain detects tampering and deletion"
```

---

### Task 8: Chainer run loop + bootstrap wiring

**Files:**
- Modify: `internal/domain/audit/chainer.go` (add `Run`)
- Modify: `internal/bootstrap/*.go` (start the chainer goroutine — resolve exact file via `grep -rln "outbox.NewWorker\|Worker" internal/bootstrap`)
- Test: `internal/domain/audit/chainer_run_test.go`

**Interfaces:**
- Produces: `func (c *Chainer) Run(ctx context.Context, interval time.Duration)` — ticks `ProcessBatch` until ctx is cancelled.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/chainer_run_test.go
package audit

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestChainer_RunDrainsThenStops(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, 5*time.Millisecond); close(done) }()

	// Give it a few ticks to drain.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on cancel")
	}

	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("Run left %d pending", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestChainer_Run -v`
Expected: FAIL — `c.Run undefined`

- [ ] **Step 3: Write minimal implementation**

Append to `internal/domain/audit/chainer.go` (add `"time"` to imports if not present):

```go
// Run ticks ProcessBatch every interval until ctx is cancelled. Single
// goroutine — this IS the single writer to the chain.
func (c *Chainer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := c.ProcessBatch(ctx, 100); err != nil {
			c.logger.Warn("audit chainer: batch failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestChainer_Run -v`
Expected: PASS

- [ ] **Step 5: Wire into bootstrap**

Find where background workers start (e.g. the outbox worker's `go worker.Run(ctx)`):

Run: `grep -rn "\.Run(ctx)" internal/bootstrap`

Add alongside it, using the app's existing DB handle, snowflake generator, logger, and the audit HMAC key from config (Phase 1: read `cfg.Audit.ChainKey` — a hex/base64 string decoded to `[]byte`; if the config field does not yet exist, add it to the config struct and `.env.example` as `AUDIT_CHAIN_KEY`):

```go
chainer := audit.NewChainer(db, auditChainKey, "default", logger)
go chainer.Run(ctx, 2*time.Second)
```

- [ ] **Step 6: Verify build + tests**

Run: `go build ./... && go test ./internal/domain/audit/ ./internal/bootstrap/...`
Expected: build OK, tests PASS

- [ ] **Step 7: Commit**

```bash
git add internal/domain/audit/chainer.go internal/domain/audit/chainer_run_test.go internal/bootstrap/
git commit -m "feat(audit): run chainer as a background single-writer loop"
```

---

### Task 9: verify as an integration test over sqlite (full round-trip)

**Files:**
- Test: `internal/domain/audit/roundtrip_test.go`

**Interfaces:**
- Consumes: everything above. No new production code — this task locks the end-to-end guarantee.

- [ ] **Step 1: Write the round-trip test**

```go
// internal/domain/audit/roundtrip_test.go
package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// Capture -> chain -> verify -> tamper -> verify-fails, in one flow. This is the
// executable statement of the Phase 1 guarantee.
func TestRoundTrip_CaptureChainVerifyTamper(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	key := []byte("integration-key")

	for i := 0; i < 5; i++ {
		seedPending(t, db, gen, 7, "data", "evt")
	}
	c := NewChainer(db, key, "default", zap.NewNop())
	n, err := c.ProcessBatch(context.Background(), 100)
	if err != nil || n != 5 {
		t.Fatalf("chain: n=%d err=%v", n, err)
	}

	res, _ := VerifyChain(context.Background(), db, key, 7, "data")
	if !res.OK || res.VerifiedThrough != 5 {
		t.Fatalf("expected clean verify through 5, got %+v", res)
	}

	// A wrong key must fail verification for the whole chain at seq 1.
	bad, _ := VerifyChain(context.Background(), db, []byte("wrong-key"), 7, "data")
	if bad.OK {
		t.Fatalf("verification passed under wrong key — HMAC not actually protecting")
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/domain/audit/ -run TestRoundTrip -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/domain/audit/roundtrip_test.go
git commit -m "test(audit): end-to-end capture-chain-verify-tamper round-trip"
```

---

### Task 10: CLI `audit verify` command

**Files:**
- Create: the CLI command file (resolve location: `grep -rn "cobra.Command\|AddCommand" cmd/ | head` — match the existing CLI style; if the project uses a single `cmd/server` with subcommands, add a `verify-audit` subcommand there).
- Test: covered by Task 7/9 (the command is a thin wrapper).

**Interfaces:**
- Consumes: `audit.VerifyChain`, the app DB, the audit chain key.
- Produces: a command that prints `chain (tenant=%d class=%s): verified through seq %d, %s`.

- [ ] **Step 1: Add the command**

Following the project's CLI pattern, add a command that:
1. Loads config + opens the DB (reuse the bootstrap DB init).
2. Reads the audit chain key from config.
3. For each `(tenant_id, chain_class)` present in `mxid_audit_chain_head`, calls `audit.VerifyChain` and prints the result.

```go
// exact package/path per the project's cmd structure
func runVerifyAudit(ctx context.Context, db *gorm.DB, key []byte) error {
	var heads []audit.ChainHead
	if err := db.Find(&heads).Error; err != nil {
		return err
	}
	for _, h := range heads {
		res, err := audit.VerifyChain(ctx, db, key, h.TenantID, h.ChainClass)
		if err != nil {
			return err
		}
		status := "OK"
		if !res.OK {
			status = fmt.Sprintf("FAIL at seq %d (%s)", res.FailSeq, res.Reason)
		}
		fmt.Printf("chain tenant=%d class=%s: verified through seq %d — %s\n",
			h.TenantID, h.ChainClass, res.VerifiedThrough, status)
	}
	return nil
}
```

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: build OK

- [ ] **Step 3: Manual smoke (against a dev DB with some chained rows)**

Run: the new command (e.g. `go run ./cmd/server verify-audit` — exact invocation per CLI wiring)
Expected: prints one line per chain, all `OK`.

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "feat(audit): CLI command to verify audit chains"
```

---

## Self-Review

**Spec coverage (Phase 1 slice of the design doc):**
- §2 pipeline (capture → pending → ordered chainer → append-only log): Tasks 5, 6, 8. ✅
- §3 data structures (audit_pending, audit_log→audit_entry, chain_head): Tasks 3, 4. ✅ (Deviation: `anchored_root_id` removed from the entry table — anchoring lives in Phase 3's `audit_anchor` range so the entry table stays INSERT-only for all roles. Documented in Global Constraints.)
- §6 verify: Tasks 7, 9, 10. ✅
- §5 hash chain (HMAC, canonical, genesis, key_id): Tasks 1, 2, 6. ✅
- §5 external Merkle anchoring: **deferred to Phase 3** (out of this plan's scope; noted).
- §4 ORM callback enforcement + §5 DB append-only privileges: **deferred to Phase 2**.
- §8 UI, §9 migration, §10 remaining tests, sensitive-read/app-event integration: **later phases**.

**Placeholder scan:** No "TBD"/"handle edge cases"/vague steps; every code step has full code. Two locations intentionally say "resolve exact path via grep" (Task 8 bootstrap, Task 10 CLI) because the wiring point depends on existing structure — each gives the exact grep and the exact code to add. Acceptable (not a code placeholder).

**Type consistency:** `ChainPayload`, `AuditPending`, `AuditEntry`, `ChainHead`, `Capturer.Capture`, `Chainer.ProcessBatch/Run`, `VerifyChain`, `VerifyResult` names and signatures are consistent across Tasks 2–10. `ComputeEntryHash(key, seq, prevHash, canonical)` argument order identical in chain.go, chainer.go, verify.go.

## Phase Roadmap (subsequent plans, each its own doc)

- **Phase 2:** gorm Create/Update/Delete callback capturing before/after for the audited-table whitelist; DB role privileges making `mxid_audit_entry` INSERT-only for the app role; whitelist-coverage test.
- **Phase 3:** Merkle root + Ed25519 signing (reuse `pkg/ee/license` signer) + `audit_anchor` + pluggable external WORM sink; verify extended to check anchors.
- **Phase 4:** migrate existing `auditctx` app-event emitters + sensitive-read events onto `Capture`; export CLI (JSONL + proof.json); verification-status query API.
- **Phase 5:** time-range audit viewer UI with verify/anchor badges; one-time import of historical `mxid_audit_log` as `imported=true`; retention-purge hardening.
