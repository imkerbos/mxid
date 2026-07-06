# Tamper-Proof Audit — Provability Phase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the audit chain third-party-provable and close the two Phase-3 residuals: (1) an **export** producing a self-contained, offline-verifiable proof of a chain segment (Ed25519 anchors + public key — no secret needed), (2) **sink-diff verification** that detects deleted anchor rows by cross-checking the DB against the external sink, (3) **multi-key verification** so anchor-key rotation doesn't break historical verification.

**Architecture:** Third-party proof rests on the Ed25519-signed Merkle anchors (public-key verifiable), NOT the HMAC chain (which needs the secret key). `ExportChain` writes the entries of a seq range + the signed anchors covering them + the public key to a directory; `VerifyExport` re-verifies that WITHOUT a DB or secret. `VerifyAnchorsWithSink` reads the sink back (new `AnchorSink.List`) and flags any DB anchor missing from the sink or sink anchor missing from the DB. A key registry maps `key_id → ed25519.PublicKey` (current seed's public key + operator-configured retired keys) so each anchor verifies against the key that signed it.

**Tech Stack:** Go 1.25, `crypto/ed25519`, existing `internal/domain/audit` (Phase 1-4), `pkg/crypto`, `internal/bootstrap` config.

## Global Constraints

- Module `github.com/imkerbos/mxid`. No new DB migration (export/verify are read-only; multi-key is config).
- Third-party proof uses ONLY the Ed25519 anchors + public key. The HMAC chain key is NEVER exported. Unanchored tail entries can be exported but are NOT third-party-provable (they need anchoring first); `VerifyExport` certifies only the anchored coverage and reports the unanchored remainder.
- `key_id` = first 16 hex of SHA256(pubkey) (Phase 3 `KeyIDForPublic`). Each anchor stores its `key_id`; verification resolves the key by it.
- Retired anchor public keys config: `MXID_CRYPTO_AUDIT_ANCHOR_RETIRED_PUBKEYS` (comma-separated base64 raw ed25519 public keys). The current key's public key (derived from `AuditAnchorKey` seed) is always in the registry.
- `VerifyExport` must run with NO database and NO secret — only the export files + a set of trusted public keys.

## File Structure

- `internal/domain/audit/anchorsink.go` — add `List` to `AnchorSink` + `FileSink`. (modify)
- `internal/domain/audit/anchorkeys.go` — `KeyRegistry` (key_id → PublicKey). (create)
- `internal/domain/audit/verify.go` — multi-key `VerifyAnchors` + `VerifyAnchorsWithSink`. (modify)
- `internal/domain/audit/export.go` — `ExportChain` / `ExportBundle` types + `WriteExport` + `VerifyExport`. (create)
- `internal/bootstrap/config.go` — retired-pubkeys config field. (modify)
- `app/audit_verify.go` — `audit-export` + `verify-export` subcommands; use sink-diff + registry. (modify)
- `app/run.go` — dispatch the two new subcommands. (modify)
- `internal/domain/audit/*_test.go` — tests.

---

### Task 1: AnchorSink.List + FileSink.List

**Files:**
- Modify: `internal/domain/audit/anchorsink.go`
- Test: `internal/domain/audit/anchorsink_test.go` (add)

**Interfaces:**
- Produces: `List(ctx context.Context) ([]AnchorRecord, error)` on `AnchorSink` + `FileSink` (reads the JSONL back, one record per line).

- [ ] **Step 1: Write the failing test**

```go
// add to internal/domain/audit/anchorsink_test.go
func TestFileSink_ListRoundTrips(t *testing.T) {
	dir := t.TempDir()
	sink := NewFileSink(dir + "/anchors.log")
	recs := []AnchorRecord{
		{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 3, MerkleRoot: []byte{1}, Signature: []byte{2}, KeyID: "k1"},
		{TenantID: 7, ChainClass: "data", FromSeq: 4, ToSeq: 4, MerkleRoot: []byte{3}, Signature: []byte{4}, KeyID: "k1"},
	}
	for _, r := range recs {
		if _, err := sink.Put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := sink.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].FromSeq != 1 || got[1].ToSeq != 4 {
		t.Fatalf("list round-trip wrong: %+v", got)
	}
}

func TestFileSink_ListEmptyWhenNoFile(t *testing.T) {
	sink := NewFileSink(t.TempDir() + "/none.log")
	got, err := sink.List(context.Background())
	if err != nil {
		t.Fatalf("missing file should be empty, not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestFileSink_List -v`
Expected: FAIL — `sink.List undefined`

- [ ] **Step 3: Write minimal implementation**

Add `List` to the `AnchorSink` interface, and implement on `FileSink`:

```go
// in the AnchorSink interface:
	// List returns all records previously Put, in append order. A missing file
	// is an empty list, not an error.
	List(ctx context.Context) ([]AnchorRecord, error)
```

```go
// FileSink.List (append to anchorsink.go)
func (s *FileSink) List(_ context.Context) ([]AnchorRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open anchor sink: %w", err)
	}
	defer f.Close()
	var out []AnchorRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // anchors can be a few KB
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec AnchorRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("parse anchor line: %w", err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
```

Add imports `bufio` to anchorsink.go (`encoding/json`, `os`, `fmt` already present).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestFileSink_List -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchorsink.go internal/domain/audit/anchorsink_test.go
git commit -m "feat(audit): AnchorSink.List to read anchors back for sink-diff/export"
```

---

### Task 2: Anchor key registry (multi-key) + config

**Files:**
- Create: `internal/domain/audit/anchorkeys.go`
- Modify: `internal/bootstrap/config.go` (retired-pubkeys field)
- Test: `internal/domain/audit/anchorkeys_test.go`

**Interfaces:**
- Produces:
  - `type KeyRegistry map[string]ed25519.PublicKey` (key_id → pubkey)
  - `func NewKeyRegistry(pubs ...ed25519.PublicKey) KeyRegistry` — indexes each by `KeyIDForPublic`.
  - `func (r KeyRegistry) For(keyID string) (ed25519.PublicKey, bool)`

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/anchorkeys_test.go
package audit

import (
	"crypto/ed25519"
	"testing"
)

func TestKeyRegistry_ResolvesByKeyID(t *testing.T) {
	seed1 := make([]byte, ed25519.SeedSize)
	seed1[0] = 1
	seed2 := make([]byte, ed25519.SeedSize)
	seed2[0] = 2
	pub1 := ed25519.NewKeyFromSeed(seed1).Public().(ed25519.PublicKey)
	pub2 := ed25519.NewKeyFromSeed(seed2).Public().(ed25519.PublicKey)

	reg := NewKeyRegistry(pub1, pub2)
	got1, ok := reg.For(KeyIDForPublic(pub1))
	if !ok || !got1.Equal(pub1) {
		t.Fatal("pub1 not resolved by its key_id")
	}
	if _, ok := reg.For("deadbeefdeadbeef"); ok {
		t.Fatal("unknown key_id should not resolve")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestKeyRegistry -v`
Expected: FAIL — `undefined: NewKeyRegistry`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/anchorkeys.go
package audit

import "crypto/ed25519"

// KeyRegistry maps an anchor key_id to the Ed25519 public key that signed it, so
// verification survives key rotation: each anchor carries its key_id, and old
// anchors keep verifying against retired-but-registered public keys.
type KeyRegistry map[string]ed25519.PublicKey

// NewKeyRegistry indexes each public key by its KeyIDForPublic.
func NewKeyRegistry(pubs ...ed25519.PublicKey) KeyRegistry {
	r := make(KeyRegistry, len(pubs))
	for _, p := range pubs {
		if len(p) == 0 {
			continue
		}
		r[KeyIDForPublic(p)] = p
	}
	return r
}

// For returns the public key for a key_id.
func (r KeyRegistry) For(keyID string) (ed25519.PublicKey, bool) {
	p, ok := r[keyID]
	return p, ok
}
```

Config: add to `CryptoConfig` a field `AuditAnchorRetiredPubKeys string` (mapstructure `audit_anchor_retired_pubkeys`, env `MXID_CRYPTO_AUDIT_ANCHOR_RETIRED_PUBKEYS`), a comma-separated list of base64 raw ed25519 public keys. Add to `.env.example` (empty, with a comment: "comma-separated base64 ed25519 public keys retired from anchoring; keep so their old anchors still verify") and `configs/config.yaml` (`audit_anchor_retired_pubkeys: ""`). No validateSecrets rule (optional).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestKeyRegistry -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchorkeys.go internal/domain/audit/anchorkeys_test.go internal/bootstrap/config.go .env.example configs/config.yaml
git commit -m "feat(audit): anchor key registry (multi-key verify) + retired pubkeys config"
```

---

### Task 3: Multi-key VerifyAnchors

**Files:**
- Modify: `internal/domain/audit/verify.go`
- Test: `internal/domain/audit/verify_anchor_test.go` (add)

**Interfaces:**
- Change `VerifyAnchors` to resolve the key per anchor via a `KeyRegistry` instead of a single `pub`:
  `func VerifyAnchors(ctx, db, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error)`
- Update the existing callers (`app/audit_verify.go`, existing tests) to pass `NewKeyRegistry(pub)`.
- On an anchor whose `key_id` isn't in the registry → `OK=false, Reason="unknown key"`.

- [ ] **Step 1: Write the failing test**

```go
// add to verify_anchor_test.go
func TestVerifyAnchors_RetiredKeyStillVerifies(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 2; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	// anchor with an "old" key
	oldPriv := testKey(t)
	an := NewAnchorer(db, oldPriv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)

	// a NEW current key is now in play, but the registry ALSO holds the retired one
	newSeed := make([]byte, ed25519.SeedSize)
	newSeed[0] = 99
	newPub := ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey)
	reg := NewKeyRegistry(newPub, oldPub)

	res, err := VerifyAnchors(context.Background(), db, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("retired-key anchor should verify via registry: %+v err=%v", res, err)
	}
	// registry WITHOUT the old key -> unknown key
	res2, _ := VerifyAnchors(context.Background(), db, NewKeyRegistry(newPub), 7, "data")
	if res2.OK || res2.Reason != "unknown key" {
		t.Fatalf("missing key should be 'unknown key': %+v", res2)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchors_RetiredKey -v`
Expected: FAIL — VerifyAnchors signature mismatch / no "unknown key"

- [ ] **Step 3: Write minimal implementation**

Change `VerifyAnchors` to take `keys KeyRegistry`. In the loop, before the signature check, resolve the anchor's key:

```go
		pub, ok := keys.For(a.KeyID)
		if !ok {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
```

Add `"unknown key"` to the `AnchorVerifyResult.Reason` doc comment. Update the callers:
- Existing `verify_anchor_test.go` tests that call `VerifyAnchors(ctx, db, pub, ...)` → change to `VerifyAnchors(ctx, db, NewKeyRegistry(pub), ...)`.
- `app/audit_verify.go` — build a registry from the anchor pubkey (Task 6 refines this) and pass it.
- The Postgres e2e (`e2e_postgres_test.go`) VerifyAnchors call → wrap with `NewKeyRegistry(anchorPub)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchors -v && go build ./...`
Expected: PASS + build clean (all callers updated).

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/verify.go internal/domain/audit/verify_anchor_test.go internal/domain/audit/e2e_postgres_test.go app/audit_verify.go
git commit -m "feat(audit): verify anchors against a key registry (survives key rotation)"
```

---

### Task 4: Sink-diff — detect deleted anchor rows

**Files:**
- Modify: `internal/domain/audit/verify.go`
- Test: `internal/domain/audit/verify_sinkdiff_test.go`

**Interfaces:**
- Produces: `func VerifyAnchorsWithSink(ctx, db, sink AnchorSink, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error)` — runs `VerifyAnchors` (DB-side), then cross-checks the sink: every DB anchor `(tenant,class,from,to)` must be present in the sink with a matching `merkle_root`+`signature`, and every sink anchor for this chain must be present in the DB. A DB row missing from the sink or a sink record missing from the DB ⇒ `OK=false, Reason="sink mismatch"` (an anchor row was deleted/altered on one side). This closes the Phase-3 residual: deleting a DB anchor row is now detectable because the signed copy survives in the sink.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/verify_sinkdiff_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func TestVerifyAnchorsWithSink_DeletedDBRowDetected(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	// clean: sink and DB agree
	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("clean sink-diff should pass: %+v err=%v", res, err)
	}
	// delete the DB anchor row (attacker with DB access) — sink copy survives
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").Delete(&AuditAnchor{})
	bad, _ := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if bad.OK || bad.Reason != "sink mismatch" {
		t.Fatalf("deleted DB anchor row not detected via sink: %+v", bad)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchorsWithSink -v`
Expected: FAIL — `undefined: VerifyAnchorsWithSink`

- [ ] **Step 3: Write minimal implementation**

```go
// append to verify.go
// VerifyAnchorsWithSink runs the DB-side anchor verification, then cross-checks
// the external sink so that DELETING a DB anchor row (which VerifyAnchors alone
// reports only as a coverage gap, and not at all if the whole tail is dropped)
// is caught: the signed copy in the sink survives a DB compromise.
func VerifyAnchorsWithSink(ctx context.Context, db *gorm.DB, sink AnchorSink, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error) {
	res, err := VerifyAnchors(ctx, db, keys, tenantID, class)
	if err != nil {
		return res, err
	}

	var dbAnchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&dbAnchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	sinkAll, err := sink.List(ctx)
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	// index the sink by (tenant,class,from,to)
	type k struct {
		t    int64
		c    string
		f, o int64
	}
	sinkIdx := make(map[k]AnchorRecord)
	for _, r := range sinkAll {
		if r.TenantID == tenantID && r.ChainClass == class {
			sinkIdx[k{r.TenantID, r.ChainClass, r.FromSeq, r.ToSeq}] = r
		}
	}
	dbIdx := make(map[k]bool)
	for i := range dbAnchors {
		a := &dbAnchors[i]
		dbIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}] = true
		sr, ok := sinkIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}]
		if !ok || !bytesEqual(sr.MerkleRoot, a.MerkleRoot) || !bytesEqual(sr.Signature, a.Signature) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: a.FromSeq, Reason: "sink mismatch"}, nil
		}
	}
	// sink record not present in DB -> a DB anchor row was deleted
	for key := range sinkIdx {
		if !dbIdx[key] {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: key.f, Reason: "sink mismatch"}, nil
		}
	}
	return res, nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
```

(If a `bytes.Equal` is already imported in verify.go, use it and drop the helper.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchorsWithSink -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/verify.go internal/domain/audit/verify_sinkdiff_test.go
git commit -m "feat(audit): sink-diff verify detects deleted anchor rows"
```

---

### Task 5: Export bundle + WriteExport

**Files:**
- Create: `internal/domain/audit/export.go`
- Test: `internal/domain/audit/export_test.go`

**Interfaces:**
- Produces:
  - `type ExportEntry struct { Seq int64; PrevHash, EntryHash, Payload []byte }`
  - `type ExportBundle struct { TenantID int64; ChainClass string; FromSeq, ToSeq int64; Entries []ExportEntry; Anchors []AuditAnchor; PubKeys map[string]string /*key_id->base64 pub*/ }`
  - `func BuildExport(ctx, db, keys KeyRegistry, tenantID int64, class string, fromSeq, toSeq int64) (*ExportBundle, error)` — loads entries in [from,to] + all anchors overlapping that range + the pubkeys (base64) for those anchors' key_ids.
  - `func WriteExport(dir string, b *ExportBundle) error` — writes `entries.jsonl` (one ExportEntry per line) + `proof.json` (the bundle minus entries: anchors + pubkeys + range).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/export_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestBuildAndWriteExport(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	an.AnchorChain(context.Background(), 7, "data")
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	b, err := BuildExport(context.Background(), db, reg, 7, "data", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) != 3 || len(b.Anchors) != 1 || len(b.PubKeys) != 1 {
		t.Fatalf("bundle wrong: entries=%d anchors=%d keys=%d", len(b.Entries), len(b.Anchors), len(b.PubKeys))
	}
	dir := t.TempDir()
	if err := WriteExport(dir, b); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"entries.jsonl", "proof.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestBuildAndWriteExport -v`
Expected: FAIL — `undefined: BuildExport`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/export.go
package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/gorm"
)

type ExportEntry struct {
	Seq       int64  `json:"seq"`
	PrevHash  []byte `json:"prev_hash"`
	EntryHash []byte `json:"entry_hash"`
	Payload   []byte `json:"payload"`
}

type ExportBundle struct {
	TenantID   int64             `json:"tenant_id"`
	ChainClass string            `json:"chain_class"`
	FromSeq    int64             `json:"from_seq"`
	ToSeq      int64             `json:"to_seq"`
	Entries    []ExportEntry     `json:"entries,omitempty"`
	Anchors    []AuditAnchor     `json:"anchors"`
	PubKeys    map[string]string `json:"pub_keys"` // key_id -> base64 raw ed25519 public key
}

// BuildExport gathers a self-contained, third-party-verifiable bundle: the chain
// entries in [fromSeq,toSeq], the signed anchors overlapping that range, and the
// public keys (by key_id) needed to verify them. The HMAC key is never included;
// verification rests entirely on the Ed25519 anchors.
func BuildExport(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string, fromSeq, toSeq int64) (*ExportBundle, error) {
	var entries []AuditEntry
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq >= ? AND seq <= ?", tenantID, class, fromSeq, toSeq).
		Order("seq asc").Find(&entries).Error; err != nil {
		return nil, err
	}
	b := &ExportBundle{TenantID: tenantID, ChainClass: class, FromSeq: fromSeq, ToSeq: toSeq, PubKeys: map[string]string{}}
	for _, e := range entries {
		b.Entries = append(b.Entries, ExportEntry{Seq: e.Seq, PrevHash: e.PrevHash, EntryHash: e.EntryHash, Payload: e.Payload})
	}
	// anchors overlapping [fromSeq,toSeq]
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND to_seq >= ? AND from_seq <= ?", tenantID, class, fromSeq, toSeq).
		Order("from_seq asc").Find(&b.Anchors).Error; err != nil {
		return nil, err
	}
	for _, a := range b.Anchors {
		if pub, ok := keys.For(a.KeyID); ok {
			b.PubKeys[a.KeyID] = base64.StdEncoding.EncodeToString(pub)
		}
	}
	return b, nil
}

// WriteExport writes entries.jsonl (one ExportEntry per line) + proof.json (the
// bundle without entries) to dir.
func WriteExport(dir string, b *ExportBundle) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ef, err := os.Create(filepath.Join(dir, "entries.jsonl"))
	if err != nil {
		return err
	}
	defer ef.Close()
	enc := json.NewEncoder(ef)
	for _, e := range b.Entries {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("write entry: %w", err)
		}
	}
	proof := *b
	proof.Entries = nil // entries live in entries.jsonl
	pf, err := os.Create(filepath.Join(dir, "proof.json"))
	if err != nil {
		return err
	}
	defer pf.Close()
	pe := json.NewEncoder(pf)
	pe.SetIndent("", "  ")
	return pe.Encode(proof)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestBuildAndWriteExport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/export.go internal/domain/audit/export_test.go
git commit -m "feat(audit): build + write a third-party-verifiable audit export bundle"
```

---

### Task 6: Offline VerifyExport (no DB, no secret)

**Files:**
- Modify: `internal/domain/audit/export.go`
- Test: `internal/domain/audit/export_verify_test.go`

**Interfaces:**
- Produces:
  - `func ReadExport(dir string) (*ExportBundle, error)` — reads entries.jsonl + proof.json back into a bundle.
  - `func VerifyExport(b *ExportBundle, trusted KeyRegistry) (AnchorVerifyResult, error)` — with NO DB: for each anchor, resolve its key from the bundle's PubKeys AND require that key to be in `trusted`; verify the Ed25519 signature; recompute the Merkle root over the EXPORTED entries in the anchor's [from,to] and require it equals the signed root. `AnchoredThrough` = highest anchored seq proven. Unanchored exported entries beyond the last anchor are reported (not proven).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/export_verify_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func exportFixture(t *testing.T) (*ExportBundle, ed25519.PublicKey) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	an.AnchorChain(context.Background(), 7, "data")
	pub := priv.Public().(ed25519.PublicKey)
	b, err := BuildExport(context.Background(), db, NewKeyRegistry(pub), 7, "data", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	return b, pub
}

func TestVerifyExport_CleanProvesOffline(t *testing.T) {
	b, pub := exportFixture(t)
	res, err := VerifyExport(b, NewKeyRegistry(pub))
	if err != nil || !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("clean export should prove offline: %+v err=%v", res, err)
	}
}

func TestVerifyExport_TamperedEntryFails(t *testing.T) {
	b, pub := exportFixture(t)
	b.Entries[1].EntryHash = []byte("tamperedtamperedtamperedtampered") // change a hash in the anchored range
	res, _ := VerifyExport(b, NewKeyRegistry(pub))
	if res.OK {
		t.Fatal("tampered entry accepted offline")
	}
}

func TestVerifyExport_UntrustedKeyFails(t *testing.T) {
	b, _ := exportFixture(t)
	other := make([]byte, ed25519.SeedSize)
	other[0] = 77
	wrong := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	res, _ := VerifyExport(b, NewKeyRegistry(wrong))
	if res.OK {
		t.Fatal("export verified against an untrusted key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestVerifyExport -v`
Expected: FAIL — `undefined: VerifyExport`

- [ ] **Step 3: Write minimal implementation**

```go
// append to export.go (imports: add "bufio", "bytes", "crypto/ed25519")

// ReadExport reads entries.jsonl + proof.json from dir.
func ReadExport(dir string) (*ExportBundle, error) {
	pf, err := os.Open(filepath.Join(dir, "proof.json"))
	if err != nil {
		return nil, err
	}
	defer pf.Close()
	var b ExportBundle
	if err := json.NewDecoder(pf).Decode(&b); err != nil {
		return nil, fmt.Errorf("parse proof.json: %w", err)
	}
	ef, err := os.Open(filepath.Join(dir, "entries.jsonl"))
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	sc := bufio.NewScanner(ef)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e ExportEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("parse entry: %w", err)
		}
		b.Entries = append(b.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return &b, nil
}

// VerifyExport proves an export bundle offline — NO database, NO HMAC key. For
// each anchor: resolve+trust its key, verify the Ed25519 signature, and recompute
// the Merkle root over the EXPORTED entries in its range. Returns the highest
// anchored seq proven.
func VerifyExport(b *ExportBundle, trusted KeyRegistry) (AnchorVerifyResult, error) {
	// index exported entries by seq
	bySeq := make(map[int64]ExportEntry, len(b.Entries))
	for _, e := range b.Entries {
		bySeq[e.Seq] = e
	}
	var through int64
	expectedFrom := b.FromSeq
	for i := range b.Anchors {
		a := &b.Anchors[i]
		// the bundle's declared pubkey for this key_id must itself be trusted
		pubB64, ok := b.PubKeys[a.KeyID]
		if !ok {
			return AnchorVerifyResult{OK: false, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		raw, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			return AnchorVerifyResult{OK: false, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		pub := ed25519.PublicKey(raw)
		if tp, ok := trusted.For(a.KeyID); !ok || !tp.Equal(pub) {
			return AnchorVerifyResult{OK: false, FailFromSeq: a.FromSeq, Reason: "untrusted key"}, nil
		}
		if a.FromSeq != expectedFrom {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "anchor gap"}, nil
		}
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
		leaves := make([][]byte, 0, a.ToSeq-a.FromSeq+1)
		for s := a.FromSeq; s <= a.ToSeq; s++ {
			e, ok := bySeq[s]
			if !ok {
				return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "missing entries"}, nil
			}
			leaves = append(leaves, e.EntryHash)
		}
		if !bytes.Equal(MerkleRoot(leaves), a.MerkleRoot) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "root mismatch"}, nil
		}
		through = a.ToSeq
		expectedFrom = a.ToSeq + 1
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestVerifyExport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/export.go internal/domain/audit/export_verify_test.go
git commit -m "feat(audit): offline VerifyExport proves a bundle with only the public key"
```

---

### Task 7: CLI — audit-export + verify-export subcommands, sink-diff in verify-audit

**Files:**
- Modify: `app/audit_verify.go`, `app/run.go`
- Test: covered by Tasks 1-6 + manual smoke.

**Interfaces:**
- Consumes: `BuildExport`/`WriteExport`/`ReadExport`/`VerifyExport`, `VerifyAnchorsWithSink`, `NewKeyRegistry`, config retired pubkeys.

- [ ] **Step 1: Build the anchor key registry helper**

In `app/audit_verify.go`, add a helper that builds a `KeyRegistry` from config: the current key's public key (derive from `a.Config.Crypto.AuditAnchorKey` seed → `crypto.Ed25519FromSeed` → `.Public()`) plus each base64 pubkey in `a.Config.Crypto.AuditAnchorRetiredPubKeys` (comma-split, base64-decode to `ed25519.PublicKey`). Return `audit.NewKeyRegistry(pubs...)`.

- [ ] **Step 2: Use sink-diff + registry in runVerifyAudit**

Replace the `audit.VerifyAnchors(ctx, a.DB, anchorPub, ...)` call (Phase 3) with the sink-aware, multi-key form: build the sink (`audit.NewFileSink(a.Config.Audit.AnchorSinkPath)`) + the registry, and call `audit.VerifyAnchorsWithSink(ctx, a.DB, sink, reg, h.TenantID, h.ChainClass)`. Keep the printed `anchors ... verified through seq N — OK/FAIL` line; a `sink mismatch` now surfaces a deleted anchor row.

- [ ] **Step 3: Add `audit-export` subcommand**

Add `runAuditExport(a *bootstrap.App, args)` that parses `--tenant --class --from --to --out <dir>` (use a `flag.FlagSet` on the remaining args), builds the registry, calls `audit.BuildExport` + `audit.WriteExport(outDir, bundle)`, and prints the output path + a one-line summary (entries, anchors, anchored-through). Wire it in `app/run.go` alongside the `verify-audit` dispatch: `if flag.Arg(0) == "audit-export" { runAuditExport(a, flag.Args()[1:]); return }`.

- [ ] **Step 4: Add `verify-export` subcommand (offline)**

Add `runVerifyExport(args)` — a STANDALONE command that does NOT build the app/DB: parse `--dir <exportDir> --trust <base64pub>,...` (the trusted public keys the third party holds), `audit.ReadExport(dir)`, build a registry from the `--trust` keys, `audit.VerifyExport(bundle, reg)`, print `export tenant=%d class=%s: proved through seq %d — %s` and exit non-zero on failure. Wire it in `app/run.go` BEFORE `bootstrap.NewApp` (it needs no DB): `if flag.Arg(0) == "verify-export" { if err := runVerifyExport(flag.Args()[1:]); err != nil { os.Exit(1) }; return }`. (Place this check right after `flag.Parse()`, before `bootstrap.NewApp`.)

- [ ] **Step 5: Build + smoke**

Run: `go build ./...`
Dev-container smoke (a chain with data + an anchor must exist; if the dev DB is empty this just prints nothing — that's fine for a compile/boot check):
```
docker exec mxid-dev sh -c 'cd /app && go run ./cmd/server -config=configs verify-audit 2>&1 | tail -10'
```
Expected: no error. (A full export→verify-export round-trip is exercised by the unit tests in Tasks 5-6; the CLI is a thin wrapper.)

- [ ] **Step 6: Commit**

```bash
git add app/audit_verify.go app/run.go
git commit -m "feat(audit): audit-export + offline verify-export CLI; sink-diff in verify-audit"
```

---

## Self-Review

**Spec coverage (design §7 export/verify + Phase-3 residuals):**
- Export (JSONL + proof) third-party-verifiable via Ed25519 anchors: Tasks 5, 6, 7. ✅
- Offline verify (no DB, no secret): Task 6, 7 (verify-export runs before NewApp). ✅
- Sink-diff closes the "deleted anchor row" residual: Tasks 1, 4, 7. ✅
- Multi-key survives rotation: Tasks 2, 3, 7. ✅
- **Deferred:** S3 Object Lock sink impl (interface + FileSink shipped; S3 is a drop-in `AnchorSink`); export of the "unanchored tail" is exported-but-not-proven (documented — needs anchoring first); UI. 

**Placeholder scan:** all code steps carry full code; Task 7's CLI steps give exact flags + wiring points (before/after NewApp) — concrete.

**Type consistency:** `AnchorSink.List`, `KeyRegistry`/`NewKeyRegistry`/`For`, `VerifyAnchors(…, keys KeyRegistry, …)`, `VerifyAnchorsWithSink`, `ExportEntry`/`ExportBundle`/`BuildExport`/`WriteExport`/`ReadExport`/`VerifyExport` are consistent across tasks. `VerifyAnchors` signature change (single pub → KeyRegistry) is propagated to all callers in Task 3.

## Risks / follow-ups

- **`VerifyAnchors` signature change** (single `pub` → `KeyRegistry`) touches every caller (verify-audit CLI, e2e test, verify_anchor tests) — Task 3 updates them; a missed caller is a build break, caught immediately.
- **Sink trust**: sink-diff detects DB↔sink divergence but if BOTH the DB and the sink are attacker-controlled and re-signed, only an OUT-OF-BAND trusted public key + a copy of the signed roots (the export handed to a third party) gives true non-repudiation. FileSink on the same host is still not WORM — S3 Object Lock remains the production sink.
- **Export size**: a huge range writes many entries; the CLI streams JSONL so memory is bounded per line, but `BuildExport` currently loads entries into memory — fine for realistic export windows, revisit if someone exports millions of rows.
